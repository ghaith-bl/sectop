"""security: kernel box (docs/modules/security.md, Kernel box).

What the kernel did since sectop started, from the same journal entries as the
other boxes plus one file:
- taint: /proc/sys/kernel/tainted, read each collect. Baseline = first read since
  start; a bit set later is a row. Letters: docs.kernel.org admin-guide/tainted-kernels
  ("the kernel will remain tainted even after you undo what caused the taint").
- modules: audit SYSCALL init_module / finit_module / delete_module (hardening rule key
  kernel_modules) + KERN_MODULE name. auid set = from a login, unset = autoload.
- blocked load: `install <mod> /bin/false` (CIS) makes modprobe run `sh -c -- /bin/false`
  instead of loading: no module syscall, no KERN_MODULE. Seen as the root command
  (root_cmds) of a modprobe run.
- SELinux: audit AVC (1400) / USER_AVC (1107) denials. permissive=1: allowed
  (permissive domain or permissive mode), permissive=0: blocked.
- kernel log: _TRANSPORT=kernel, PRIORITY 0..4, without HFW-* (firewall screen).
  Grouped by normalized message.
- USB: "New USB device found, idVendor=.., idProduct=.." (PRIORITY 6), Product /
  Manufacturer from the next lines of the same port.

Severity (table agreed 2026-10-25: red = dangerous or suspicious, worth following up):
crit = new taint D L M B (oops, lockup, machine check, bad page) or O E P (a module out
of tree / unsigned / proprietary loaded later), kernel log PRIORITY 0-2; warn = module
loaded or removed from a login, new taint W, SELinux denial allowed (permissive=1),
kernel log PRIORITY 3, any other new taint bit; info = module autoload, blocked load,
SELinux denial blocked, kernel log PRIORITY 4, new USB device. A crit row is also a
check (alert) while its last one is under the window (the same 1 h as watch / auth).
"""

import collections
import errno
import hashlib
import os
import re

from core import audit
from core import proc as procmod
from core.journal import values
from core.sanitize import _ADDR

TAINT_PATH = "/proc/sys/kernel/tainted"
# bit -> (letter, meaning), docs.kernel.org admin-guide/tainted-kernels
TAINT = {0: ("P", "proprietary module loaded"), 1: ("F", "module force loaded"),
         2: ("S", "system out of spec"), 3: ("R", "module force unloaded"),
         4: ("M", "machine check exception"), 5: ("B", "bad page"),
         6: ("U", "taint set by user space"), 7: ("D", "kernel died (oops or BUG)"),
         8: ("A", "ACPI table overridden"), 9: ("W", "kernel warning"),
         10: ("C", "staging driver loaded"), 11: ("I", "firmware bug workaround"),
         12: ("O", "out-of-tree module loaded"), 13: ("E", "unsigned module loaded"),
         14: ("L", "soft lockup"), 15: ("K", "kernel live patched"),
         16: ("X", "auxiliary taint (distribution)"), 17: ("T", "struct randomization"),
         18: ("N", "in-kernel test run"), 19: ("J", "fwctl mutating debug operation")}
TAINT_CRIT = set("DLMBOEP")
TAINT_WARN = set("W")             # any other bit: warn too (not in the agreed table)
# arch -> syscall number -> name (x86_64, i386: the hardening rules cover b64 + b32)
MODULE_CALLS = {"c000003e": {"175": "init_module", "313": "finit_module",
                             "176": "delete_module"},
                "40000003": {"128": "init_module", "350": "finit_module",
                             "129": "delete_module"}}
AVC, USER_AVC = 1400, 1107
UNSET = "4294967295"
PRIORITIES = {"0": "emerg", "1": "alert", "2": "crit", "3": "err", "4": "warning"}
LOG_SEV = {"0": "crit", "1": "crit", "2": "crit", "3": "warn", "4": "info"}
USB_SUBSYSTEM = "usb"
OWN_PREFIX = "HFW-"               # hostfw lines: firewall screen
MODPROBE = ("modprobe", "insmod")
FALSE_CMDS = ("false", "true")    # install <mod> /bin/false | /bin/true
MODPROBE_KEEP = 60.0
MAX_MODPROBES = 64
MAX_ROWS = 180                    # + taint rows (20 bits): panel max 200
MAX_MSGS = 3
MAX_CHECKS = 50
COLUMNS = ["last", "n", "kind", "from", "what"]
TYPES = ["age", "num", "text", "text", "text"]

AVC_RE = re.compile(r"avc:\s+denied\s+\{\s*([^}]*?)\s*\}")
USB_NEW_RE = re.compile(r"usb (\S+): New USB device found, idVendor=([0-9A-Fa-f]{4}), "
                        r"idProduct=([0-9A-Fa-f]{4})(?:, bcdDevice=\s*(\S+))?")
USB_STR_RE = re.compile(r"usb (\S+): (Product|Manufacturer): (.*)")
UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
HEX_RE = re.compile(r"\b0x[0-9a-f]+\b|\b[0-9a-f]{12,}\b", re.I)
BRACKET_RE = re.compile(r"\[[^\]]*\]")
NUM_RE = re.compile(r"\d+")
SPACE_RE = re.compile(r"\s+")


def letters(mask: int) -> str:
    """Taint value -> its letters, bit order (12288 -> "O E")."""
    return " ".join(TAINT.get(b, (f"bit{b}", ""))[0] for b in range(mask.bit_length())
                    if mask >> b & 1)


def read_taint(path: str = TAINT_PATH) -> int:
    with open(path, encoding="ascii") as f:
        return int(f.read().strip())


def normalize(msg: str) -> str:
    """Kernel log line for grouping only: UUIDs, IPs, hex, [..], numbers -> placeholders."""
    s = UUID_RE.sub("<uuid>", msg)
    s = _ADDR.sub("<ip>", s)
    s = HEX_RE.sub("<hex>", s)
    s = BRACKET_RE.sub("[.]", s)
    s = NUM_RE.sub("#", s)
    return SPACE_RE.sub(" ", s).strip()


class Row:
    def __init__(self, kind: str, src: str, what: str, sev: str, why: str, ts: float):
        self.kind, self.src, self.what, self.sev, self.why = kind, src, what, sev, why
        self.n, self.first, self.last = 0, ts, ts
        self.detail = {}                                 # k -> v, newest values
        self.msgs = collections.deque(maxlen=MAX_MSGS)   # log: distinct raw lines
        self.subject = ""                                # check: what the alert is about
        self.progs = procmod.names()                     # c = program card
        self.label = ""                                  # check title: log priority name
        self.reported = 0                                # n at the last check


class Kernel:
    def __init__(self):
        self.rows = collections.OrderedDict()       # key -> Row, least recent first
        self.taint_rows = collections.OrderedDict()  # letter -> Row
        self.taint_start = self.taint_now = None     # int once read
        self.taint_err = ""
        self.modprobes = collections.OrderedDict()   # pid -> (module, auid, ts, argv)
        self.usb_ports = {}                          # port -> row key (Product lines)
        self.loads = 0                               # module loads + removals since start


def _add(k: Kernel, key: str, kind: str, src: str, what: str, sev: str, why: str,
         ts: float) -> Row:
    r = k.rows.pop(key, None) or Row(kind, src, what, sev, why, ts)
    k.rows[key] = r                                  # most recent last
    while len(k.rows) > MAX_ROWS:
        old, _ = k.rows.popitem(last=False)
        for port in [p for p, v in k.usb_ports.items() if v == old]:
            del k.usb_ports[port]
    r.n += 1
    r.first, r.last = min(r.first, ts), max(r.last, ts)
    r.what, r.sev, r.why = what, sev, why
    return r


# --- taint ---------------------------------------------------------------

def taint(k: Kernel, read, now: float) -> None:
    """One read of the taint file. read() -> int; OSError / ValueError: kept as a note."""
    try:
        value = read()
    except (OSError, ValueError) as e:
        k.taint_err = (getattr(e, "strerror", None) or str(e))[:80] or "unreadable"
        return
    k.taint_err = ""
    if k.taint_start is None:
        k.taint_start = value
    k.taint_now = value
    new = value & ~k.taint_start
    for b in range(new.bit_length()):
        if not new >> b & 1:
            continue
        letter, meaning = TAINT.get(b, (f"bit{b}", "unknown taint bit"))
        if letter in k.taint_rows:
            continue
        sev = "crit" if letter in TAINT_CRIT else "warn"
        r = Row("taint", "kernel", f"{letter}  {meaning}", sev, f"new taint {letter}: "
                f"{meaning} (stays set until reboot)", now)
        r.n, r.subject = 1, letter
        r.detail = {"bit": str(b), "value now": str(value), "at start": str(k.taint_start)}
        k.taint_rows[letter] = r


def title_note(k: Kernel) -> str:
    if k.taint_start is None:
        return f"taint: {k.taint_err or 'not read yet'}"
    start = letters(k.taint_start) or "none"
    note = f"taint at start: {start}"
    if k.taint_now != k.taint_start:
        note += f", now: {letters(k.taint_now)}"
    if k.taint_err:
        note += f" (read: {k.taint_err})"
    return note


# --- audit ---------------------------------------------------------------

def _login(name, auid: str | None) -> str:
    return "-" if not auid or auid == UNSET else name(auid)


def _result(ev) -> str:
    if ev.get("success") != "no":
        return "ok"
    code = ev.get("exit") or ""
    try:
        return "failed " + errno.errorcode.get(-int(code), code)
    except ValueError:
        return "failed"


def _none(pid, ts):
    return None


def _module(k: Kernel, ev, call: str, ts: float, name, prog=_none) -> None:
    rec = ev.first("KERN_MODULE")
    mod = (audit.text(rec.raw, "name") if rec else None) or "?"
    auid = ev.get("auid")
    login = _login(name, auid)
    action = "remove" if call == "delete_module" else "load"
    result = _result(ev)
    exe = ev.get("exe") or "?"
    if login == "-":
        sev, why = "info", "module autoload (no login: udev, kernel request)"
    else:
        sev, why = "warn", f"module {action} from a login"
    what = f"{action} {mod}" + ("" if result == "ok" else f" {result}")
    key = "\x1f".join(("module", action, mod, result, login, exe))
    r = _add(k, key, "module", login, what, sev, why, ts)
    procmod.add(r.progs, prog(ev.get("pid"), ts) or prog(ev.get("ppid"), ts))
    k.loads += 1
    r.detail = {"exe": exe, "cmdline": ev.proctitle or ev.get("comm") or "-",
                "syscall": call, "result": result, "pid / ppid":
                f"{ev.get('pid') or '-'} / {ev.get('ppid') or '-'}",
                "tty": ev.get("tty") or "-", "ses": ev.get("ses") or "-"}


def _ctx_type(ctx: str | None) -> str:
    parts = (ctx or "").split(":")
    return parts[2] if len(parts) >= 3 else (ctx or "?")


def _avc(k: Kernel, rec, ts: float, prog=_none) -> None:
    m = AVC_RE.search(rec.message)
    if m is None:
        return                                   # granted, policy load notice, ...
    raw = rec.raw
    perms = " ".join(m.group(1).split()) or "?"
    exe = audit.text(raw, "exe") or ""
    comm = audit.text(raw, "comm") or (os.path.basename(exe) if exe else "?")
    stype, ttype = _ctx_type(raw.get("scontext")), _ctx_type(raw.get("tcontext"))
    tclass = raw.get("tclass") or "?"
    allowed = raw.get("permissive") == "1"
    if allowed:
        sev, why = "warn", "SELinux denial allowed (permissive=1: permissive domain or mode)"
    else:
        sev, why = "info", "SELinux denial, blocked (enforcing)"
    what = f"{{ {perms} }} {stype} -> {ttype} {tclass}" + (" (allowed)" if allowed else "")
    key = "\x1f".join(("avc", comm, stype, ttype, tclass, perms, "1" if allowed else "0"))
    r = _add(k, key, "avc", comm, what, sev, why, ts)
    procmod.add(r.progs, prog(raw.get("pid"), ts))
    d = {"record": "AVC" if rec.type == AVC else "USER_AVC",
         "scontext": raw.get("scontext") or "-", "tcontext": raw.get("tcontext") or "-",
         "pid": raw.get("pid") or "-"}
    for f in ("path", "name", "exe", "capability"):
        v = audit.text(raw, f)
        if v:
            d[f] = v
    r.detail = d


def audit_event(k: Kernel, ev, ts: float, name, prog=_none) -> None:
    """One audit event (core/audit.py Event): module syscalls, AVC, USER_AVC."""
    if ev.kind == "SYSCALL":
        call = MODULE_CALLS.get(ev.get("arch") or "", {}).get(ev.get("syscall") or "")
        if call:
            _module(k, ev, call, ts, name, prog)
    for rec in ev.records:
        if rec.type in (AVC, USER_AVC):
            _avc(k, rec, ts, prog)


def _modname(argv: list) -> str:
    for a in argv[1:]:
        if not a.startswith("-"):
            return a
    return "?"


def exec_event(k: Kernel, ev, ts: float, name, prog=_none) -> None:
    """A root command / setuid exec (commands box keys). modprobe runs are kept a short
    time; its `sh -c -- /bin/false` (or /bin/false itself) = the load was blocked."""
    for pid in list(k.modprobes):
        if ts - k.modprobes[pid][2] > MODPROBE_KEEP:
            del k.modprobes[pid]
    argv, pid, ppid = ev.argv, ev.get("pid") or "", ev.get("ppid") or ""
    base = os.path.basename(argv[0]) if argv else ""
    if base in MODPROBE and "-r" not in argv and "--remove" not in argv:
        k.modprobes.pop(pid, None)
        k.modprobes[pid] = (_modname(argv), ev.get("auid"), ts, " ".join(argv))
        while len(k.modprobes) > MAX_MODPROBES:
            k.modprobes.popitem(last=False)
        return
    if ppid not in k.modprobes or not argv:
        return
    last = os.path.basename(argv[-1])
    if not (last in FALSE_CMDS and (base in ("sh", "bash") or base == last)):
        return
    mod, auid, _, line = k.modprobes.pop(ppid)    # one row per modprobe run
    login = _login(name, auid)
    key = "\x1f".join(("blocked", mod, login))
    r = _add(k, key, "module", login, f"blocked {mod}", "info",
             f"load blocked: install {mod} {argv[-1]} (modprobe.d)", ts)
    r.detail = {"cmdline": line, "install": " ".join(argv), "pid / ppid": f"{pid} / {ppid}"}
    procmod.add(r.progs, prog(pid, ts) or prog(ppid, ts))


# --- kernel log + USB ------------------------------------------------------

def _first(v) -> str:
    vs = values(v)
    return vs[0] if vs else ""


def wanted(e: dict) -> bool:
    """The entries this box reads (= its JOURNAL groups)."""
    return e.get("_TRANSPORT") == "kernel" and (
        e.get("PRIORITY") in PRIORITIES or e.get("_KERNEL_SUBSYSTEM") == USB_SUBSYSTEM)


def journal_entry(k: Kernel, e: dict, ts: float) -> None:
    if not wanted(e):
        return
    msg = _first(e.get("MESSAGE"))
    if not msg or msg.startswith(OWN_PREFIX):
        return
    prio = e.get("PRIORITY")
    if prio in PRIORITIES:
        _log(k, e, msg, prio, ts)
    if e.get("_KERNEL_SUBSYSTEM") == USB_SUBSYSTEM:
        _usb(k, msg, ts)


def _log(k: Kernel, e: dict, msg: str, prio: str, ts: float) -> None:
    norm = normalize(msg)
    if not norm:
        return
    src = _first(e.get("_KERNEL_SUBSYSTEM")) or "kernel"
    sev = LOG_SEV[prio]
    key = "\x1f".join(("log", prio, norm))
    r = _add(k, key, "log", src, msg, sev, f"kernel log {PRIORITIES[prio]} "
             f"(PRIORITY {prio})", ts)
    if msg in r.msgs:
        r.msgs.remove(msg)
    r.msgs.appendleft(msg)
    r.subject, r.label = norm, PRIORITIES[prio]
    r.detail = {"priority": f"{prio} {PRIORITIES[prio]}",
                "device": _first(e.get("_KERNEL_DEVICE")) or "-"}


def _usb(k: Kernel, msg: str, ts: float) -> None:
    m = USB_NEW_RE.match(msg)
    if m is not None:
        port, vid, pid, bcd = m.group(1), m.group(2).lower(), m.group(3).lower(), m.group(4)
        key = "\x1f".join(("usb", vid, pid))
        old = k.rows.get(key)
        r = _add(k, key, "usb", port, old.what if old else f"{vid}:{pid}", "info",
                 "new USB device", ts)
        r.src = port
        r.detail.update({"id": f"{vid}:{pid}", "port": port, "bcdDevice": bcd or "-"})
        k.usb_ports[port] = key
        return
    m = USB_STR_RE.match(msg)
    if m is None:
        return
    key = k.usb_ports.get(m.group(1))
    r = k.rows.get(key) if key else None
    if r is None:
        return
    field, text = m.group(2).lower(), m.group(3).strip()[:80]
    r.detail[field] = text
    vidpid = r.detail.get("id", "?")
    r.what = " ".join(x for x in (vidpid, r.detail.get("product"),
                                  f"({r.detail['manufacturer']})"
                                  if r.detail.get("manufacturer") else "") if x)


# --- output --------------------------------------------------------------

def rows(k: Kernel, stamp) -> list:
    out = []
    every = list(k.taint_rows.items()) + list(k.rows.items())
    for key, r in sorted(every, key=lambda kv: -kv[1].last):
        detail = [("why", r.why), ("first", stamp(r.first))]
        detail += [("line", m) for m in r.msgs]
        detail += list(r.detail.items())
        row = {"cells": [f"{r.last:.3f}", str(r.n), r.kind, r.src, r.what],
               "sev": r.sev, "id": f"{r.kind}:{key}" if r.kind == "taint" else key,
               "detail": [{"k": a, "v": b} for a, b in detail]}
        if r.progs:
            row["progs"] = list(r.progs)
        out.append(row)
    return out


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "backslashreplace")).hexdigest()[:12]


def checks(k: Kernel, now: float, window: float, stamp) -> list:
    """crit rows with new lines since the last report, last one under `window` old ->
    one event check each, at = the newest line (a new taint bit: when it was read)."""
    every = list(k.taint_rows.values()) + list(k.rows.values())
    hot = sorted((r for r in every
                  if r.sev == "crit" and r.n > r.reported and now - r.last <= window),
                 key=lambda r: -r.last)[:MAX_CHECKS]
    out = []
    for r in hot:
        if r.kind == "taint":
            key, title = f"kernel:taint:{r.subject}", f"kernel tainted: {r.what}"
        else:
            key = f"kernel:{r.kind}:{_digest(r.kind + chr(31) + (r.subject or r.what))}"
            title = f"kernel {r.label or r.kind}: {r.what}"
        out.append({"key": key, "sev": "crit", "title": " ".join(title.split())[:160],
                    "detail": f"{r.kind} from {r.src}, last {stamp(r.last)}, {r.why}",
                    "n": r.n - r.reported, "at": r.last})
        r.reported = r.n
    return out
