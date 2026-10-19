"""firewall: hostfw + Proton WireGuard status for sectop.

Sources (fixed argv, via core.run.run): nft counters / enforce chain /
wg_fwmark set, kernel journal (HFW- lines, cursor), ss, wg per-field
subcommands, ip default routes. Files: /etc/hostfw/mode, /run/hostfw/rollback,
/proc/uptime. At start: one boot journal scan (leak lines, first tunnel flow).
Audit box: every HFW line (allowed + blocked, in + out), program from ss.
See docs/modules/firewall.md.
"""

import collections
import os
import re
import stat
import time

from core.module import worst
from core.run import run as _run
from modules.firewall import conns, journal, nft, vpn

NAME = "firewall"
INTERVAL = 2.0

TIMEOUT = 1.0            # per command, keeps a full tick below INTERVAL
BOOT_TIMEOUT = 5.0       # boot journal scan, once in init()
HS_STALE = 180           # WireGuard rejects keys after 180 s
HOLD = 60.0              # seconds a new blocked packet keeps its severity in status
SPARK = 120
MAX_CONNS = 50
MAX_EVENTS = 100
MAX_AUDIT = 200          # audit flows (grouped repeats) kept, newest first
MAX_PORTS = 10           # varying ports kept per flow, shown in its detail
MAX_PROGS = 3
MAX_LEAKS = 100          # leak lines kept (boot scan + live), newest first
RECENT = 10              # log lines kept per counter, shown in its detail
LEAK_ROWS = 8            # shown in the out_leak box
FILE_MAX = 4096

TABLE = ("inet", "hostfw")
MODE_FILE = "/etc/hostfw/mode"
ROLLBACK_FILE = "/run/hostfw/rollback"
UPTIME_FILE = "/proc/uptime"
DEFAULT_TUNNEL = "proton0"
DEFAULT_KS = ("pvpnksintrf0", "pvpnksintrf1")
OPTIONS = {"tunnel", "ks_ifaces", "hold"}
IFACE_RE = re.compile(r"[A-Za-z0-9_.-]{1,15}")

# hostfw counter / log kind -> severity. None = hidden (counter only, no event).
SEV = {
    "out_leak": "crit",
    "out_dns": "warn", "in_lan": "warn", "in_vpn": "warn",
    "fwd_vm_lan": "warn", "fwd_in": "warn",
    "out_ks": "info", "out_disco": "info", "out_share": "info", "out_lan": "info",
    "fwd_vm_ks": "info",
    "in_noise": None,
}
# allowed traffic: counted, never raises status
ALLOWED = {"out_dns_vpn", "out_wg", "out_probe", "out_router_admin", "out_lan_allow",
           "out_new", "fwd_vm_new"}
AUDIT_ONLY = {"out_new", "fwd_vm_new"}          # every new flow: audit box, no event
KS_KINDS = {"out_ks", "fwd_vm_ks"}              # always dropped by hostfw
LOG_ONLY = {"in_noise", "in_lan", "in_vpn"}     # hostfw logs, firewalld zone decides
AUDIT_COLUMNS = ["last", "n", "dir", "verdict", "proto", "uid", "prog", "src", "dst", "iface"]
LEAK_COLUMNS = ["time", "uid", "proto", "dst", "iface", "context"]
CONTEXT_NOTE = {
    "pre-connect": "before the first flow via the tunnel this boot "
                   "(expected: DoH fallback before Proton connects)",
    "tunnel up": "the tunnel was up: a program sent around it",
    "tunnel down": "the tunnel was down after it had been up (reconnect window)",
    "after connect": "after the first flow via the tunnel this boot, before sectop "
                     "started: tunnel state at that time unknown",
    "unknown": "first tunnel flow unknown (boot scan failed)",
}
# what each hostfw counter matches (silverblue-cis-hardening firewall/docs/rules.md)
MATCH = {
    "out_dns_vpn": "tcp/udp 53, 853 to 10.2.0.1 via proton0",
    "out_wg": "WireGuard transport (fwmark in wg_fwmark) on the uplink",
    "out_probe": "uid 1000 tcp to Proton entry IPs on probe ports (before connect)",
    "out_router_admin": "router web UI while opened (hostfw router-open)",
    "out_lan_allow": "explicit LAN exceptions (set lan_allow4)",
    "out_new": "first packets of every new host flow via proton0",
    "fwd_vm_new": "first packets of every new VM flow via proton0",
    "out_dns": "any other tcp/udp 53, 853 (not the VPN resolver)",
    "out_disco": "udp 137 138 1900 3702 5351 5353 5355 27036, tcp 5355 5357 5358 27036 27037",
    "out_share": "tcp 21 111 139 445 548 2049, udp 69 111 2049 (not via virbr0)",
    "out_ks": "host traffic routed to the kill switch dummy (pvpnksintrf0/1)",
    "out_lan": "to private / link-local / CGNAT / multicast / broadcast, not router / exception",
    "out_leak": "anything else leaving on the uplink (not tunnel transport, DHCP, router)",
    "fwd_vm_ks": "VM traffic routed to the kill switch dummy",
    "fwd_vm_lan": "VM traffic to LAN / uplink (not via the tunnel)",
    "fwd_in": "new forwarded traffic not from a VM",
    "in_noise": "LAN broadcast / multicast to the host (not via proton0)",
    "in_lan": "new inbound from the uplink",
    "in_vpn": "new inbound from the tunnel",
}
NOT_LOGGED = {"out_dns_vpn", "out_wg", "out_probe"}
VERDICT_NOTE = {
    "allow": "allowed by hostfw (logged new flow or exception)",
    "drop": "kill switch: always dropped",
    "zone": "hostfw only logs, the firewalld zone decides (default zone: drop)",
    "block": "rejected by hostfw (enforce mode)",
    "pass": "deny rule in observe mode: logged, not blocked",
    "deny": "deny rule, mode unknown",
}


TONE = {"allow": "blue", "drop": "red", "block": "yellow"}   # verdict -> color, else plain


def _tone(verdict: str) -> str:
    return TONE.get(verdict, "plain")


def kind_sev(name: str) -> str | None:
    """Severity of new packets for a counter / log kind. None = never raises status."""
    if name in ALLOWED:
        return None
    return SEV.get(name, "info")


def _hms(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))


def _stamp(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) + f".{int(ts * 1000) % 1000:03d}"


def _bin(name: str) -> str:
    for d in ("/usr/bin", "/usr/sbin"):
        p = f"{d}/{name}"
        if os.path.isfile(p):
            return p
    return f"/usr/bin/{name}"         # run() reports rc 127


class State:
    def __init__(self, tunnel=DEFAULT_TUNNEL, ks=DEFAULT_KS, hold=HOLD, run=_run,
                 mono=time.monotonic, wall=time.time, owner=0,
                 mode_file=MODE_FILE, rollback_file=ROLLBACK_FILE, hms=_hms, stamp=_stamp,
                 uptime_file=UPTIME_FILE):
        self.tunnel, self.ks, self.hold = tunnel, tuple(ks), hold
        self.run, self.mono, self.wall, self.owner = run, mono, wall, owner
        self.mode_file, self.rollback_file = mode_file, rollback_file
        self.uptime_file = uptime_file
        self.hms = hms                 # epoch -> "HH:MM:SS" for audit rows
        self.stamp = stamp             # epoch -> full local time for audit detail
        self.comments = {}             # counter name -> hostfw rule comment
        self.bins = {n: _bin(n) for n in ("nft", "journalctl", "ss", "wg", "ip")}
        self.cursor = None
        self.since = int(wall())
        self.prev = None               # counters of last tick
        self.prev_tx = None
        self.held = {}                 # kind -> mono time until its sev is held
        self.blocked = collections.deque(maxlen=SPARK)
        self.flows = {}                # audit flow key -> Flow, oldest first
        self.lines = 0                 # audit lines since start (all flows)
        self.leaks = collections.deque(maxlen=MAX_LEAKS)   # (Entry, context), newest first
        self.recent = {}               # counter name -> deque of (ts, summary), newest first
        self.leak_seen = set()         # cursors from the boot scan (live reader skips them)
        self.tunnel_first = None       # epoch of the first HFW-OUT-NEW line this boot
        self.boot = None               # boot time, epoch (from /proc/uptime)
        self.boot_note = ""            # boot scan problem, shown in the out_leak title

    def cmd(self, *argv, timeout=TIMEOUT):
        return self.run([self.bins[argv[0]], *argv[1:]], timeout=timeout)


# --- helpers --------------------------------------------------------------

def _first(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return ""


def _fail(res) -> str:
    if res.timed_out:
        return "timeout"
    if res.rc == 127:
        return "not found"
    if res.rc == 126:
        return "binary not trusted"
    return _first(res.err) or f"rc {res.rc}"


def _read(path: str, owner: int) -> str | None:
    """Small root-owned regular file -> text. None if missing."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"{path}: not a regular file")
        if st.st_uid != owner or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValueError(f"{path}: not owned by uid {owner} or writable by others")
        data = os.read(fd, FILE_MAX + 1)
    finally:
        os.close(fd)
    if len(data) > FILE_MAX:
        raise ValueError(f"{path}: larger than {FILE_MAX} bytes")
    return data.decode("utf-8", errors="replace")


def _human(n: int) -> str:
    for unit in ("", "K", "M", "G", "T"):
        if n < 1000 or unit == "T":
            return f"{n}{unit}" if unit == "" else f"{n:.1f}{unit}"
        n /= 1000
    return str(n)


def _age(sec: float) -> str:
    sec = int(sec)
    if sec < 120:
        return f"{sec}s"
    if sec < 7200:
        return f"{sec // 60}m"
    return f"{sec // 3600}h"


def _since(sec: float) -> str:
    """Offset from boot: 12s, 3m 05s, 2h 10m."""
    if sec < 0:
        return "?"
    sec = int(sec)
    if sec < 120:
        return f"{sec}s"
    if sec < 3600:
        return f"{sec // 60}m {sec % 60:02d}s"
    return f"{sec // 3600}h {sec % 3600 // 60:02d}m"


def _item(k: str, v: str, sev: str = "ok", tone: str = "") -> dict:
    """kv item; tone green = healthy state (drawn only while sev is ok)."""
    out = {"k": k, "v": v, "sev": sev}
    if tone and sev == "ok":
        out["tone"] = tone
    return out


# --- sources --------------------------------------------------------------

def _hostfw(st: State, checks: list) -> tuple:
    """-> (kv items, counters or None, live mode)."""
    items = []
    res = st.cmd("nft", "-j", "list", "counters", "table", *TABLE)
    if res.rc != 0:
        msg = "missing" if nft.missing(res.err) else _fail(res)
        checks.append(("crit", f"table {msg}"))
        items.append(_item("table", msg, "crit"))
        return items, None, "-"
    counters = nft.counters(res.out)
    st.comments = nft.comments(res.out)
    items.append(_item("table", "loaded", tone="green"))

    res = st.cmd("nft", "-j", "list", "chain", *TABLE, "enforce")
    live = nft.mode(res.out) if res.rc == 0 else "unknown"
    sev = {"enforce": "ok", "observe": "warn"}.get(live, "warn")
    if sev != "ok":
        checks.append((sev, f"mode {live}"))
    items.append(_item("mode", live if res.rc == 0 else f"unknown ({_fail(res)})", sev,
                       "green"))

    try:
        boot = _read(st.mode_file, st.owner)
        boot = boot.strip() if boot is not None else "-"
        items.append(_item("boot mode", boot, "ok" if boot in (live, "-") else "info",
                           "green" if boot == live else ""))
    except (OSError, ValueError) as e:
        items.append(_item("boot mode", str(e), "warn"))
        checks.append(("warn", "boot mode unreadable"))

    try:
        rb = _read(st.rollback_file, st.owner)
    except (OSError, ValueError) as e:
        items.append(_item("rollback", str(e), "warn"))
        checks.append(("warn", "rollback file unreadable"))
    else:
        if rb is None:
            items.append(_item("rollback", "-"))
        else:
            text, armed = _rollback_state(rb, st.wall())
            if armed:
                checks.append(("info", "rollback armed"))
            items.append(_item("rollback", text, "info"))
    return items, counters, live


def _rollback_state(text: str, now: float) -> tuple:
    """hostfw deadline file: line 1 epoch deadline, line 2 rollback command.

    -> (text, armed). The file stays after the timer fired (hostfw.sh
    removes it only on confirm / observe / apply / remove), so a deadline
    in the past = no longer armed. Other content -> ('armed', True).
    """
    lines = text.splitlines()
    first = lines[0].strip() if lines else ""
    if not (first.isascii() and first.isdigit() and int(first) > 1_000_000_000):
        return "armed", True
    left = int(first) - int(now)
    action = lines[1].strip() if len(lines) > 1 else ""
    if left > 0:
        out, armed = f"armed, {left // 60}m {left % 60:02d}s left", True
    else:
        out, armed = f"deadline passed {_age(-left)} ago", False
    return (f"{out} -> {action}" if action else out), armed


def _log_note(name: str) -> str:
    if name in NOT_LOGGED:
        return "counted only, not logged"
    if name.endswith("_new"):
        return "5/s burst 50 (one line per new flow, more than that: counter only)"
    if name == "in_noise":
        return "6/min burst 10, hidden from audit and events"
    return "10/min burst 20: lines are samples, the counter is exact"


def _counter_detail(st: State, name: str, nbytes: int, live: str) -> list:
    """Shown on enter: what the counter means, what hostfw does, last log lines."""
    verdict = _verdict(name, live)
    sev = kind_sev(name)
    if name in SEV and SEV[name] is None:
        new = "never raises status (noise)"
    elif sev is None:
        new = "never raises status (allowed traffic)"
    else:
        new = f"{sev} in status for {st.hold:g} s after each tick with new packets"
    out = [("meaning", st.comments.get(name, "-")), ("match", MATCH.get(name, "-")),
           ("verdict", f"{verdict}  {VERDICT_NOTE[verdict]}"), ("new packets", new),
           ("log", _log_note(name)), ("bytes", str(nbytes)),
           ("since", "hostfw table load (a reload resets it)")]
    lines = list(st.recent.get(name, ()))
    if name not in NOT_LOGGED:
        out += [("", ""), ("last lines", f"{len(lines)} since sectop started" if lines
                           else "none since sectop started")]
        out += [(st.hms(ts), text) for ts, text in lines]
    return [{"k": k, "v": v} for k, v in out]


def _recent(st: State, entries: list) -> None:
    for e in entries:
        q = st.recent.setdefault(e.kind, collections.deque(maxlen=RECENT))
        q.appendleft((e.ts, journal.summary(e)))


def _counters(st: State, counters: dict | None, now: float, live: str = "?") -> tuple:
    """-> (table panel or None, totals, deltas). Updates held severities."""
    if counters is None:
        return None, {}, {}
    prev = st.prev or {}
    deltas = {}
    for name, (pkts, _b) in counters.items():
        old = prev.get(name, (pkts, 0))[0] if st.prev is not None else pkts
        deltas[name] = pkts - old if pkts >= old else pkts      # reset -> count again
    st.prev = counters
    for name, d in deltas.items():
        if d > 0 and kind_sev(name):
            st.held[name] = now + st.hold

    rows = []
    for name, (pkts, nbytes) in counters.items():
        if pkts == 0:
            continue                                          # zero counters hidden
        sev = kind_sev(name) if st.held.get(name, 0) > now else None
        rows.append({"cells": [name, str(pkts), f"+{deltas[name]}" if deltas[name] else "",
                               _human(nbytes)], "sev": sev or "ok",
                     "tone": _tone(_verdict(name, live)),
                     "detail": _counter_detail(st, name, nbytes, live)})
    zero = len(counters) - len(rows)
    title = "hostfw counters" + (f"  ({zero} zero hidden)" if zero else "")
    panel = {"id": "counters", "title": title, "type": "table",
             "columns": ["counter", "pkts", "new", "bytes"], "rows": rows}
    return panel, {n: c[0] for n, c in counters.items()}, deltas


def _held_checks(st: State, now: float, checks: list) -> None:
    for name, until in list(st.held.items()):
        if until <= now:
            del st.held[name]
            continue
        checks.append((kind_sev(name), f"new {name}"))


def _events(st: State, checks: list, items: list) -> tuple:
    """-> (events, HFW entries)."""
    if st.cursor:
        argv = ("journalctl", "_TRANSPORT=kernel", "-o", "json", "--output-fields=MESSAGE",
                "-q", "--no-pager", f"--after-cursor={st.cursor}")
    else:
        argv = ("journalctl", "_TRANSPORT=kernel", "-o", "json", "--output-fields=MESSAGE",
                "-q", "--no-pager", f"--since=@{st.since}")
    res = st.cmd(*argv)
    cut = res.timed_out or res.truncated
    if res.rc != 0 and not cut:
        checks.append(("warn", "log reader error"))
        items.append(_item("log reader", _fail(res), "warn"))
        return [], []
    entries, cursor, bad = journal.parse(res.out)
    if cursor:
        st.cursor = cursor
    state = "ok"
    if cut:
        state = "behind (output cut, catching up)"
    if bad:
        state = f"{bad} bad line(s)"
    items.append(_item("log reader", state, "ok" if state == "ok" else "info", "green"))

    out = []
    for e in entries:
        if (e.kind in SEV and SEV[e.kind] is None) or e.kind in AUDIT_ONLY:
            continue                                   # hidden kind / audit only
        sev = kind_sev(e.kind) or "info"               # allowed kinds: info
        out.append({"ts": e.ts, "sev": sev, "code": e.code, "msg": journal.summary(e)})
    return out[-MAX_EVENTS:], entries


def _verdict(kind: str, live: str) -> str:
    if kind in ALLOWED:
        return "allow"
    if kind in KS_KINDS:
        return "drop"
    if kind in LOG_ONLY:
        return "zone"
    return {"enforce": "block", "observe": "pass"}.get(live, "deny")


class Flow:
    """Repeats of one flow in the audit box: same kind, dir, proto, uid, src, dst
    (without the varying port) and iface."""

    def __init__(self, e, src, dst, side):
        self.first = self.last = e.ts
        self.n = 0
        self.src, self.dst, self.side = src, dst, side
        self.progs = []                # program names seen, first seen first
        self.ports = collections.deque(maxlen=MAX_PORTS)   # varying ports, newest first
        self.entry, self.verdict = e, ""


def _prog(e, idx: dict) -> tuple:
    """-> (program or '?' / 'vm' / '-', iface) of one log line."""
    f = e.fields
    proto = f.get("PROTO", "-").lower()
    if e.dir == "out":
        prog = "?"
        if proto in ("tcp", "udp"):
            key = (proto, *conns.split(journal.src(e)), *conns.split(journal.dst(e)))
            prog = ",".join(idx.get(key, ())) or "?"
        return prog, f.get("OUT") or "-"
    if e.dir == "fwd":
        return ("vm" if e.kind.startswith("fwd_vm") else "-"), \
            f"{f.get('IN') or '-'}>{f.get('OUT') or '-'}"
    return "-", f.get("IN") or "-"


def _audit(st: State, entries: list, cs: list, live: str) -> dict:
    """Group HFW lines (hidden kinds skipped) by flow, newest flow first."""
    idx = conns.index(cs)
    for e in entries:
        if e.kind in SEV and SEV[e.kind] is None:
            continue
        f = e.fields
        src, dst, side, port = journal.flow(e)
        prog, iface = _prog(e, idx)
        key = (e.kind, e.dir, f.get("PROTO", "-").lower(), f.get("UID") or "-", src, dst, iface)
        fl = st.flows.pop(key, None) or Flow(e, src, dst, side)
        st.flows[key] = fl                                     # newest at the end
        fl.n += 1
        fl.last, fl.entry, fl.verdict = e.ts, e, _verdict(e.kind, live)
        for name in prog.split(","):
            if name not in ("?", "-", "vm", "") and name not in fl.progs:
                fl.progs.append(name)
        if port and port not in fl.ports:
            fl.ports.appendleft(port)
        st.lines += 1
    while len(st.flows) > MAX_AUDIT:
        del st.flows[next(iter(st.flows))]                    # oldest flow out
    rows = [_flow_row(st, key, fl) for key, fl in reversed(st.flows.items())]
    return {"id": "audit", "title": f"audit {len(rows)} flows  ({st.lines} lines)",
            "type": "table", "columns": list(AUDIT_COLUMNS), "rows": rows}


def _flow_row(st: State, key: tuple, fl: Flow) -> dict:
    kind, d, proto, uid, _src, _dst, iface = key
    if fl.progs:
        prog = ",".join(fl.progs[:MAX_PROGS]) + ("+" if len(fl.progs) > MAX_PROGS else "")
    else:
        prog = {"fwd": "vm" if kind.startswith("fwd_vm") else "-", "in": "-"}.get(d, "?")
    detail = [("count", f"{fl.n} line{'s' if fl.n != 1 else ''}, first {st.stamp(fl.first)}")]
    if fl.ports:
        detail.append((f"{fl.side} ports", " ".join(fl.ports) + ("  (newest first)"
                                                                 if len(fl.ports) > 1 else "")))
    if len(fl.progs) > 1:
        detail.append(("programs", ", ".join(fl.progs)))
    detail.append(("last line", "fields below"))
    return {"cells": [st.hms(fl.last), str(fl.n), d, fl.verdict, proto, uid, prog,
                      fl.src, fl.dst, iface],
            "sev": kind_sev(kind) or "ok", "tone": _tone(fl.verdict),
            "id": "|".join(key),
            "detail": [{"k": k, "v": v} for k, v in detail]
                      + _audit_detail(st, fl.entry, fl.verdict)}


def _vpn(st: State, checks: list, wall: float) -> tuple:
    """-> (kv items, summary text, fwmark or None, tunnel up)."""
    t = st.tunnel
    res = st.cmd("wg", "show", t, "latest-handshakes")
    if res.rc != 0:
        checks.append(("warn", f"{t} down"))
        st.prev_tx = None
        return [_item("tunnel", f"{t} down ({_fail(res)})", "warn")], f"{t} down", None, False
    hs = vpn.handshake(res.out)
    items = [_item("tunnel", f"{t} up", tone="green")]

    res = st.cmd("wg", "show", t, "transfer")
    rx, tx = vpn.transfer(res.out) if res.rc == 0 else (None, None)
    sending = tx is not None and st.prev_tx is not None and tx > st.prev_tx
    st.prev_tx = tx

    res = st.cmd("wg", "show", t, "endpoints")
    items.append(_item("endpoint", vpn.endpoint(res.out) if res.rc == 0 else _fail(res)))

    if hs == 0:
        sev = "warn" if sending else "info"
        items.append(_item("handshake", "never", sev))
        if sev != "ok":
            checks.append((sev, "no handshake"))
        hs_text = "hs never"
    else:
        age = max(0, wall - hs)
        if age > HS_STALE and sending:
            items.append(_item("handshake", f"{_age(age)} ago, sending", "crit"))
            checks.append(("crit", "handshake stale"))
        elif age > HS_STALE:
            items.append(_item("handshake", f"{_age(age)} ago (idle)"))
        else:
            items.append(_item("handshake", f"{_age(age)} ago", tone="green"))
        hs_text = f"hs {_age(age)}"
    if rx is not None:                 # since the tunnel came up: received / sent
        items.append(_item("recv / sent", f"{_human(rx)}B / {_human(tx)}B"))

    res = st.cmd("wg", "show", t, "fwmark")
    mark = vpn.fwmark(res.out) if res.rc == 0 else None
    return items, f"{t} up | {hs_text}", mark, True


def _fwmark(st: State, mark, tunnel_up: bool, checks: list) -> dict | None:
    res = st.cmd("nft", "-j", "list", "set", *TABLE, "wg_fwmark")
    if res.rc != 0:
        if tunnel_up:
            checks.append(("crit", "wg_fwmark set missing"))
            return _item("fwmark", f"set: {_fail(res)}", "crit")
        return None
    elems = nft.set_elems(res.out)
    if not tunnel_up:
        return _item("fwmark", "set " + (", ".join(hex(e) for e in elems) or "empty"))
    if mark is not None and mark in elems:
        return _item("fwmark", f"{hex(mark)} (in set)", tone="green")
    checks.append(("crit", "fwmark mismatch"))
    live = hex(mark) if mark is not None else "off"
    return _item("fwmark", f"live {live}, set {', '.join(hex(e) for e in elems) or 'empty'}",
                 "crit")


def _routes(st: State, checks: list) -> list:
    items = []
    for fam in ("-4", "-6"):
        res = st.cmd("ip", "-j", fam, "route", "show", "default")
        key = f"default v{fam[1]}"
        if res.rc != 0:
            items.append(_item(key, _fail(res), "warn"))
            checks.append(("warn", f"{key} unknown"))
            continue
        rts = vpn.routes(res.out)
        if not rts:
            items.append(_item(key, "none"))
            continue
        dev, metric, gw = rts[0]
        if dev in st.ks:
            items.append(_item(key, f"{dev} (kill switch)", tone="green"))
        elif dev == st.tunnel:
            items.append(_item(key, dev, tone="green"))
        else:
            items.append(_item(key, f"{dev} via {gw or '-'} metric {metric}", "warn"))
            checks.append(("warn", f"{key} not kill switch"))
    return items


def _uptime(st: State) -> float | None:
    try:
        with open(st.uptime_file, "rb") as f:
            return float(f.read(64).split()[0])
    except (OSError, ValueError, IndexError):
        return None


def _scan(st: State, *args) -> tuple:
    """Boot journal query with -g. -> (entries, problem or '')."""
    res = st.cmd("journalctl", "-b", "0", "_TRANSPORT=kernel", "-o", "json",
                 "--output-fields=MESSAGE", "-q", "--no-pager", *args, timeout=BOOT_TIMEOUT)
    cut = res.timed_out or res.truncated
    if res.rc != 0 and not cut and (res.out.strip() or res.err.strip()):
        return [], _fail(res)                          # rc 1, no output: no match
    entries, _cursor, _bad = journal.parse(res.out)
    return entries, ("cut" if cut else "")


def _boot_scan(st: State) -> None:
    """Once at start: leak lines and the first tunnel flow of this boot.

    The live reader starts at the newest entry, so leaks from before sectop
    started (pre-connect window) would never reach the out_leak box.
    """
    up = _uptime(st)
    st.boot = st.wall() - up if up is not None else None
    try:
        first, err1 = _scan(st, "--grep=^HFW-OUT-NEW:", "-n", "+1")
        leaks, err2 = _scan(st, "--grep=^HFW-OUT-LEAK:")
    except (ValueError, KeyError, TypeError) as e:
        st.boot_note = f"boot scan: {type(e).__name__}"
        return
    known = not err1
    st.tunnel_first = first[0].ts if first else None
    for e in leaks:
        if e.kind != "out_leak":
            continue
        st.leak_seen.add(e.cursor)
        if not known:
            ctx = "unknown"
        elif st.tunnel_first is None or e.ts < st.tunnel_first:
            ctx = "pre-connect"
        else:
            ctx = "after connect"
        st.leaks.appendleft((e, ctx))
    problems = [f"{what} {err}" for what, err in (("first flow", err1), ("leaks", err2)) if err]
    st.boot_note = "boot scan: " + ", ".join(problems) if problems else ""


def _leak_box(st: State, entries: list, up: bool, total, live: str) -> dict:
    """out_leak box: boot scan + live leak lines, newest first, with context."""
    for e in entries:
        if e.kind == "out_new" and st.tunnel_first is None:
            st.tunnel_first = e.ts
        if e.kind != "out_leak" or e.cursor in st.leak_seen:
            continue
        if up:
            ctx = "tunnel up"
        else:
            ctx = "pre-connect" if st.tunnel_first is None else "tunnel down"
        st.leaks.appendleft((e, ctx))
    rows = []
    for e, ctx in list(st.leaks)[:LEAK_ROWS]:
        f = e.fields
        detail = [("meaning", CONTEXT_NOTE[ctx])]
        if st.boot is not None:
            detail.append(("after boot", _since(e.ts - st.boot)))
        verdict = _verdict(e.kind, live)
        rows.append({
            "cells": [st.hms(e.ts), f.get("UID") or "-", f.get("PROTO", "-").lower(),
                      journal.dst(e), f.get("OUT") or "-", ctx],
            "sev": "info" if ctx == "pre-connect" else "crit", "tone": _tone(verdict),
            "detail": [{"k": k, "v": v} for k, v in detail] + _audit_detail(st, e, verdict)})
    title = f"out_leak {total if total is not None else '?'}"
    if len(st.leaks) > LEAK_ROWS:
        title += f"  (newest {LEAK_ROWS} of {len(st.leaks)} lines)"
    if st.boot_note:
        title += f"  ({st.boot_note})"
    sev = "crit" if any(r["sev"] == "crit" for r in rows) else "ok"
    return {"id": "leak", "title": title, "type": "table", "columns": list(LEAK_COLUMNS),
            "rows": rows, "sev": sev}


def _audit_detail(st: State, e, verdict: str) -> list:
    """Shown on enter: rule, verdict meaning, full time, every log field."""
    rule = e.kind + (f"  {st.comments[e.kind]}" if st.comments.get(e.kind) else "")
    out = [("rule", rule), ("verdict", f"{verdict}  {VERDICT_NOTE[verdict]}"),
           ("time", st.stamp(e.ts)), ("prefix", e.code)]
    out += [(k, v) for k, v in e.fields.items() if v]
    if e.flags:
        out.append(("flags", " ".join(e.flags)))
    return [{"k": k, "v": v} for k, v in out]


def _conns(st: State, checks: list) -> tuple:
    """-> (panel, parsed connections)."""
    res = st.cmd("ss", "-tunapH", "state", "established")
    if res.rc != 0:
        checks.append(("warn", "ss error"))
        return _conns_error(_fail(res)), []
    cs = sorted(conns.parse(res.out), key=lambda c: (",".join(c.procs), c.peer))
    rows = [{"cells": [c.proto, c.peer, ",".join(c.procs) or "-", c.local]}
            for c in cs[:MAX_CONNS]]
    title = f"connections {len(cs)}" + (f" (first {MAX_CONNS})" if len(cs) > MAX_CONNS else "")
    return {"id": "conns", "title": title, "type": "table",
            "columns": ["proto", "peer", "proc", "local"], "rows": rows}, cs


def _conns_error(msg: str) -> dict:
    return {"id": "conns", "title": f"connections: {msg}", "type": "table",
            "columns": ["proto", "peer", "proc", "local"], "rows": [], "sev": "warn"}


def _note(items: list, key: str, err: str, value):
    items.append(_item(key, err, "warn"))
    return value


def _safe(fn, what: str, checks: list, default):
    """Parse errors in one source do not hide the others."""
    try:
        return fn()
    except (ValueError, KeyError, TypeError, IndexError) as e:
        checks.append(("warn", f"{what} parse error"))
        return default(f"{type(e).__name__}: {e}")


# --- module API -----------------------------------------------------------

def init(cfg: dict) -> State:
    unknown = set(cfg) - OPTIONS
    if unknown:
        raise ValueError(f"unknown option(s): {', '.join(sorted(unknown))}")
    tunnel = cfg.get("tunnel", DEFAULT_TUNNEL)
    ks = cfg.get("ks_ifaces", list(DEFAULT_KS))
    hold = cfg.get("hold", HOLD)
    if not isinstance(tunnel, str) or not IFACE_RE.fullmatch(tunnel):
        raise ValueError("tunnel: interface name required")
    if not isinstance(ks, list) or not ks or \
            not all(isinstance(i, str) and IFACE_RE.fullmatch(i) for i in ks):
        raise ValueError("ks_ifaces: list of interface names required")
    if isinstance(hold, bool) or not isinstance(hold, (int, float)) or not 0 <= hold <= 3600:
        raise ValueError("hold: seconds 0..3600 required")
    st = State(tunnel=tunnel, ks=ks, hold=float(hold))
    _start_cursor(st)
    _boot_scan(st)
    return st


def _start_cursor(st: State) -> None:
    """Start at the newest kernel entry so old lines are not replayed."""
    res = st.cmd("journalctl", "_TRANSPORT=kernel", "-o", "json",
                 "--output-fields=MESSAGE", "-q", "--no-pager", "-n", "1")
    if res.rc == 0:
        _entries, cursor, _bad = journal.parse(res.out)
        st.cursor = cursor


def collect(st: State) -> dict:
    now, wall = st.mono(), st.wall()
    checks, panels = [], []

    fw_items, counters, live = _safe(lambda: _hostfw(st, checks), "nft", checks,
                                     lambda e: ([_item("table", e, "warn")], None, "?"))
    events, entries = _safe(lambda: _events(st, checks, fw_items), "journal", checks,
                            lambda e: _note(fw_items, "log reader", e, ([], [])))
    _recent(st, entries)
    table, totals, deltas = _safe(lambda: _counters(st, counters, now, live), "counters", checks,
                                  lambda e: (None, {}, {}))
    _held_checks(st, now, checks)

    vpn_items, vpn_text, mark, up = _safe(
        lambda: _vpn(st, checks, wall), "wg", checks,
        lambda e: ([_item("tunnel", e, "warn")], f"{st.tunnel} ?", None, False))
    fm = _safe(lambda: _fwmark(st, mark, up, checks), "fwmark", checks,
               lambda e: _item("fwmark", e, "warn"))
    if fm:
        vpn_items.append(fm)
    vpn_items += _safe(lambda: _routes(st, checks), "routes", checks,
                       lambda e: [_item("routes", e, "warn")])

    blocked = sum(d for n, d in deltas.items() if kind_sev(n))
    if deltas:
        st.blocked.append(blocked)

    panels.append({"id": "hostfw", "title": "hostfw", "type": "kv", "items": fw_items,
                   "sev": worst(*(i["sev"] for i in fw_items))})
    panels.append({"id": "vpn", "title": "vpn", "type": "kv", "items": vpn_items,
                   "sev": worst(*(i["sev"] for i in vpn_items))})
    if table:
        panels.append(table)
    panels.append(_safe(lambda: _leak_box(st, entries, up, totals.get("out_leak"), live),
                        "leak", checks,
                        lambda e: {"id": "leak", "title": f"out_leak: {e}", "type": "table",
                                   "columns": list(LEAK_COLUMNS), "rows": [], "sev": "warn"}))
    panels.append({"id": "blocked", "title": "blocked / tick", "type": "spark",
                   "values": list(st.blocked), "unit": "pkt",
                   "sev": "warn" if blocked else "ok"})
    conns_panel, cs = _safe(lambda: _conns(st, checks), "ss", checks,
                            lambda e: (_conns_error(e), []))
    panels.append(_safe(lambda: _audit(st, entries, cs, live), "audit", checks,
                        lambda e: {"id": "audit", "title": f"audit: {e}", "type": "table",
                                   "columns": list(AUDIT_COLUMNS), "rows": [], "sev": "warn"}))
    panels.append(conns_panel)

    status = worst(*(s for s, _ in checks))
    leak = totals.get("out_leak")
    summary = " | ".join([live, vpn_text, f"leak {leak if leak is not None else '?'}"])
    problems = [t for s, t in checks if s in ("warn", "crit")]
    if problems:
        summary += " | " + ", ".join(problems[:3])
    return {"v": 1, "status": status, "summary": summary, "panels": panels, "events": events}
