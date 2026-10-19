"""firewall: hostfw + Proton WireGuard status for sectop.

Sources (fixed argv, via core.run.run): nft counters / enforce chain /
wg_fwmark set, kernel journal (HFW- lines, cursor), ss, wg per-field
subcommands, ip default routes. Files: /etc/hostfw/mode, /run/hostfw/rollback.
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
HS_STALE = 180           # WireGuard rejects keys after 180 s
HOLD = 60.0              # seconds a new blocked packet keeps its severity in status
SPARK = 120
MAX_CONNS = 50
MAX_EVENTS = 100
MAX_AUDIT = 200
FILE_MAX = 4096

TABLE = ("inet", "hostfw")
MODE_FILE = "/etc/hostfw/mode"
ROLLBACK_FILE = "/run/hostfw/rollback"
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
AUDIT_COLUMNS = ["time", "dir", "verdict", "proto", "uid", "prog", "src", "dst", "iface"]
VERDICT_NOTE = {
    "allow": "allowed by hostfw (logged new flow or exception)",
    "drop": "kill switch: always dropped",
    "zone": "hostfw only logs, the firewalld zone decides (default zone: drop)",
    "block": "rejected by hostfw (enforce mode)",
    "pass": "deny rule in observe mode: logged, not blocked",
    "deny": "deny rule, mode unknown",
}


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
                 mode_file=MODE_FILE, rollback_file=ROLLBACK_FILE, hms=_hms, stamp=_stamp):
        self.tunnel, self.ks, self.hold = tunnel, tuple(ks), hold
        self.run, self.mono, self.wall, self.owner = run, mono, wall, owner
        self.mode_file, self.rollback_file = mode_file, rollback_file
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
        self.leak = collections.deque(maxlen=SPARK)
        self.audit = collections.deque(maxlen=MAX_AUDIT)   # rows, newest first

    def cmd(self, *argv):
        return self.run([self.bins[argv[0]], *argv[1:]], timeout=TIMEOUT)


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


def _item(k: str, v: str, sev: str = "ok") -> dict:
    return {"k": k, "v": v, "sev": sev}


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
    items.append(_item("table", "loaded"))

    res = st.cmd("nft", "-j", "list", "chain", *TABLE, "enforce")
    live = nft.mode(res.out) if res.rc == 0 else "unknown"
    sev = {"enforce": "ok", "observe": "warn"}.get(live, "warn")
    if sev != "ok":
        checks.append((sev, f"mode {live}"))
    items.append(_item("mode", live if res.rc == 0 else f"unknown ({_fail(res)})", sev))

    try:
        boot = _read(st.mode_file, st.owner)
        boot = boot.strip() if boot is not None else "-"
        items.append(_item("boot mode", boot, "ok" if boot in (live, "-") else "info"))
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


def _counters(st: State, counters: dict | None, now: float) -> tuple:
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
                               _human(nbytes)], "sev": sev or "ok"})
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
        checks.append(("warn", "journal error"))
        items.append(_item("journal", _fail(res), "warn"))
        return [], []
    entries, cursor, bad = journal.parse(res.out)
    if cursor:
        st.cursor = cursor
    state = "ok"
    if cut:
        state = "behind (output cut, catching up)"
    if bad:
        state = f"{bad} bad line(s)"
    items.append(_item("journal", state, "ok" if state == "ok" else "info"))

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


def _audit(st: State, entries: list, cs: list, live: str) -> dict:
    """Add one row per HFW line (hidden kinds skipped), newest first."""
    idx = conns.index(cs)
    for e in entries:
        if e.kind in SEV and SEV[e.kind] is None:
            continue
        f = e.fields
        proto = f.get("PROTO", "-").lower()
        if e.dir == "out":
            prog, iface = "?", f.get("OUT") or "-"
            if proto in ("tcp", "udp"):
                key = (proto, *conns.split(journal.src(e)), *conns.split(journal.dst(e)))
                prog = ",".join(idx.get(key, ())) or "?"
        elif e.dir == "fwd":
            prog = "vm" if e.kind.startswith("fwd_vm") else "-"
            iface = f"{f.get('IN') or '-'}>{f.get('OUT') or '-'}"
        else:
            prog, iface = "-", f.get("IN") or "-"
        verdict = _verdict(e.kind, live)
        st.audit.appendleft({
            "cells": [st.hms(e.ts), e.dir, verdict, proto, f.get("UID") or "-",
                      prog, journal.src(e), journal.dst(e), iface],
            "sev": kind_sev(e.kind) or "ok",
            "detail": _audit_detail(st, e, verdict)})
    return {"id": "audit", "title": f"audit {len(st.audit)}", "type": "table",
            "columns": list(AUDIT_COLUMNS), "rows": list(st.audit)}


def _vpn(st: State, checks: list, wall: float) -> tuple:
    """-> (kv items, summary text, fwmark or None, tunnel up)."""
    t = st.tunnel
    res = st.cmd("wg", "show", t, "latest-handshakes")
    if res.rc != 0:
        checks.append(("warn", f"{t} down"))
        st.prev_tx = None
        return [_item("tunnel", f"{t} down ({_fail(res)})", "warn")], f"{t} down", None, False
    hs = vpn.handshake(res.out)
    items = [_item("tunnel", f"{t} up")]

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
            items.append(_item("handshake", f"{_age(age)} ago"))
        hs_text = f"hs {_age(age)}"
    if rx is not None:
        items.append(_item("rx / tx", f"{_human(rx)} / {_human(tx)}"))

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
        return _item("fwmark", f"{hex(mark)} (in set)")
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
            items.append(_item(key, f"{dev} (kill switch)"))
        elif dev == st.tunnel:
            items.append(_item(key, dev))
        else:
            items.append(_item(key, f"{dev} via {gw or '-'} metric {metric}", "warn"))
            checks.append(("warn", f"{key} not kill switch"))
    return items


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
    table, totals, deltas = _safe(lambda: _counters(st, counters, now), "counters", checks,
                                  lambda e: (None, {}, {}))
    _held_checks(st, now, checks)
    events, entries = _safe(lambda: _events(st, checks, fw_items), "journal", checks,
                            lambda e: _note(fw_items, "journal", e, ([], [])))

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
        st.leak.append(deltas.get("out_leak", 0))

    panels.append({"id": "hostfw", "title": "hostfw", "type": "kv", "items": fw_items,
                   "sev": worst(*(i["sev"] for i in fw_items))})
    panels.append({"id": "vpn", "title": "vpn", "type": "kv", "items": vpn_items,
                   "sev": worst(*(i["sev"] for i in vpn_items))})
    if table:
        panels.append(table)
    panels.append({"id": "blocked", "title": "blocked / tick", "type": "spark",
                   "values": list(st.blocked), "unit": "pkt",
                   "sev": "warn" if blocked else "ok"})
    panels.append({"id": "leak", "title": "out_leak / tick", "type": "spark",
                   "values": list(st.leak), "unit": "pkt",
                   "sev": "crit" if deltas.get("out_leak") else "ok"})
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
