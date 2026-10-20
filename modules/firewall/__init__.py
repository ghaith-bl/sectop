"""firewall: hostfw + Proton WireGuard status for sectop.

Sources (fixed argv). Every tick: nft table without set elements (counters +
enforce chain), kernel journal (HFW- lines, cursor), wg handshakes + transfer,
ss. Every SLOW s or when the tunnel goes up / down: wg endpoints + fwmark, nft
wg_fwmark set, ip default routes. nft and wg need CAP_NET_ADMIN: their results
come from the net unit's files (core/netd.py Reader), the rest via
core.run.run as user sectop. Files:
/etc/hostfw/mode, /run/hostfw/rollback, /proc/uptime. At start: one boot
journal scan (leak lines, first tunnel flow).
Audit box: every HFW line (allowed + blocked, in + out), program from ss.
Programs box: the same lines + open sockets, one row per program.
Snapshot v2: problems are checks with keys (core/alerts.py keeps the alerts).
See docs/modules/firewall.md.
"""

import collections
import ipaddress
import os
import re
import stat
import time

from core import netd
from core.module import SEV_RANK, worst
from core.run import run as _run
from modules.firewall import conns, journal, nft, vpn

NAME = "firewall"
INTERVAL = netd.FW_INTERVAL

TIMEOUT = netd.TIMEOUT   # per command, keeps a full tick below INTERVAL
BOOT_TIMEOUT = 5.0       # boot journal scan, once in init()
SLOW = netd.FW_SLOW      # endpoint, live fwmark, wg_fwmark set, default routes: rarely change
HS_STALE = 180           # WireGuard rejects keys after 180 s
HOLD = 60.0              # seconds the alert (and the counter row color) stays after new packets
SPARK = 120
MAX_PEERS = 200          # remote addresses kept, least recently seen out first
MAX_APPS = 100           # programs kept (programs box), least recently seen out first
MAX_APP_PEERS = 50       # remote addresses kept per program
MAX_SOCKS = 10           # open sockets listed in a peer's detail
MAX_EVENTS = 100
MAX_AUDIT = 200          # audit flows (grouped repeats) kept, newest first
MAX_PORTS = 10           # varying ports kept per flow, shown in its detail
MAX_PROGS = 3
MAX_LEAKS = 100          # leak lines kept (boot scan + live), newest first
RECENT = 10              # log lines kept per counter, shown in its detail
LEAK_ROWS = 8            # shown in the out_leak box
FILE_MAX = 4096

TABLE = netd.TABLE
MODE_FILE = "/etc/hostfw/mode"
ROLLBACK_FILE = "/run/hostfw/rollback"
UPTIME_FILE = "/proc/uptime"
DEFAULT_TUNNEL = netd.DEFAULT_TUNNEL
DEFAULT_KS = ("pvpnksintrf0", "pvpnksintrf1")
OPTIONS = {"tunnel", "ks_ifaces", "hold"}
IFACE_RE = netd.IFACE_RE

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
PEER_COLUMNS = ["peer", "open", "new", "drop", "prog", "last"]
APP_COLUMNS = ["prog", "uid", "open", "out", "block", "in", "peers", "last"]
PICK_RE = re.compile(r"[ -~]{1,60}")      # row filter: what the filter prompt can type
# programs box rows for lines without a program: key -> (prog cell, row filter, note)
APP_OTHER = {
    "(inbound)": ("(inbound)", "zone",
                  "inbound lines: no program (hostfw logs, the firewalld zone decides)"),
    "vm": ("vm", "vm", "forwarded traffic of libvirt VMs"),
    "(forward)": ("(forward)", "fwd_in", "forwarded traffic not from a VM"),
}
CGNAT = ipaddress.ip_network("100.64.0.0/10")
ULA = ipaddress.ip_network("fc00::/7")
CONTEXT_NOTE = {
    "pre-connect": "before the first flow via the tunnel this boot "
                   "(expected: DoH fallback before Proton connects)",
    "tunnel up": "the tunnel was up: a program sent around it",
    "tunnel down": "the tunnel was down after it had been up (reconnect window)",
    "after connect": "after the first flow via the tunnel this boot, before sectop "
                     "started: tunnel state at that time unknown",
    "unknown": "first tunnel flow unknown (boot scan failed)",
}
CONTEXT_SEV = {"out_leak": "crit, info pre-connect",            # counter detail text
               "in_vpn": "warn, info for late replies from known peers"}
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


class State:
    def __init__(self, tunnel=DEFAULT_TUNNEL, ks=DEFAULT_KS, hold=HOLD, run=_run, net=None,
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
        self.bins = {n: netd.bin_path(n) for n in ("nft", "journalctl", "ss", "wg", "ip")}
        self.net = net if net is not None else netd.Reader(tunnel, wall=wall)
        self.cursor = None
        self.since = int(wall())
        self.prev = None               # counters of last tick
        self.prev_tx = None
        self.held = {}                 # kind -> (mono time, sev): counter row color until then
        self.blocked = collections.deque(maxlen=SPARK)
        self.flows = {}                # audit flow key -> Flow, oldest first
        self.peers = {}                # remote address -> Peer, least recently seen first
        self.apps = {}                 # program key -> App, least recently seen first
        self.lines = 0                 # audit lines since start (all flows)
        self.leaks = collections.deque(maxlen=MAX_LEAKS)   # (Entry, context), newest first
        self.recent = {}               # counter name -> deque of (ts, summary), newest first
        self.leak_seen = set()         # cursors from the boot scan (live reader skips them)
        self.tunnel_first = None       # epoch of the first HFW-OUT-NEW line this boot
        self.boot = None               # boot time, epoch (from /proc/uptime)
        self.boot_note = ""            # boot scan problem, shown in the out_leak title
        self.slow_at = None            # mono time the slow sources are due again
        self.slow_up = None            # tunnel state at the last slow refresh
        self.slow = (None, [], [])     # last slow result: endpoint item, items, checks

    def cmd(self, *argv, timeout=TIMEOUT):
        """nft / wg: last result from the net unit (CAP_NET_ADMIN). Others: run here."""
        full = [self.bins[argv[0]], *argv[1:]]
        if argv[0] in netd.NET_BINS:
            return self.net(full, timeout=timeout)
        return self.run(full, timeout=timeout)


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


def _item(k: str, v: str, sev: str = "ok", tone: str = "", ip: str | None = None) -> dict:
    """kv item; tone green = healthy state (drawn only while sev is ok)."""
    out = {"k": k, "v": v, "sev": sev}
    if tone and sev == "ok":
        out["tone"] = tone
    if ip:
        out["ip"] = ip
    return out


def _ip(text: str) -> str | None:
    """Address for the row `ip` (whois), None if text is not one."""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _remote(e) -> str | None:
    """The other side of a log line: dst for out / fwd, src for in."""
    return _ip(e.fields.get("SRC" if e.dir == "in" else "DST", ""))


def _chk(checks: list, key: str, sev: str, title: str, detail: str = "", n: int = 0,
         hold: float | None = None) -> None:
    """Add a check (Snapshot v2): a problem that is true now."""
    c = {"key": key, "sev": sev, "title": title, "detail": detail, "n": n}
    if hold is not None:
        c["hold"] = hold
    checks.append(c)


def _merge(checks: list) -> list:
    """One check per key (the same source can fail twice in a tick): the worse
    severity keeps its title and detail, n adds up. Input dicts not changed."""
    out = {}
    for c in checks:
        old = out.get(c["key"])
        if old is None:
            out[c["key"]] = dict(c)
            continue
        if SEV_RANK[c["sev"]] > SEV_RANK[old["sev"]]:
            old.update(sev=c["sev"], title=c["title"], detail=c["detail"])
        old["n"] += c["n"]
    return list(out.values())


# --- sources --------------------------------------------------------------

def _hostfw(st: State, checks: list) -> tuple:
    """-> (kv items, counters or None, live mode).

    One nft call: the whole table without set elements (-t) has the counters
    and the enforce chain. Set elements (Proton entry IPs: thousands) are not needed.
    """
    items = []
    res = st.cmd("nft", "-j", "-t", "list", "table", *TABLE)
    if res.rc != 0:
        msg = "missing" if nft.missing(res.err) else _fail(res)
        _chk(checks, "table", "crit", f"table {msg}")
        items.append(_item("table", msg, "crit"))
        return items, None, "-"
    counters = nft.counters(res.out)
    st.comments = nft.comments(res.out)
    items.append(_item("table", "loaded", tone="green"))

    live = nft.mode(res.out)
    sev = {"enforce": "ok", "observe": "warn"}.get(live, "warn")
    if sev != "ok":
        _chk(checks, "mode", sev, f"mode {live}")
    items.append(_item("mode", live, sev, "green"))

    try:
        boot = _read(st.mode_file, st.owner)
        boot = boot.strip() if boot is not None else "-"
        items.append(_item("boot mode", boot, "ok" if boot in (live, "-") else "info",
                           "green" if boot == live else ""))
    except (OSError, ValueError) as e:
        items.append(_item("boot mode", str(e), "warn"))
        _chk(checks, "boot_mode", "warn", "boot mode unreadable", str(e))

    try:
        rb = _read(st.rollback_file, st.owner)
    except (OSError, ValueError) as e:
        items.append(_item("rollback", str(e), "warn"))
        _chk(checks, "rollback_file", "warn", "rollback file unreadable", str(e))
    else:
        if rb is None:
            items.append(_item("rollback", "-"))
        else:
            text, armed = _rollback_state(rb, st.wall())
            if armed:
                _chk(checks, "rollback", "info", "rollback armed", text)
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
        new = "no alert (noise)"
    elif sev is None:
        new = "no alert (allowed traffic)"
    else:
        new = (f"alert new:{name} ({CONTEXT_SEV.get(name, sev)}), kept {st.hold:g} s "
               "after the last tick with new packets")
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


def _deltas(st: State, counters: dict | None) -> tuple:
    """-> (totals, new packets per counter since the last tick)."""
    if counters is None:
        return {}, {}
    prev = st.prev or {}
    deltas = {}
    for name, (pkts, _b) in counters.items():
        old = prev.get(name, (pkts, 0))[0] if st.prev is not None else pkts
        deltas[name] = pkts - old if pkts >= old else pkts      # reset -> count again
    st.prev = counters
    return {n: c[0] for n, c in counters.items()}, deltas


def _counter_panel(st: State, counters: dict | None, deltas: dict, now: float,
                   live: str = "?") -> dict | None:
    """Counter rows keep the severity of their last new packets for `hold` s
    (st.held, set by _new_checks): display only, the alert engine holds alerts."""
    if counters is None:
        return None
    rows = []
    for name, (pkts, nbytes) in counters.items():
        if pkts == 0:
            continue                                          # zero counters hidden
        until, sev = st.held.get(name, (0, None))
        sev = sev if until > now else None
        rows.append({"cells": [name, str(pkts), f"+{deltas[name]}" if deltas[name] else "",
                               _human(nbytes)], "sev": sev or "ok",
                     "tone": _tone(_verdict(name, live)),
                     "detail": _counter_detail(st, name, nbytes, live)})
    zero = len(counters) - len(rows)
    title = "hostfw counters" + (f"  ({zero} zero hidden)" if zero else "")
    return {"id": "counters", "title": title, "type": "table",
            "columns": ["counter", "pkts", "new", "bytes"], "rows": rows}


def _leak_ctx(st: State, up: bool) -> str:
    """Context of a live out_leak (same rule as the out_leak box)."""
    if up:
        return "tunnel up"
    return "pre-connect" if st.tunnel_first is None else "tunnel down"


def _in_vpn(st: State, entries: list, cs: list) -> tuple:
    """Severity of new in_vpn packets this tick -> (sev, note).

    info: every in_vpn line is from a peer this host talked to (an allowed flow
    logged, or a socket open now): late replies after a flow closed. warn: any
    other source, or no line this tick (rate limit / lag: source unknown).
    """
    srcs = {str(a) for e in entries if e.kind == "in_vpn"
            if (a := _addr(e.fields.get("SRC", ""))) is not None}
    if not srcs:
        return "warn", "no log line this tick: source unknown"
    known = {ip for ip, p in st.peers.items() if p.new}
    known |= {str(a) for c in cs if (a := _addr(conns.split(c.peer)[0])) is not None}
    unknown = sorted(srcs - known)
    if not unknown:
        return "info", f"late replies from {len(srcs)} peer(s) this host talked to"
    more = f" +{len(unknown) - 3}" if len(unknown) > 3 else ""
    return "warn", "from " + ", ".join(unknown[:3]) + more


def _new_checks(st: State, deltas: dict, up: bool, vpn_in: tuple, now: float,
                checks: list) -> str:
    """One check per deny kind with new packets this tick (n = packets, hold =
    st.hold). Context decides out_leak / in_vpn severity. -> worst sev (spark)."""
    sevs = []
    for name, d in deltas.items():
        sev = kind_sev(name)
        if d <= 0 or sev is None:
            continue
        title, detail = f"new {name}", f"+{d} pkt this tick; {MATCH.get(name, name)}"
        if name == "out_leak":
            ctx = _leak_ctx(st, up)
            sev = "info" if ctx == "pre-connect" else "crit"
            title += f" ({ctx})"
            detail += f"; {CONTEXT_NOTE[ctx]}"
        elif name == "in_vpn":
            sev, note = vpn_in
            detail += f"; {note}"
        st.held[name] = (now + st.hold, sev)
        _chk(checks, f"new:{name}", sev, title, detail, n=d, hold=st.hold)
        sevs.append(sev)
    for name, (until, _sev) in list(st.held.items()):
        if until <= now:
            del st.held[name]
    return worst(*sevs)


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
        _chk(checks, "log_reader", "warn", "log reader error", _fail(res))
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
    row = {"cells": [st.hms(fl.last), str(fl.n), d, fl.verdict, proto, uid, prog,
                     fl.src, fl.dst, iface],
           "sev": kind_sev(kind) or "ok", "tone": _tone(fl.verdict),
           "id": "|".join(key),
           "detail": [{"k": k, "v": v} for k, v in detail]
                     + _audit_detail(st, fl.entry, fl.verdict)}
    ip = _remote(fl.entry)
    if ip:
        row["ip"] = ip
    return row


def _vpn(st: State, checks: list, wall: float, ks_new: int = 0) -> tuple:
    """Every tick: handshake + transfer. -> (kv items, summary text, tunnel up).
    ks_new: kill switch drops this tick (context of a stale handshake)."""
    t = st.tunnel
    res = st.cmd("wg", "show", t, "latest-handshakes")
    if res.rc != 0:
        _chk(checks, f"tunnel_down:{t}", "warn", f"{t} down", _fail(res))
        st.prev_tx = None
        return [_item("tunnel", f"{t} down ({_fail(res)})", "warn")], f"{t} down", False
    hs = vpn.handshake(res.out)
    items = [_item("tunnel", f"{t} up", tone="green")]

    res = st.cmd("wg", "show", t, "transfer")
    rx, tx = vpn.transfer(res.out) if res.rc == 0 else (None, None)
    sending = tx is not None and st.prev_tx is not None and tx > st.prev_tx
    st.prev_tx = tx

    if hs == 0:
        sev = "warn" if sending else "info"
        items.append(_item("handshake", "never", sev))
        if sev != "ok":
            _chk(checks, f"no_handshake:{t}", sev, "no handshake",
                 "tx growing" if sending else "idle")
        hs_text = "hs never"
    else:
        age = max(0, wall - hs)
        if age > HS_STALE and sending:
            items.append(_item("handshake", f"{_age(age)} ago, sending", "crit"))
            detail = f"last handshake {_age(age)} ago, tx growing (keys rejected after 180 s)"
            if ks_new:
                detail += f"; kill switch dropped +{ks_new} pkt this tick (fail closed)"
            _chk(checks, f"handshake_stale:{t}", "crit", "handshake stale", detail)
        elif age > HS_STALE:
            items.append(_item("handshake", f"{_age(age)} ago (idle)"))
        else:
            items.append(_item("handshake", f"{_age(age)} ago", tone="green"))
        hs_text = f"hs {_age(age)}"
    if rx is not None:                 # since the tunnel came up: received / sent
        items.append(_item("recv / sent", f"{_human(rx)}B / {_human(tx)}B"))
    return items, f"{t} up | {hs_text}", True


def _endpoint(st: State) -> dict:
    res = st.cmd("wg", "show", st.tunnel, "endpoints")
    if res.rc != 0:
        return _item("endpoint", _fail(res))
    ep = vpn.endpoint(res.out)
    return _item("endpoint", ep, ip=_ip(conns.split(ep)[0]))


def _live_mark(st: State):
    res = st.cmd("wg", "show", st.tunnel, "fwmark")
    return vpn.fwmark(res.out) if res.rc == 0 else None


def _slow(st: State, up: bool) -> tuple:
    """Rarely changing sources: endpoint, fwmark (live + set), default routes.

    Run every SLOW s and when the tunnel goes up / down (collect). Their items
    and checks are kept and shown every tick until the next run.
    -> (endpoint item or None, items, checks).
    """
    checks, items, ep, mark, bad = [], [], None, None, []
    if up:
        ep = _safe(lambda: _endpoint(st), "wg", checks,
                   lambda e: _item("endpoint", e, "warn"))
        mark = _safe(lambda: _live_mark(st), "wg", checks, bad.append)
    if bad:                            # live fwmark unreadable: no mismatch claim
        items.append(_item("fwmark", f"live: {bad[0]}", "warn"))
    else:
        fm = _safe(lambda: _fwmark(st, mark, up, checks), "fwmark", checks,
                   lambda e: _item("fwmark", e, "warn"))
        if fm:
            items.append(fm)
    items += _safe(lambda: _routes(st, checks), "routes", checks,
                   lambda e: [_item("routes", e, "warn")])
    return ep, items, checks


def _fwmark(st: State, mark, tunnel_up: bool, checks: list) -> dict | None:
    res = st.cmd("nft", "-j", "list", "set", *TABLE, "wg_fwmark")
    if res.rc != 0:
        if tunnel_up:
            _chk(checks, "fwmark_set", "crit", "wg_fwmark set missing", _fail(res))
            return _item("fwmark", f"set: {_fail(res)}", "crit")
        return None
    elems = nft.set_elems(res.out)
    if not tunnel_up:
        return _item("fwmark", "set " + (", ".join(hex(e) for e in elems) or "empty"))
    if mark is not None and mark in elems:
        return _item("fwmark", f"{hex(mark)} (in set)", tone="green")
    live = hex(mark) if mark is not None else "off"
    text = f"live {live}, set {', '.join(hex(e) for e in elems) or 'empty'}"
    _chk(checks, "fwmark", "crit", "fwmark mismatch", text)
    return _item("fwmark", text, "crit")


def _routes(st: State, checks: list) -> list:
    items = []
    for fam in ("-4", "-6"):
        res = st.cmd("ip", "-j", fam, "route", "show", "default")
        key = f"default v{fam[1]}"
        if res.rc != 0:
            items.append(_item(key, _fail(res), "warn"))
            _chk(checks, f"route_unknown:v{fam[1]}", "warn", f"{key} unknown", _fail(res))
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
            text = f"{dev} via {gw or '-'} metric {metric}"
            items.append(_item(key, text, "warn"))
            _chk(checks, f"route:v{fam[1]}", "warn", f"{key} not kill switch", text)
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
        if _ip(f.get("DST", "")):
            rows[-1]["ip"] = _ip(f["DST"])
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
    """-> (open sockets, error or '')."""
    res = st.cmd("ss", "-tunapH", "state", "established")
    if res.rc != 0:
        _chk(checks, "ss", "warn", "ss error", _fail(res))
        return [], _fail(res)
    return conns.parse(res.out), ""


class Peer:
    """One remote address: logged lines (audit) + open sockets (ss)."""

    def __init__(self, ts):
        self.first = self.last = ts
        self.new = self.drop = 0
        self.verdicts = collections.Counter()
        self.progs, self.uids, self.ports, self.ifaces = [], [], [], []


def _addr(text: str):
    """Remote address worth listing, or None (loopback, multicast, broadcast, junk)."""
    try:
        a = ipaddress.ip_address(text)
    except ValueError:
        return None
    if a.is_loopback or a.is_multicast or a.is_unspecified or str(a) == "255.255.255.255":
        return None
    return a


def _scope(a) -> str:
    if a.is_global:
        return "public"
    if a.version == 4 and a in CGNAT:
        return "shared (CGNAT)"
    if a.is_link_local:
        return "link-local"
    if a.version == 6 and a in ULA:
        return "unique local (ULA)"
    return "private" if a.is_private else "special"


def _add(lst: list, value: str, limit: int = MAX_SOCKS) -> None:
    if value and value not in lst and len(lst) < limit:
        lst.append(value)


def _peer(st: State, ip: str, ts: float) -> Peer:
    p = st.peers.pop(ip, None) or Peer(ts)
    st.peers[ip] = p                                        # most recent at the end
    p.last = max(p.last, ts)
    return p


def _peers(st: State, entries: list, cs: list, err: str, live: str, wall: float) -> dict:
    """peers box: one row per remote address, from log lines and open sockets."""
    idx = conns.index(cs)
    for e in entries:
        if e.kind in SEV and SEV[e.kind] is None:
            continue
        f = e.fields
        inbound = e.dir == "in"
        a = _addr(f.get("SRC" if inbound else "DST", ""))
        if a is None:
            continue
        p = _peer(st, str(a), e.ts)
        verdict = _verdict(e.kind, live)
        p.verdicts[verdict] += 1
        if verdict == "allow":
            p.new += 1
        else:
            p.drop += 1
        prog, iface = _prog(e, idx)
        for name in prog.split(","):
            if name not in ("?", "-", ""):
                _add(p.progs, name)
        _add(p.uids, f.get("UID", ""))
        _add(p.ports, f.get("SPT" if inbound else "DPT", ""))
        _add(p.ifaces, iface)
    socks = collections.defaultdict(list)
    for c in cs:
        host, port = conns.split(c.peer)
        a = _addr(host)
        if a is None:
            continue
        socks[str(a)].append(c)
        p = _peer(st, str(a), wall)
        for name in c.procs:
            _add(p.progs, name)
        _add(p.ports, port)
    while len(st.peers) > MAX_PEERS:
        del st.peers[next(iter(st.peers))]                  # least recently seen out
    order = sorted(sorted(st.peers.items()), reverse=True,     # open first, then newest
                   key=lambda kv: (len(socks[kv[0]]) > 0, kv[1].last, len(socks[kv[0]])))
    rows = [_peer_row(st, ip, p, socks[ip]) for ip, p in order]
    n_open = sum(len(v) for v in socks.values())
    title = f"peers {len(rows)}  {n_open} open" + (f"  (ss: {err})" if err else "")
    return {"id": "peers", "title": title, "type": "table", "columns": list(PEER_COLUMNS),
            "rows": rows, "sev": "warn" if err else "ok"}


def _peer_row(st: State, ip: str, p: Peer, socks: list) -> dict:
    progs = p.progs[:MAX_PROGS]
    prog = ",".join(progs) + ("+" if len(p.progs) > MAX_PROGS else "") if progs else "?"
    if p.drop and not (p.new or socks):
        tone = "red"                                        # only dropped / blocked
    else:
        tone = "blue" if p.new or socks else "plain"
    detail = [("scope", _scope(ipaddress.ip_address(ip))),
              ("open now", f"{len(socks)} socket{'s' if len(socks) != 1 else ''}")]
    for c in socks[:MAX_SOCKS]:
        detail.append(("socket", f"{c.proto} {c.local} -> {c.peer}  "
                                 f"{','.join(c.procs) or '-'}"))
    detail += [("logged", f"{p.new} new flows, {p.drop} dropped / blocked lines"),
               ("verdicts", ", ".join(f"{v} {n}" for v, n in p.verdicts.most_common()) or "-"),
               ("first seen", st.stamp(p.first)), ("last seen", st.stamp(p.last)),
               ("programs", ", ".join(p.progs) or "-"), ("uids", ", ".join(p.uids) or "-"),
               ("ports", ", ".join(p.ports) or "-"), ("ifaces", ", ".join(p.ifaces) or "-")]
    return {"cells": [ip, str(len(socks)), str(p.new), str(p.drop), prog, st.hms(p.last)],
            "tone": tone, "id": ip, "ip": ip, "detail": [{"k": k, "v": v} for k, v in detail]}


class App:
    """One program: logged lines (audit) + open sockets (ss)."""

    def __init__(self, ts):
        self.first = self.last = ts
        self.out = self.block = self.inb = 0       # logged lines
        self.kinds = collections.Counter()
        self.peers = collections.Counter()         # remote address -> logged lines
        self.uids = []


def _app_keys(e, prog: str) -> list:
    """Program keys of one log line: names from ss, '? uid N' when not matched,
    (inbound) / vm / (forward) for lines without a program."""
    if e.dir == "in":
        return ["(inbound)"]
    if e.dir == "fwd":
        return ["vm" if e.kind.startswith("fwd_vm") else "(forward)"]
    names = [n for n in prog.split(",") if n not in ("?", "-", "")]
    return names or [f"? uid {e.fields.get('UID') or '-'}"]


def _app(st: State, key: str, ts: float) -> App:
    a = st.apps.pop(key, None) or App(ts)
    st.apps[key] = a                                        # most recent at the end
    a.last = max(a.last, ts)
    return a


def _apps(st: State, entries: list, cs: list, live: str, wall: float) -> dict:
    """programs box: one row per program, from log lines and open sockets."""
    idx = conns.index(cs)
    for e in entries:
        if e.kind in SEV and SEV[e.kind] is None:
            continue
        prog, _iface = _prog(e, idx)
        remote = _remote(e)
        verdict = _verdict(e.kind, live)
        for key in _app_keys(e, prog):
            a = _app(st, key, e.ts)
            if e.dir == "in":
                a.inb += 1
            elif verdict == "allow":
                a.out += 1
            else:
                a.block += 1
            a.kinds[e.kind] += 1
            if remote and (remote in a.peers or len(a.peers) < MAX_APP_PEERS):
                a.peers[remote] += 1
            _add(a.uids, e.fields.get("UID", ""))
    socks = collections.defaultdict(list)
    for c in cs:
        for name in c.procs:
            socks[name].append(c)
            a = _app(st, name, wall)
            host = conns.split(c.peer)[0]
            if _addr(host) is not None and (host in a.peers or len(a.peers) < MAX_APP_PEERS):
                a.peers[host] += 0                          # known peer, no logged line
    while len(st.apps) > MAX_APPS:
        del st.apps[next(iter(st.apps))]                    # least recently seen out
    order = sorted(sorted(st.apps.items()), reverse=True,      # open first, then newest
                   key=lambda kv: (len(socks[kv[0]]) > 0, kv[1].last, len(socks[kv[0]])))
    rows = [_app_row(st, key, a, socks[key]) for key, a in order]
    n_open = sum(1 for key in st.apps if socks[key])
    return {"id": "programs", "title": f"programs {len(rows)}  {n_open} with open sockets",
            "type": "table", "columns": list(APP_COLUMNS), "rows": rows}


def _app_row(st: State, key: str, a: App, socks: list) -> dict:
    other = APP_OTHER.get(key)
    if other:
        prog, pick, note = other
    elif key.startswith("? uid "):
        uid = key[len("? uid "):]
        prog, pick = "?", ("?" if uid == "-" else f"? {uid}")
        note = "program unknown: the flow closed before the next ss poll"
    else:
        prog, pick, note = key, key, ""
    if a.block and not (a.out or a.inb or socks):
        tone = "red"                                        # only dropped / blocked
    else:
        tone = "blue" if a.out or socks else "plain"
    peers = sorted(a.peers.items(), key=lambda kv: (-kv[1], kv[0]))
    detail = []
    if note:
        detail.append(("note", note))
    detail.append(("open now", f"{len(socks)} socket{'s' if len(socks) != 1 else ''}"))
    for c in socks[:MAX_SOCKS]:
        detail.append(("socket", f"{c.proto} {c.local} -> {c.peer}"))
    detail += [("logged", f"{a.out} allowed, {a.block} dropped / blocked, {a.inb} inbound lines"),
               ("kinds", ", ".join(f"{k} {n}" for k, n in a.kinds.most_common()) or "-"),
               ("peers", ", ".join(f"{ip} ({n or 'socket'})" for ip, n in peers[:MAX_SOCKS])
                or "-"),
               ("uids", ", ".join(a.uids) or "-"),
               ("first seen", st.stamp(a.first)), ("last seen", st.stamp(a.last))]
    uids = ",".join(a.uids[:MAX_PROGS]) + ("+" if len(a.uids) > MAX_PROGS else "")
    row = {"cells": [prog, uids or "-", str(len(socks)), str(a.out), str(a.block), str(a.inb),
                     str(len(a.peers)), st.hms(a.last)],
           "tone": tone, "id": key, "detail": [{"k": k, "v": v} for k, v in detail]}
    if PICK_RE.fullmatch(pick) and pick.strip():
        row["filter"] = pick                                # f follow / x hide (core/ui.py)
    return row


def _note(items: list, key: str, err: str, value):
    items.append(_item(key, err, "warn"))
    return value


def _safe(fn, what: str, checks: list, default):
    """Parse errors in one source do not hide the others."""
    try:
        return fn()
    except (ValueError, KeyError, TypeError, IndexError) as e:
        err = f"{type(e).__name__}: {e}"
        _chk(checks, f"parse:{what}", "warn", f"{what} parse error", err)
        return default(err)


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
    totals, deltas = _safe(lambda: _deltas(st, counters), "counters", checks,
                           lambda e: ({}, {}))

    vpn_items, vpn_text, up = _safe(
        lambda: _vpn(st, checks, wall, deltas.get("out_ks", 0)), "wg", checks,
        lambda e: ([_item("tunnel", e, "warn")], f"{st.tunnel} ?", False))
    if st.slow_at is None or now >= st.slow_at or up != st.slow_up:
        st.slow = _slow(st, up)
        st.slow_at, st.slow_up = now + SLOW, up
    ep, slow_items, slow_checks = st.slow
    checks += slow_checks
    vpn_items = vpn_items[:1] + ([ep] if ep else []) + vpn_items[1:] + slow_items

    blocked = sum(d for n, d in deltas.items() if kind_sev(n))
    if deltas:
        st.blocked.append(blocked)

    # the leak box sets the first tunnel flow: before the out_leak context
    leak = _safe(lambda: _leak_box(st, entries, up, totals.get("out_leak"), live),
                 "leak", checks,
                 lambda e: {"id": "leak", "title": f"out_leak: {e}", "type": "table",
                            "columns": list(LEAK_COLUMNS), "rows": [], "sev": "warn"})
    cs, ss_err = _safe(lambda: _conns(st, checks), "ss", checks, lambda e: ([], e))
    vpn_in = _safe(lambda: _in_vpn(st, entries, cs), "in_vpn", checks,
                   lambda e: ("warn", e))
    spark_sev = _new_checks(st, deltas, up, vpn_in, now, checks)
    table = _safe(lambda: _counter_panel(st, counters, deltas, now, live), "counters", checks,
                  lambda e: None)

    panels.append({"id": "hostfw", "title": "hostfw", "type": "kv", "items": fw_items,
                   "sev": worst(*(i["sev"] for i in fw_items))})
    panels.append({"id": "vpn", "title": "vpn", "type": "kv", "items": vpn_items,
                   "sev": worst(*(i["sev"] for i in vpn_items))})
    if table:
        panels.append(table)
    panels.append(leak)
    panels.append({"id": "blocked", "title": "blocked / tick", "type": "spark",
                   "values": list(st.blocked), "unit": "pkt", "sev": spark_sev})
    panels.append(_safe(lambda: _apps(st, entries, cs, live, wall), "programs", checks,
                        lambda e: {"id": "programs", "title": f"programs: {e}",
                                   "type": "table", "columns": list(APP_COLUMNS), "rows": [],
                                   "sev": "warn"}))
    panels.append(_safe(lambda: _peers(st, entries, cs, ss_err, live, wall), "peers", checks,
                        lambda e: {"id": "peers", "title": f"peers: {e}", "type": "table",
                                   "columns": list(PEER_COLUMNS), "rows": [], "sev": "warn"}))
    audit = _safe(lambda: _audit(st, entries, cs, live), "audit", checks,
                  lambda e: {"id": "audit", "title": f"audit: {e}", "type": "table",
                             "columns": list(AUDIT_COLUMNS), "rows": [], "sev": "warn"})
    audit["width"] = "full"                  # most columns: a row of its own, at the bottom
    panels.append(audit)

    checks = _merge(checks)
    status = worst(*(c["sev"] for c in checks))
    n_leak = totals.get("out_leak")
    summary = " | ".join([live, vpn_text, f"leak {n_leak if n_leak is not None else '?'}"])
    problems = [c["title"] for c in checks if c["sev"] in ("warn", "crit")]
    if problems:
        summary += " | " + ", ".join(problems[:3])
    return {"v": 2, "status": status, "summary": summary, "panels": panels, "events": events,
            "checks": checks}
