"""sectop ids summary: sectop-ids.service (step 11b1, 2026-11-27).

What: Suricata's alerts counted, every line of eve.json, no sampling and no limit inside
Suricata (NIST SP 800-53 AU-7 b: the reduction never alters the original records; SP
800-92 event aggregation: one entry per rule + source with its count). eve.json stays
as Suricata wrote it.

Counts per rule (sid) + source address, in clock-hour buckets: `n24` = the last 24 clock
hours, `nh` = this clock hour (since hh:00). At start: yesterday's file (eve.json.1, kept
uncompressed by logrotate delaycompress) and today's file from their start (max
START_BYTES each), so a restart keeps exact 24 h counts. Then followed live
(core/eve.py). Plus the newest TAIL alert lines and a count of the other event types.

DHCP answers (step 11b2a, for the lan box's rogue DHCP check): per interface + server
address, the same hour buckets, the message types; nothing about the client.

Who: system user sectop-ids, group sectop-feed (unit Group=), supplementary group
suricata (eve.json is 0640 suricata): read only (ProtectSystem=strict), never writes a
Suricata file, no capabilities, no network. The collector reads the summary through
sectop-feed and is no longer in group suricata (least privilege: NIST SP 800-53 AC-6).

Summary: /run/sectop-ids/summary.json, dir 0750 sectop-ids:sectop-feed, file 0640
(core/statefile.py). The collector validates every field (modules/ids).

systemd: /usr/bin/python3 -I -B /usr/local/lib/sectop/bin/sectop-ids
"""

import collections
import grp
import os
import pwd
import signal
import stat
import sys
import time

from core import eve as evemod
from core import statefile
from core.sanitize import display

RUN_DIR = "/run/sectop-ids"
FILE = "summary.json"
OWNER = "sectop-ids"             # the unit's User=
GROUP = "sectop-feed"            # unit Group=: helper -> collector only
VERSION = 1
INTERVAL = 2.0
ALIVE = 30.0                     # written at least this often (the collector: MAX_AGE)
HOURS = 24                       # clock hours counted
MAX_GROUPS = 200
TAIL = 50
MAX_DSTS = 5
START_BYTES = 64 << 20           # each file at start: from its start, at most this much
BUDGET = 4 << 20                 # per read
CRIT_KINDS = ("leak", "scan")    # kept first when MAX_GROUPS is reached
MAX_DHCP = 50                    # DHCP servers (interface + address) kept


class Quit(BaseException):
    pass


def hour(ts: float) -> int:
    return int(ts // 3600) * 3600


class Group:
    __slots__ = ("sid", "src", "a", "first", "last", "hours", "dsts")

    def __init__(self, a):
        self.sid, self.src = a.sid, a.src
        self.first = self.last = a.ts
        self.hours = {}
        self.dsts = collections.deque(maxlen=MAX_DSTS)    # distinct, newest first
        self.a = a

    def add(self, a, now: float) -> None:
        ts = min(a.ts, now)
        h = hour(ts)
        self.hours[h] = self.hours.get(h, 0) + 1
        self.first = min(self.first, ts)
        if ts >= self.last:
            self.last = ts
            self.a = a                  # the newest line's rule fields
        to = a.dst + (f":{a.dport}" if a.dport is not None else "")
        if to in self.dsts:
            self.dsts.remove(to)
        self.dsts.appendleft(to)


class DhcpGroup:
    """One DHCP server on one interface: its answers per clock hour."""
    __slots__ = ("iface", "server", "first", "last", "hours", "types")

    def __init__(self, x):
        self.iface, self.server = x.iface, x.server
        self.first = self.last = x.ts
        self.hours = {}
        self.types = set()

    def add(self, x, now: float) -> None:
        ts = min(x.ts, now)
        h = hour(ts)
        self.hours[h] = self.hours.get(h, 0) + 1
        self.first, self.last = min(self.first, ts), max(self.last, ts)
        if len(self.types) < 4:
            self.types.add(x.dtype)


class Counts:
    def __init__(self):
        self.groups = {}            # (sid, src) -> Group
        self.dhcp = {}              # (iface, server) -> DhcpGroup
        self.tail = collections.deque(maxlen=TAIL)
        self.other = collections.Counter()   # other event types (anomaly, dhcp ...)
        self.bad = 0                # lines that are not a JSON object
        self.dropped = 0            # groups pushed out by MAX_GROUPS

    def add(self, lines: list, now: float) -> None:
        for raw in lines:
            et, a = evemod.parse_line(raw, now)
            if et is None:
                self.bad += 1
                continue
            if a is None or isinstance(a, evemod.Dhcp):
                self.other[et] += 1
                if a is not None:
                    self.add_dhcp(a, now)
                continue
            key = (a.sid, a.src)
            g = self.groups.get(key)
            if g is None:
                g = self.groups[key] = Group(a)
            g.add(a, now)
            self.tail.appendleft(a)

    def add_dhcp(self, x, now: float) -> None:
        key = (x.iface, x.server)
        g = self.dhcp.get(key)
        if g is None:
            g = self.dhcp[key] = DhcpGroup(x)
        g.add(x, now)

    def prune(self, now: float) -> None:
        lo = hour(now) - (HOURS - 1) * 3600
        for key in list(self.dhcp):
            g = self.dhcp[key]
            for h in [h for h in g.hours if h < lo]:
                del g.hours[h]
            if not g.hours:
                del self.dhcp[key]
        if len(self.dhcp) > MAX_DHCP:       # the newest kept
            keep = sorted(self.dhcp.items(), key=lambda kv: kv[1].last, reverse=True)
            self.dhcp = dict(keep[:MAX_DHCP])
        for key in list(self.groups):
            g = self.groups[key]
            for h in [h for h in g.hours if h < lo]:
                del g.hours[h]
            if not g.hours:
                del self.groups[key]
        if len(self.groups) > MAX_GROUPS:
            keep = sorted(self.groups.items(), reverse=True, key=lambda kv: (
                kv[1].a.kind in CRIT_KINDS, -(kv[1].a.severity or 4), kv[1].last))
            self.dropped += len(keep) - MAX_GROUPS
            self.groups = dict(keep[:MAX_GROUPS])

    def doc(self, now: float, note: str, skipped: int, started: float) -> dict:
        h = hour(now)
        groups = []
        for g in sorted(self.groups.values(), key=lambda g: g.last, reverse=True):
            a = g.a
            groups.append({
                "sid": g.sid, "src": g.src, "sig": a.sig, "kind": a.kind,
                "severity": a.severity, "sigsev": a.sigsev, "category": a.category,
                "target": a.target, "confidence": a.confidence, "proto": a.proto,
                "app": a.app, "first": g.first, "last": g.last,
                "n24": sum(g.hours.values()), "nh": g.hours.get(h, 0), "dsts": list(g.dsts)})
        tail = [{"ts": min(a.ts, now), "sid": a.sid, "sig": a.sig, "kind": a.kind,
                 "severity": a.severity, "sigsev": a.sigsev, "category": a.category,
                 "src": a.src, "dst": a.dst, "dport": a.dport, "proto": a.proto}
                for a in self.tail]
        dhcp = [{"iface": g.iface, "server": g.server, "types": sorted(g.types),
                 "first": g.first, "last": g.last, "n24": sum(g.hours.values()),
                 "nh": g.hours.get(h, 0)}
                for g in sorted(self.dhcp.values(), key=lambda g: g.last, reverse=True)]
        return {"v": VERSION, "ts": now, "started": started, "note": note,
                "skipped": skipped + self.bad, "dropped": self.dropped,
                "other": dict(sorted(self.other.items())[:20]), "groups": groups, "tail": tail,
                "dhcp": dhcp}


def _log(msg: str) -> None:
    print(f"sectop-ids: {display(msg)}", file=sys.stderr, flush=True)


def catch_up(reader, counts: Counts, now) -> bool:
    """Read until the reader is at the end of its file. -> anything read."""
    got = False
    while True:
        lines = reader.read()
        if lines:
            counts.add(lines, now())
            got = True
        if reader.done:
            return got


def start(path: str, counts: Counts, now) -> evemod.Reader:
    """Yesterday's file, then today's from its start; -> today's reader (kept open)."""
    old = evemod.Reader(path + ".1", backlog=START_BYTES, budget=BUDGET)
    try:
        catch_up(old, counts, now)
    finally:
        old.close()
    cur = evemod.Reader(path, backlog=START_BYTES, budget=BUDGET)
    catch_up(cur, counts, now)
    return cur


def loop(path: str, out: str, write=statefile.write, wall=time.time, sleep=time.sleep,
         log=_log, stop=lambda: False) -> None:
    counts = Counts()
    started = wall()
    reader = start(path, counts, wall)
    written, last_doc, problem = 0.0, None, None
    try:
        while not stop():
            catch_up(reader, counts, wall)
            now = wall()
            counts.prune(now)
            d = counts.doc(now, reader.note, reader.skipped, started)
            same = last_doc is not None and {**d, "ts": 0} == {**last_doc, "ts": 0}
            if not same or now - written >= ALIVE:
                try:
                    write(out, d, 0o640)
                    written, last_doc, err = now, d, None
                except (OSError, statefile.StateError) as e:
                    err = f"{out}: {type(e).__name__}: {e}"
                if err != problem:
                    log(err or "writing again")
                    problem = err
            sleep(INTERVAL)
    finally:
        reader.close()


def prepare(path: str, uid: int, gid: int) -> None:
    """The runtime dir systemd made (RuntimeDirectory=, User= / Group=): mine, group
    sectop-feed, 0750. OSError / ValueError."""
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != uid:
        raise ValueError(f"{path}: not a directory owned by uid {uid}")
    if st.st_gid != gid:
        raise ValueError(f"{path}: group {st.st_gid}, not {GROUP} ({gid}): check Group=")
    os.chmod(path, 0o750, follow_symlinks=False)


def _term(signum, frame):
    raise Quit


def main(argv: list | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        print("usage: sectop-ids   (run by sectop-ids.service)", file=sys.stderr)
        return 2
    if os.geteuid() == 0:
        _log("refusing to run as root: runs as user sectop-ids (sectop-ids.service)")
        return 2
    try:
        me = pwd.getpwuid(os.getuid()).pw_name
        gid = grp.getgrnam(GROUP).gr_gid
    except KeyError as e:
        _log(f"no such user / group: {e}")
        return 2
    if me != OWNER or gid != os.getgid():
        _log(f"runs as {OWNER}:{GROUP} (User= / Group= of sectop-ids.service)")
        return 2
    try:
        prepare(RUN_DIR, os.getuid(), gid)
    except (OSError, ValueError) as e:
        _log(f"{RUN_DIR}: {e} (RuntimeDirectory=sectop-ids in the unit)")
        return 2
    signal.signal(signal.SIGTERM, _term)
    try:
        loop(evemod.EVE_PATH, os.path.join(RUN_DIR, FILE))
    except (KeyboardInterrupt, Quit):
        pass
    return 0
