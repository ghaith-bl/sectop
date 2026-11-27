"""ids: Suricata alerts on screen 1 (firewall). docs/modules/ids.md

Source: Suricata's eve.json (silverblue-privacy-hardening section ids:
/var/log/suricata/harden-ids/eve.json, suricata:suricata 0640). The collector reads it
through group suricata (install.sh adds a drop-in only when that group exists); no root,
no capture rights. Read only, from the file: no socket, no command.

Boxes:
- ids: alerts of the last 24 h grouped by rule (sid) + source address, worst first, then
  newest. Severity: the hardening's own rules (metadata `harden <kind>`): leak, scan = crit
  (the alert bar, red), the other kinds (probe, vm_lan, vm_probe) = warn. ET Open rules:
  rule severity 1 or signature_severity Critical = crit, 2 or Major = warn, else info.
- eve: the newest alert lines (live tail), newest first.

Checks: one event check per group with new lines (crit / warn; info: row only), `at` = the
newest line, so a backlog read at start or after a collector restart opens nothing old
(core/alerts.py: older than its hold = record only).

File handling: kept open between collects (follows the file across a logrotate rename:
the old one is read to its end first, then the new one from its start). At start only
the last START_BYTES are read (a whole line boundary). At most READ_MAX per collect, lines
over LINE_MAX are skipped. Alert text comes from rules (ET Open, local), never from a
packet: the eve config has no payload / app-layer metadata (hardening ids/suricata.yaml).
"""

import collections
import datetime
import errno
import ipaddress
import json
import os
import stat
import time

NAME = "ids"
INTERVAL = 2.0
EVE_PATH = "/var/log/suricata/harden-ids/eve.json"
START_BYTES = 4 << 20           # backlog read at start
READ_MAX = 2 << 20              # per collect
LINE_MAX = 64 << 10
KEEP = 86400.0                  # groups not seen for this long go
MAX_GROUPS = 200
TAIL = 50
MAX_DSTS = 5
MAX_CHECKS = 50
CRIT_KINDS = ("leak", "scan")
LOCAL_SIDS = range(9200000, 9300000)      # hardening ids/local.rules
COLUMNS = ["last", "n", "kind", "signature", "from", "to"]
TYPES = ["age", "num", "text", "text", "text", "text"]
TAIL_COLUMNS = ["time", "kind", "signature", "from", "to"]
TAIL_TYPES = ["age", "text", "text", "text", "text"]
RANK = {"crit": 3, "warn": 2, "info": 1, "ok": 0}

NOTE_MISSING = "no eve.json (Suricata not installed / not started)"
NOTE_DENIED = "eve.json not readable: collector not in group suricata (sudo ./install.sh)"


def _str(v, limit=200) -> str:
    return v[:limit] if isinstance(v, str) else ""


def _int(v) -> int | None:
    return v if type(v) is int else None


def _addr(v) -> str:
    """A valid address as text, else ''."""
    try:
        return str(ipaddress.ip_address(v)) if isinstance(v, str) else ""
    except ValueError:
        return ""


def parse_ts(v) -> float | None:
    """eve timestamp (2026-01-01T03:00:00.180000+0300) -> epoch seconds."""
    if not isinstance(v, str):
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.datetime.strptime(v, fmt).timestamp()
        except ValueError:
            pass
    return None


def rate(kind: str, severity: int | None, sigsev: list) -> str:
    """Severity of an alert line: the hardening's kind first, else the ET rule's."""
    if kind:
        return "crit" if kind in CRIT_KINDS else "warn"
    if severity == 1 or "Critical" in sigsev:
        return "crit"
    if severity == 2 or "Major" in sigsev:
        return "warn"
    return "info"


class Alert:
    __slots__ = ("ts", "sid", "sig", "sev", "kind", "src", "dst", "dport", "proto", "app",
                 "category", "severity", "sigsev")


def parse_line(raw: bytes, now: float):
    """One eve line -> (event_type, Alert or None). Not json / not a dict -> (None, None)."""
    try:
        ev = json.loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None, None
    if not isinstance(ev, dict):
        return None, None
    et = _str(ev.get("event_type"), 40) or "?"
    if et != "alert":
        return et, None
    al = ev.get("alert")
    if not isinstance(al, dict):
        return et, None
    sid = _int(al.get("signature_id"))
    if sid is None:
        return et, None
    md = al.get("metadata") if isinstance(al.get("metadata"), dict) else {}
    kinds = md.get("harden") if isinstance(md.get("harden"), list) else []
    sigsev = md.get("signature_severity") if isinstance(md.get("signature_severity"), list) else []
    a = Alert()
    a.ts = parse_ts(ev.get("timestamp")) or now
    a.sid = sid
    a.sig = _str(al.get("signature")) or f"sid {sid}"
    a.kind = _str(kinds[0], 20) if kinds else ""
    a.severity = _int(al.get("severity"))
    a.sigsev = [s for s in sigsev if isinstance(s, str)][:3]
    a.sev = rate(a.kind, a.severity, a.sigsev)
    a.src = _addr(ev.get("src_ip"))
    a.dst = _addr(ev.get("dest_ip"))
    a.dport = _int(ev.get("dest_port"))
    a.proto = _str(ev.get("proto"), 10)
    a.app = _str(ev.get("app_proto"), 20)
    a.category = _str(al.get("category"), 100)
    return et, a


class Group:
    def __init__(self, a: Alert):
        self.sid, self.src = a.sid, a.src
        self.first = self.last = a.ts
        self.n = self.reported = 0
        self.dsts = collections.deque(maxlen=MAX_DSTS)    # distinct, newest first
        self.add(a)

    def add(self, a: Alert) -> None:
        self.n += 1
        self.first = min(self.first, a.ts)
        if a.ts >= self.last:
            self.last = a.ts
        self.sig, self.sev, self.kind = a.sig, a.sev, a.kind
        self.severity, self.sigsev, self.category = a.severity, a.sigsev, a.category
        self.proto, self.app = a.proto, a.app
        to = a.dst + (f":{a.dport}" if a.dport is not None else "")
        if to in self.dsts:
            self.dsts.remove(to)
        self.dsts.appendleft(to)


class State:
    def __init__(self, path=EVE_PATH, wall=time.time,
                 stamp=lambda ts: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))):
        self.path, self.wall, self.stamp = path, wall, stamp
        self.f = None               # open file
        self.ident = None           # (st_dev, st_ino) of self.f
        self.buf = b""              # partial last line
        self.started = False        # first open done (backlog = last START_BYTES only)
        self.note = ""
        self.groups = {}            # (sid, src) -> Group
        self.tail = collections.deque(maxlen=TAIL)
        self.other = collections.Counter()   # other event types (anomaly, dhcp ...)
        self.skipped = 0            # bad / too long lines

    def close(self) -> None:
        if self.f is not None:
            try:
                self.f.close()
            except OSError:
                pass
        self.f, self.ident, self.buf = None, None, b""


def init(cfg: dict) -> State:
    cfg = dict(cfg)
    path = cfg.pop("path", EVE_PATH)
    if cfg:
        raise ValueError(f"unknown option(s): {', '.join(sorted(cfg))}")
    if not isinstance(path, str) or not os.path.isabs(path):
        raise ValueError("path: absolute path required")
    return State(path=path)


def close(st: State) -> None:
    st.close()


def _open(st: State, backlog: bool) -> None:
    fd = os.open(st.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        f = os.fdopen(fd, "rb", buffering=0)
    except BaseException:
        os.close(fd)
        raise
    st.f, st.ident, st.buf = f, (s.st_dev, s.st_ino), b""
    if backlog and s.st_size > START_BYTES:
        f.seek(s.st_size - START_BYTES)
        st.buf = None               # drop up to the first newline (a cut line)


def _lines(st: State, data: bytes) -> list:
    if st.buf is None:              # after a seek into the middle
        i = data.find(b"\n")
        if i < 0:
            return []
        data, st.buf = data[i + 1:], b""
    data = st.buf + data
    parts = data.split(b"\n")
    st.buf = parts.pop()
    if len(st.buf) > LINE_MAX:
        st.buf, st.skipped = None, st.skipped + 1     # rest of this long line: dropped
    out = []
    for p in parts:
        if len(p) > LINE_MAX:
            st.skipped += 1
        elif p.strip():
            out.append(p)
    return out


def _drain(st: State, budget: int) -> tuple:
    """Lines of the open file up to budget bytes -> (lines, bytes read)."""
    data = st.f.read(budget) or b""
    return _lines(st, data), len(data)


def read(st: State) -> list:
    """New complete lines of eve.json since the last call. Sets st.note."""
    out, budget = [], READ_MAX
    try:
        s = os.stat(st.path)
        ident = (s.st_dev, s.st_ino)
    except FileNotFoundError:
        s = ident = None
    except PermissionError:
        st.close()
        st.note = NOTE_DENIED
        return out
    if st.f is not None and ident != st.ident:
        lines, n = _drain(st, budget)          # rotated / removed: the old file to its end
        out += lines
        budget -= n
        if n < READ_MAX:
            st.close()
    if st.f is not None and ident == st.ident and s.st_size < st.f.tell():
        st.close()                              # truncated: from the start again
    if ident is None:
        st.note = "" if st.f is not None else NOTE_MISSING
        if st.f is None:
            st.started = True
        return out
    if st.f is None:
        try:
            _open(st, backlog=not st.started)
        except PermissionError:
            st.note = NOTE_DENIED
            return out
        except OSError as e:
            st.note = f"eve.json: {e.strerror or e}"
            return out
        st.started = True
    st.note = ""
    if budget > 0:
        lines, _ = _drain(st, budget)
        out += lines
    return out


def follow(st: State, lines: list, now: float) -> None:
    for raw in lines:
        et, a = parse_line(raw, now)
        if et is None:
            st.skipped += 1
            continue
        if a is None:
            st.other[et] += 1
            continue
        key = (a.sid, a.src)
        g = st.groups.get(key)
        if g is None:
            st.groups[key] = Group(a)
        else:
            g.add(a)
        st.tail.appendleft(a)
    old = now - KEEP
    for key in [k for k, g in st.groups.items() if g.last < old]:
        del st.groups[key]
    if len(st.groups) > MAX_GROUPS:
        keep = sorted(st.groups.items(), key=lambda kv: (RANK[kv[1].sev], kv[1].last),
                      reverse=True)[:MAX_GROUPS]
        st.groups = dict(keep)


def _source(sid: int) -> str:
    return "local rule (hardening ids/local.rules)" if sid in LOCAL_SIDS else "ET Open"


def _row(st: State, g: Group) -> dict:
    to = g.dsts[0] if g.dsts else "-"
    if len(g.dsts) > 1:
        to += f" +{len(g.dsts) - 1}"
    detail = [("signature", g.sig), ("sid", str(g.sid)), ("rule", _source(g.sid))]
    if g.kind:
        detail.append(("kind", g.kind))
    if g.severity is not None:
        detail.append(("severity", str(g.severity) + (f" ({', '.join(g.sigsev)})" if g.sigsev else "")))
    if g.category:
        detail.append(("category", g.category))
    detail += [("from", g.src or "-"), ("to", ", ".join(g.dsts) or "-"),
               ("proto", g.proto + (f" / {g.app}" if g.app and g.app != "failed" else "") or "-"),
               ("count", str(g.n)), ("first", st.stamp(g.first)), ("last", st.stamp(g.last))]
    row = {"cells": [f"{g.last:.3f}", str(g.n), g.kind or "et", g.sig, g.src or "-", to],
           "sev": g.sev, "id": f"{g.sid}:{g.src}",
           "detail": [{"k": k, "v": v} for k, v in detail]}
    if g.src:
        row["ip"] = g.src
        row["filter"] = g.src
    return row


def _tail_row(a: Alert) -> dict:
    to = a.dst + (f":{a.dport}" if a.dport is not None else "")
    row = {"cells": [f"{a.ts:.3f}", a.kind or "et", a.sig, a.src or "-", to or "-"],
           "sev": a.sev, "detail": [{"k": "sid", "v": str(a.sid)},
                                    {"k": "proto", "v": a.proto or "-"}]}
    if a.src:
        row["ip"] = a.src
    return row


def _check(g: Group) -> dict:
    to = g.dsts[0] if g.dsts else "-"
    return {"key": f"ids:{g.sid}:{g.src or 'none'}", "sev": g.sev,
            "title": f"IDS {g.sig} from {g.src or '?'}"[:160],
            "detail": f"sid {g.sid} ({_source(g.sid)}), to {to}, {g.n} in 24 h"[:300],
            "n": g.n - g.reported, "at": g.last}


def collect(st: State, ctx) -> dict:
    now = st.wall()
    follow(st, read(st), now)
    groups = sorted(st.groups.values(), key=lambda g: (RANK[g.sev], g.last), reverse=True)
    checks = []
    for g in groups:
        if g.n > g.reported and g.sev in ("crit", "warn") and len(checks) < MAX_CHECKS:
            checks.append(_check(g))
        g.reported = g.n
    count = collections.Counter()
    for g in groups:
        count[g.sev] += g.n
    total = sum(count.values())
    title = f"ids  {total} alert(s) / 24 h, {len(groups)} group(s)"
    if st.note:
        title += f"  ({st.note})"
    panels = [
        {"id": "ids", "title": title, "type": "table", "columns": list(COLUMNS),
         "types": list(TYPES), "rows": [_row(st, g) for g in groups[:200]], "width": "full"},
        {"id": "eve", "title": f"eve  newest {len(st.tail)} alert line(s)", "type": "table",
         "columns": list(TAIL_COLUMNS), "types": list(TAIL_TYPES),
         "rows": [_tail_row(a) for a in st.tail]},
    ]
    if st.note:
        summary = st.note
    else:
        summary = f"24 h: crit {count['crit']} | warn {count['warn']} | info {count['info']}"
        if st.other:
            summary += " | " + ", ".join(f"{k} {v}" for k, v in sorted(st.other.items()))
    if st.note == NOTE_DENIED:
        checks.append({"key": "ids:no_access", "sev": "warn", "title": "IDS alerts not readable",
                       "detail": NOTE_DENIED})
    status = "warn" if st.note == NOTE_DENIED else ("info" if st.note else "ok")
    return {"v": 2, "status": status, "summary": summary, "panels": panels, "events": [],
            "checks": checks}
