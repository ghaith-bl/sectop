"""Suricata eve.json: follow the file, parse alert lines (step 11b1, 2026-11-27).

Used by the ids summary helper (core/idsd.py, sectop-ids.service), the only part of sectop
that opens eve.json. The collector reads the helper's summary, never eve.json
(modules/ids). Read only, from the file: no socket, no command.

File handling: kept open between reads (follows the file across a logrotate rename: the
old one is read to its end first, then the new one from its start; truncated: from the
start). The first open of a run can start at the last `backlog` bytes (a whole line
boundary). At most `budget` bytes per read; lines over LINE_MAX are skipped. Alert text
comes from rules (ET Open, local), never from a packet: the eve config has no payload /
app-layer metadata (hardening ids/suricata.yaml).
"""

import datetime
import errno
import ipaddress
import json
import os
import stat

EVE_PATH = "/var/log/suricata/harden-ids/eve.json"
LINE_MAX = 64 << 10

NOTE_MISSING = "no eve.json (Suricata not installed / not started)"
NOTE_DENIED = "eve.json not readable: sectop-ids not in group suricata (sudo ./install.sh)"


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


def _first(md: dict, key: str, limit: int = 40) -> str:
    v = md.get(key)
    return _str(v[0], limit) if isinstance(v, list) and v else ""


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


class Alert:
    __slots__ = ("ts", "sid", "sig", "kind", "src", "dst", "dport", "proto", "app",
                 "category", "severity", "sigsev", "target", "confidence")


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
    sigsev = md.get("signature_severity") if isinstance(md.get("signature_severity"), list) else []
    a = Alert()
    a.ts = parse_ts(ev.get("timestamp")) or now
    a.sid = sid
    a.sig = _str(al.get("signature")) or f"sid {sid}"
    a.kind = _first(md, "harden", 20)
    a.severity = _int(al.get("severity"))
    a.sigsev = [_str(s, 20) for s in sigsev if isinstance(s, str)][:3]
    a.src = _addr(ev.get("src_ip"))
    a.dst = _addr(ev.get("dest_ip"))
    a.dport = _int(ev.get("dest_port"))
    a.proto = _str(ev.get("proto"), 10)
    a.app = _str(ev.get("app_proto"), 20)
    a.category = _str(al.get("category"), 100)
    a.target = _first(md, "attack_target")
    a.confidence = _first(md, "confidence", 20)
    return et, a


class Reader:
    """eve.json followed across reads (see the module doc)."""

    def __init__(self, path=EVE_PATH, backlog: int | None = None, budget: int = 2 << 20):
        self.path, self.backlog, self.budget = path, backlog, budget
        self.f = None               # open file
        self.ident = None           # (st_dev, st_ino) of self.f
        self.buf = b""              # partial last line
        self.started = False        # first open done (backlog applies to it only)
        self.note = ""
        self.skipped = 0            # too long lines
        self.done = True            # the last read reached the end of the file

    def close(self) -> None:
        if self.f is not None:
            try:
                self.f.close()
            except OSError:
                pass
        self.f, self.ident, self.buf = None, None, b""

    def _open(self, backlog: int | None) -> None:
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            s = os.fstat(fd)
            if not stat.S_ISREG(s.st_mode):
                raise OSError(errno.EINVAL, "not a regular file")
            f = os.fdopen(fd, "rb", buffering=0)
        except BaseException:
            os.close(fd)
            raise
        self.f, self.ident, self.buf = f, (s.st_dev, s.st_ino), b""
        if backlog is not None and s.st_size > backlog:
            f.seek(s.st_size - backlog)
            self.buf = None             # drop up to the first newline (a cut line)

    def _lines(self, data: bytes) -> list:
        if self.buf is None:            # after a seek into the middle
            i = data.find(b"\n")
            if i < 0:
                return []
            data, self.buf = data[i + 1:], b""
        data = self.buf + data
        parts = data.split(b"\n")
        self.buf = parts.pop()
        if len(self.buf) > LINE_MAX:
            self.buf, self.skipped = None, self.skipped + 1     # rest of this long line: dropped
        out = []
        for p in parts:
            if len(p) > LINE_MAX:
                self.skipped += 1
            elif p.strip():
                out.append(p)
        return out

    def _drain(self, budget: int) -> tuple:
        """Lines of the open file up to budget bytes -> (lines, bytes read)."""
        data = self.f.read(budget) or b""
        return self._lines(data), len(data)

    def read(self) -> list:
        """New complete lines since the last call. Sets note and done."""
        out, budget = [], self.budget
        self.done = True
        try:
            s = os.stat(self.path)
            ident = (s.st_dev, s.st_ino)
        except FileNotFoundError:
            s = ident = None
        except PermissionError:
            self.close()
            self.note = NOTE_DENIED
            return out
        if self.f is not None and ident != self.ident:
            lines, n = self._drain(budget)      # rotated / removed: the old file to its end
            out += lines
            budget -= n
            if n < self.budget:
                self.close()
            else:
                self.done = False
        if self.f is not None and ident == self.ident and s.st_size < self.f.tell():
            self.close()                        # truncated: from the start again
        if ident is None:
            self.note = "" if self.f is not None else NOTE_MISSING
            if self.f is None:
                self.started = True
            return out
        if self.f is None:
            try:
                self._open(self.backlog if not self.started else None)
            except PermissionError:
                self.note = NOTE_DENIED
                return out
            except OSError as e:
                self.note = f"eve.json: {e.strerror or e}"
                return out
            self.started = True
        self.note = ""
        if budget > 0:
            lines, n = self._drain(budget)
            out += lines
            if n == budget:
                self.done = False
        else:
            self.done = False
        return out
