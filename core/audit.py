"""Audit events from journald entries (_TRANSPORT=audit). Pure functions.

Facts (fixtures 2026-10-20 from my host, kernel/auditsc.c, linux-audit
audit-documentation field dictionary):
- One journal entry per record. Event = the entries with the same _AUDIT_ID (per boot).
  No EOE in the journal: a syscall event is complete at its PROCTITLE (always last,
  493 entries of the sudo fixture). Records before SYSCALL may belong to it (BPF, AVC).
- User space records (types 1100-1199, 2100-2999; USER_CMD = AUDIT1123) are events of
  one record. Their own fields are in msg='...'.
- MESSAGE = "<TYPE or AUDITnnnn> k=v k=v ...".
- Encoded fields (dictionary format "encoded": acct cmd comm cwd exe key name path
  proctitle ...): "quoted", or hex when the value has a space, a quote, a control
  char or a byte > 0x7e; (null) = none. key: several keys joined by 0x01 (hex).
- EXECVE: argc=N, then a<n>= per argument, or a long one as a<n>_len=L and chunks
  a<n>[i]=, which may go on in the next EXECVE record. Encoding is decided once per
  argument. SYSCALL a0..a3 are plain hex numbers, not encoded.
"""

import re
from dataclasses import dataclass, field

USER_TYPES = (range(1100, 1200), range(2100, 3000))
PROCTITLE = 1327
EOE = 1320
ENCODED = {"a", "acct", "addr", "cmd", "comm", "cwd", "data", "dir", "exe", "file",
           "grp", "key", "name", "ocomm", "path", "proctitle", "saddr", "watch"}
MAX_PENDING = 1000       # open events kept; the oldest is given out as it is
TIMEOUT = 2.0            # an event without PROCTITLE is given out this long after its last record

TOKEN_RE = re.compile(r"""([A-Za-z0-9_\-\[\]]+)=("[^"]*"|'[^']*'|\S*)""")
HEX_RE = re.compile(r"(?:[0-9A-F]{2})+")
ARG_RE = re.compile(r"a(\d+)(?:\[(\d+)\]|(_len))?")


def is_user(t: int) -> bool:
    return any(t in r for r in USER_TYPES)


def _raw_bytes(raw: str) -> bytes | None:
    if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
        return raw[1:-1].encode("utf-8", errors="replace")
    if HEX_RE.fullmatch(raw):
        return bytes.fromhex(raw)
    return None


def decode(raw: str | None, encoded: bool = True) -> str | None:
    """Value of a field as text. Encoded field: quoted or hex; (null) -> None.
    Not encoded: quotes taken off, else as it is."""
    if raw is None or raw == "(null)":
        return None
    if encoded:
        b = _raw_bytes(raw)
        if b is not None:
            return b.decode("utf-8", errors="replace")
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
        return raw[1:-1]
    return raw


def fields(message: str) -> dict:
    """Raw k=v of a record MESSAGE (type word left out). msg='...' of a user space
    record is opened: its fields join the others (they win on a clash)."""
    out, inner = {}, None
    for k, v in TOKEN_RE.findall(message or ""):
        if k == "msg" and v.startswith("'") and v.endswith("'") and len(v) >= 2:
            inner = v[1:-1]
            continue
        out.setdefault(k, v)
    if inner is not None:
        for k, v in TOKEN_RE.findall(inner):
            out[k] = v
    return out


def _encoded(name: str) -> bool:
    """EXECVE a<n> are encoded too, but only argv() reads them (SYSCALL a0..a3 are
    plain hex numbers: a3=21 must stay 21)."""
    return name in ENCODED


def text(raw_fields: dict, name: str) -> str | None:
    """Decoded value of one field (encoded fields per the dictionary)."""
    return decode(raw_fields.get(name), _encoded(name))


def keys(raw_fields: dict) -> tuple:
    """Rule keys of a SYSCALL record: none, one, or several (joined by 0x01)."""
    k = text(raw_fields, "key")
    return tuple(x for x in k.split("\x01") if x) if k else ()


def argv(execve_records: list) -> list:
    """argv from the EXECVE records of one event (in order). Long arguments come in
    chunks (a<n>[i]=), also over more than one record; each chunk quoted or hex."""
    args, chunks, argc = {}, {}, None
    for rec in execve_records:
        for k, v in TOKEN_RE.findall(rec.message):
            if k == "argc" and argc is None and v.isdigit():
                argc = int(v)
                continue
            m = ARG_RE.fullmatch(k)
            if m is None or m.group(3):          # not an argument, or a<n>_len
                continue
            n = int(m.group(1))
            b = _raw_bytes(v)
            if b is None:
                b = v.encode("utf-8", errors="replace")
            if m.group(2) is None:
                args[n] = b
            else:
                chunks.setdefault(n, {})[int(m.group(2))] = b
    for n, parts in chunks.items():
        args[n] = b"".join(parts[i] for i in sorted(parts))
    top = argc if argc is not None else (max(args) + 1 if args else 0)
    return [args.get(i, b"").decode("utf-8", errors="replace") for i in range(top)]


def proctitle(raw: str | None) -> str | None:
    """PROCTITLE: argv joined by NUL (the kernel cuts it at 128 bytes)."""
    v = decode(raw)
    return v.replace("\x00", " ").strip() if v is not None else None


@dataclass
class Record:
    type: int            # _AUDIT_TYPE
    name: str            # _AUDIT_TYPE_NAME (SYSCALL, EXECVE, AUDIT1123, ...)
    message: str
    ts: float            # __REALTIME_TIMESTAMP, seconds
    raw: dict            # fields(message)


@dataclass
class Event:
    id: str              # _AUDIT_ID
    boot: str            # _BOOT_ID ("" when the entry has none)
    records: list = field(default_factory=list)
    seen: float = 0.0    # time of the last record

    @property
    def ts(self) -> float:
        return self.records[0].ts if self.records else 0.0

    def first(self, name: str) -> Record | None:
        return next((r for r in self.records if r.name == name), None)

    def all(self, name: str) -> list:
        return [r for r in self.records if r.name == name]

    @property
    def kind(self) -> str:
        """SYSCALL for a syscall event, else the name of its first record."""
        return "SYSCALL" if self.first("SYSCALL") else (self.records[0].name
                                                        if self.records else "")

    @property
    def main(self) -> dict:
        """Fields of the record that says who: SYSCALL, else the first record."""
        r = self.first("SYSCALL") or (self.records[0] if self.records else None)
        return r.raw if r else {}

    def get(self, name: str) -> str | None:
        return text(self.main, name)

    @property
    def keys(self) -> tuple:
        return keys(self.main)

    @property
    def argv(self) -> list:
        return argv(self.all("EXECVE"))

    @property
    def cwd(self) -> str | None:
        r = self.first("CWD")
        return text(r.raw, "cwd") if r else self.get("cwd")

    @property
    def proctitle(self) -> str | None:
        r = self.first("PROCTITLE")
        return proctitle(r.raw.get("proctitle")) if r else None

    def complete(self) -> bool:
        if not self.records:
            return False
        last = self.records[-1].type
        return last in (PROCTITLE, EOE) or (len(self.records) == 1 and is_user(last))


def record(entry: dict) -> Record | None:
    """journald entry -> Record, None if it is not an audit record."""
    t = entry.get("_AUDIT_TYPE")
    msg = entry.get("MESSAGE")
    ts = entry.get("__REALTIME_TIMESTAMP")
    if not isinstance(t, str) or not t.isdigit() or not isinstance(msg, str):
        return None
    name = entry.get("_AUDIT_TYPE_NAME")
    if not isinstance(name, str) or not name:
        name = msg.split(" ", 1)[0]
    try:
        sec = int(ts) / 1e6
    except (TypeError, ValueError):
        sec = 0.0
    return Record(int(t), name, msg, sec, fields(msg))


class Assembler:
    """Records in journal order -> complete events. Pure: the caller gives the time."""

    def __init__(self, timeout: float = TIMEOUT, limit: int = MAX_PENDING):
        self.timeout, self.limit = timeout, limit
        self.open = {}               # (boot, id) -> Event, oldest first
        self.bad = 0                 # audit entries without _AUDIT_ID / type / message

    def feed(self, entries, now: float) -> list:
        """-> events completed by these entries, then the ones that timed out."""
        done = []
        for e in entries:
            if e.get("_TRANSPORT") != "audit":
                continue
            aid = e.get("_AUDIT_ID")
            rec = record(e)
            if rec is None or not isinstance(aid, str) or not aid:
                self.bad += 1
                continue
            key = (e.get("_BOOT_ID") or "", aid)
            ev = self.open.pop(key, None) or Event(aid, key[0])
            ev.records.append(rec)
            ev.seen = now
            if ev.complete():
                done.append(ev)
            else:
                self.open[key] = ev            # re-inserted: newest last
                if len(self.open) > self.limit:
                    done.append(self.open.pop(next(iter(self.open))))
        return done + self.flush(now)

    def flush(self, now: float, all_: bool = False) -> list:
        """Events with no record for `timeout` seconds (no PROCTITLE ever: BPF without a
        syscall, kernel config records), or all of them."""
        out = []
        for key in list(self.open):
            if all_ or now - self.open[key].seen >= self.timeout:
                out.append(self.open.pop(key))
        return out
