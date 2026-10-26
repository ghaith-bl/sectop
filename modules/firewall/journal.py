"""Parse hostfw kernel log lines from journald JSON. Pure functions.

Live: entries (dicts) from core's journal follower (core/journal.py), every
kernel entry; HFW lines are picked here. Boot scan at start: text of a
one-shot `journalctl -o json --grep=...` (parse()).
"""

import ipaddress
import json
import re
from dataclasses import dataclass

# HFW-<DIR>-<NAME>: NAME may have dashes (HFW-FWD-VM-LAN, HFW-OUT-LAN-ALLOW)
CODE_RE = re.compile(r"(HFW-[A-Z0-9]+(?:-[A-Z0-9_]+)+):\s?(.*)", re.S)

@dataclass(frozen=True)
class Entry:
    ts: float          # epoch seconds
    code: str          # HFW-OUT-LEAK
    kind: str          # out_leak (= hostfw counter name)
    fields: dict       # KEY=VALUE pairs, first occurrence wins
    flags: tuple       # words without '=' (SYN, ACK, ...)
    cursor: str = ""   # journal cursor of this entry

    @property
    def dir(self) -> str:
        """out, in or fwd (from HFW-<DIR>-...)."""
        return self.code.split("-")[1].lower()


def _message(v) -> str | None:
    """journald JSON: str, or a byte array for non-UTF-8 / non-printable data."""
    if isinstance(v, str):
        return v
    if isinstance(v, list) and all(isinstance(b, int) and 0 <= b <= 255 for b in v):
        return bytes(v).decode("utf-8", errors="replace")
    return None                         # null = field too large, or bad type


def parse_fields(rest: str) -> tuple:
    fields, flags = {}, []
    for word in rest.split():
        k, sep, v = word.partition("=")
        if sep:
            fields.setdefault(k, v)
        else:
            flags.append(word)
    return fields, tuple(flags)


def _entry(e) -> tuple:
    """One journald JSON object -> (cursor, Entry or None for a non-HFW line).
    Not a journal entry -> ValueError, KeyError or TypeError."""
    cur = e["__CURSOR"]
    ts = int(e["__REALTIME_TIMESTAMP"]) / 1e6
    if not isinstance(cur, str):
        raise TypeError("__CURSOR: str required")
    msg = _message(e.get("MESSAGE"))
    m = CODE_RE.match(msg) if msg is not None else None
    if m is None:
        return cur, None
    code = m.group(1)
    fields, flags = parse_fields(m.group(2))
    kind = code[4:].lower().replace("-", "_")
    return cur, Entry(ts, code, kind, fields, flags, cur)


def entries(objs) -> tuple:
    """Follower entries (dicts, journal order) -> (HFW entries, bad entries)."""
    out, bad = [], 0
    for e in objs:
        try:
            _cur, ent = _entry(e)
        except (ValueError, KeyError, TypeError):
            bad += 1
            continue
        if ent is not None:
            out.append(ent)
    return out, bad


def parse(text: str) -> tuple:
    """Text of `journalctl -o json` -> (entries, cursor, bad).

    entries: HFW lines only, in journal order.
    cursor: of the last complete entry (any kernel line), None if none.
    bad: complete lines that were not valid JSON entries.
    A last line without newline is ignored (cut by a timeout / size limit).
    """
    lines = text.split("\n")
    if not text.endswith("\n"):
        lines = lines[:-1]
    out, cursor, bad = [], None, 0
    for line in lines:
        if not line.strip():
            continue
        try:
            cur, ent = _entry(json.loads(line))
        except (ValueError, KeyError, TypeError):
            bad += 1
            continue
        cursor = cur
        if ent is not None:
            out.append(ent)
    return out, cursor, bad


def _addr(a: str) -> str:
    try:
        return str(ipaddress.ip_address(a))      # compress kernel's full v6 form
    except ValueError:
        return a


def _hostport(addr: str, port: str | None) -> str:
    a = _addr(addr)
    if not port:
        return a
    return f"[{a}]:{port}" if ":" in a else f"{a}:{port}"


def src(e: Entry) -> str:
    return _hostport(e.fields.get("SRC", "?"), e.fields.get("SPT"))


def dst(e: Entry) -> str:
    return _hostport(e.fields.get("DST", "?"), e.fields.get("DPT"))


def flow(e: Entry) -> tuple:
    """-> (src, dst, varying side, varying port) for grouping repeats.

    The larger port of a flow is the ephemeral one (new on every connect,
    out: src port, inbound to a service: src port, late reply from :443:
    dst port), so src / dst leave it out. Equal ports or no ports: both kept.
    """
    f = e.fields
    s, d, sp, dp = f.get("SRC", "?"), f.get("DST", "?"), f.get("SPT"), f.get("DPT")
    if sp and dp and sp.isdigit() and dp.isdigit() and int(sp) != int(dp):
        if int(sp) > int(dp):
            return _hostport(s, None), _hostport(d, dp), "src", sp
        return _hostport(s, sp), _hostport(d, None), "dst", dp
    return _hostport(s, sp), _hostport(d, dp), "", ""


def summary(e: Entry) -> str:
    """One line: uid 1000 tcp 192.168.8.102:46866 -> 1.2.3.4:443 wlo1"""
    f = e.fields
    parts = []
    if f.get("UID"):
        parts.append(f"uid {f['UID']}")
    if f.get("PROTO"):
        parts.append(f["PROTO"].lower())
    if f.get("SRC") or f.get("DST"):
        parts.append(f"{src(e)} -> {dst(e)}")
    iface = f.get("OUT") or f.get("IN")
    if iface:
        parts.append(iface)
    if f.get("TYPE"):
        parts.append(f"type {f['TYPE']}")
    return " ".join(parts) or e.code
