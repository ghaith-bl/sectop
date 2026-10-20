"""journalctl -o json from my host -> test fixtures. Dev tool, stdlib only.
Stays in the repo (install.sh drops tests/). Run as my login user.

    F=$(python3 -I tests/journal_fixture.py --fields)
    journalctl -o json --output-fields="$F" ... \
      | python3 -I tests/journal_fixture.py OUTDIR [--name NAME] [--drop-key KEY]...

- Sections: an entry with SYSLOG_IDENTIFIER=sectop-fix (`logger -t sectop-fix NAME`)
  starts section NAME -> OUTDIR/NAME.json. Entries before the first marker are
  dropped. --name NAME: no markers, all entries -> OUTDIR/NAME.json.
- Per entry: fields not in FIELDS dropped (machine id, boot id, host name ...),
  cursor renumbered, HFW-* kernel lines dropped (firewall fixtures exist).
- Masked in every value, also inside audit hex (proctitle, argv): public IPs ->
  documentation ranges (same address, same mask), MACs, login name, real name,
  host name, machine id, boot id, USB serial numbers.
- --drop-key KEY: audit events (same _AUDIT_ID) whose SYSCALL key is KEY are left
  out (volume). Still counted in the report.
- Report on stderr: per section entries, span, audit events by key (before drop),
  masks. Output: one JSON object per line, ASCII only. Never overwrites a file.
"""

import argparse
import collections
import ipaddress
import json
import os
import pwd
import re
import sys

MARKER = "sectop-fix"
NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")
SYSCALL = "1300"                     # _AUDIT_TYPE of SYSCALL records

FIELDS = (
    "__CURSOR", "__REALTIME_TIMESTAMP", "_SOURCE_REALTIME_TIMESTAMP",
    "_TRANSPORT", "PRIORITY", "SYSLOG_FACILITY", "SYSLOG_IDENTIFIER", "MESSAGE_ID",
    "_AUDIT_ID", "_AUDIT_TYPE", "_AUDIT_TYPE_NAME", "_AUDIT_LOGINUID", "_AUDIT_SESSION",
    "_PID", "_UID", "_GID", "_COMM", "_EXE", "_CMDLINE", "_SELINUX_CONTEXT",
    "_SYSTEMD_UNIT", "_SYSTEMD_USER_UNIT", "_SYSTEMD_CGROUP",
    "_KERNEL_SUBSYSTEM", "_KERNEL_DEVICE", "SESSION_ID", "USER_ID", "LEADER",
    "MESSAGE",
)

GENERIC_HOSTS = {"", "localhost", "localhost-live", "fedora"}
DOC4 = tuple(f"{net}.{i}" for net in ("203.0.113", "198.51.100", "192.0.2")
             for i in range(1, 255))

IP4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")
COLON_RE = re.compile(r"(?<![\w:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f.]*){2,}(?![\w:])")
HEX_RE = re.compile(r"(?<==)(?:[0-9A-F]{2}){2,}(?![0-9A-Za-z])")
SERIAL_RE = re.compile(r"(?<=SerialNumber: )\S+")
KEY_RE = re.compile(r'\bkey=(?:"([^"]*)"|\(null\)|((?:[0-9A-F]{2})+))')
KEEP_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}


class FixtureError(Exception):
    pass


class Masker:
    """Same input, same mask, within one run. Counts what it changed."""

    def __init__(self, names: dict):
        self.n = collections.Counter()
        self.ips, self.macs = {}, {}
        self.names = [(re.compile(rf"(?<![A-Za-z0-9_]){re.escape(k)}(?![A-Za-z0-9_])"), v)
                      for k, v in sorted(names.items(), key=lambda kv: -len(kv[0])) if k]

    def value(self, v):
        """str, byte array (list of ints) or list of values; other types as is."""
        if isinstance(v, str):
            return self.text(v)
        if isinstance(v, list):
            if all(isinstance(b, int) and 0 <= b <= 255 for b in v):
                return list(self.text(bytes(v).decode("latin-1")).encode("latin-1"))
            return [self.value(x) for x in v]
        return v

    def text(self, s: str) -> str:
        return self._plain(HEX_RE.sub(self._hex, s))

    def _plain(self, s: str) -> str:
        s = COLON_RE.sub(self._colon, s)
        s = IP4_RE.sub(self._ip4, s)
        s = SERIAL_RE.sub(lambda m: self._hit("serial", "SERIAL"), s)
        for rx, rep in self.names:
            s = rx.sub(lambda m, rep=rep: self._hit("name", rep), s)
        return s

    def _hit(self, kind: str, rep: str) -> str:
        self.n[kind] += 1
        return rep

    def _hex(self, m) -> str:
        raw = bytes.fromhex(m.group(0))
        if any((b < 0x20 and b not in (0, 9, 10)) or b == 0x7F for b in raw):
            return m.group(0)
        t = raw.decode("latin-1")
        new = self._plain(t)
        return m.group(0) if new == t else new.encode("latin-1").hex().upper()

    def _ip(self, a, tok: str) -> str:
        if not a.is_global or a.is_multicast:
            return tok
        key = str(a)
        if key not in self.ips:
            n = sum(1 for k in self.ips if (":" in k) == (a.version == 6))
            if a.version == 4:
                if n >= len(DOC4):
                    raise FixtureError("more than 762 public IPv4 addresses")
                self.ips[key] = DOC4[n]
            else:
                self.ips[key] = f"2001:db8::{n + 1:x}"
        self.n[f"ip{a.version}"] += 1
        return self.ips[key]

    def _ip4(self, m) -> str:
        try:
            a = ipaddress.ip_address(m.group(0))
        except ValueError:
            return m.group(0)
        return self._ip(a, m.group(0))

    def _colon(self, m) -> str:
        tok, tail = m.group(0), ""
        while tok.endswith("."):
            tok, tail = tok[:-1], tail + "."
        try:
            a = ipaddress.ip_address(tok)
        except ValueError:
            return self._macs(tok) + tail
        return self._ip(a, tok) + tail

    def _macs(self, tok: str) -> str:
        """aa:bb:cc:dd:ee:ff, also a netfilter MAC= header (dst src type)."""
        g = tok.split(":")
        if len(g) < 6 or not all(len(x) == 2 and all(c in "0123456789abcdefABCDEF" for c in x)
                                 for x in g):
            return tok
        out = []
        for i in range(0, len(g) - 5, 6):
            out.append(self._mac(":".join(g[i:i + 6]).lower()))
        rest = g[len(out) * 6:]
        return ":".join(out + rest)

    def _mac(self, mac: str) -> str:
        if mac in KEEP_MACS or mac.startswith("02:00:00:00:"):
            return mac
        if mac not in self.macs:
            n = len(self.macs) + 1
            self.macs[mac] = f"02:00:00:00:{n >> 8:02x}:{n & 255:02x}"
        self.n["mac"] += 1
        return self.macs[mac]


def message(e: dict) -> str:
    v = e.get("MESSAGE")
    if isinstance(v, str):
        return v
    if isinstance(v, list) and all(isinstance(b, int) and 0 <= b <= 255 for b in v):
        return bytes(v).decode("utf-8", errors="replace")
    return ""


def audit_keys(msg: str) -> tuple:
    """Keys of a SYSCALL record. key=(null) -> (). Several keys: hex, \\x01 between."""
    m = KEY_RE.search(msg)
    if m is None or (m.group(1) is None and m.group(2) is None):
        return ()
    if m.group(1) is not None:
        return (m.group(1),)
    return tuple(k for k in bytes.fromhex(m.group(2)).decode("latin-1").split("\x01") if k)


def _marker(e: dict) -> bool:
    return e.get("SYSLOG_IDENTIFIER") == MARKER


def _check_name(name: str) -> str:
    if not NAME_RE.fullmatch(name):
        raise FixtureError(f"bad section name {name[:40]!r}: [a-z0-9-], max 40")
    return name


def load(lines) -> tuple:
    """-> (entries, bad). Entry = dict with str __CURSOR and __REALTIME_TIMESTAMP."""
    entries, bad = [], 0
    for line in lines:
        if not line.strip():
            continue
        try:
            e = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if not (isinstance(e, dict) and isinstance(e.get("__CURSOR"), str)
                and isinstance(e.get("__REALTIME_TIMESTAMP"), str)):
            bad += 1
            continue
        entries.append(e)
    return entries, bad


def split(entries: list, name: str | None) -> tuple:
    """-> ({section: [entries]}, entries before the first marker)."""
    if name is not None:
        return {_check_name(name): [e for e in entries if not _marker(e)]}, 0
    out, cur, before = {}, None, 0
    for e in entries:
        if _marker(e):
            cur = _check_name(message(e).strip())
            if cur in out:
                raise FixtureError(f"marker twice: {cur}")
            out[cur] = []
        elif cur is None:
            before += 1
        else:
            out[cur].append(e)
    if not out:
        raise FixtureError(f"no markers (logger -t {MARKER} NAME); one section: --name NAME")
    return out, before


def drop_events(entries: list, drop: tuple) -> tuple:
    """-> (kept, audit events by key, events dropped). Key '-' = key=(null)."""
    events, gone = collections.Counter(), set()
    for e in entries:
        if e.get("_TRANSPORT") == "audit" and e.get("_AUDIT_TYPE") == SYSCALL:
            keys = audit_keys(message(e))
            for k in keys or ("-",):
                events[k] += 1
            if set(keys) & set(drop) and e.get("_AUDIT_ID") is not None:
                gone.add(e["_AUDIT_ID"])
    kept = [e for e in entries
            if not (e.get("_TRANSPORT") == "audit" and e.get("_AUDIT_ID") in gone)]
    return kept, events, len(gone)


def clean(e: dict, masker: Masker, i: int) -> dict:
    out = {}
    for f in FIELDS:
        if f not in e:
            continue
        if f == "__CURSOR":
            out[f] = f"s=1;i={i};b=0;m=0;t=0;x=0"
        elif f.endswith("TIMESTAMP"):
            out[f] = e[f]
        else:
            out[f] = masker.value(e[f])
    return out


def _span(entries: list) -> int:
    try:
        ts = [int(e["__REALTIME_TIMESTAMP"]) for e in entries]
    except ValueError:
        return 0
    return round((max(ts) - min(ts)) / 1e6) if ts else 0


def convert(lines, masker: Masker, name: str | None = None, drop: tuple = ()) -> tuple:
    """-> ({section: [clean entries]}, report)."""
    entries, bad = load(lines)
    raw, before = split(entries, name)
    rep = {"bad": bad, "before": before, "hfw": 0, "sections": {}}
    out = {}
    for sec, es in raw.items():
        span = _span(es)
        es, events, dropped = drop_events(es, drop)
        kept = []
        for e in es:
            if e.get("_TRANSPORT") == "kernel" and message(e).startswith("HFW-"):
                rep["hfw"] += 1
                continue
            kept.append(clean(e, masker, len(kept) + 1))
        out[sec] = kept
        rep["sections"][sec] = {"entries": len(kept), "span": span, "events": events,
                                "dropped": dropped}
    rep["masked"] = dict(masker.n)
    return out, rep


def write(sections: dict, outdir: str) -> list:
    """Non-empty sections -> OUTDIR/<name>.json. Refuses if any file exists."""
    paths = {s: os.path.join(outdir, s + ".json") for s, es in sections.items() if es}
    there = sorted(p for p in paths.values() if os.path.lexists(p))
    if there:
        raise FixtureError("exists, not overwritten: " + ", ".join(there))
    os.makedirs(outdir, exist_ok=True)
    for s, p in paths.items():
        with open(p, "x", encoding="ascii") as f:
            for e in sections[s]:
                f.write(json.dumps(e) + "\n")
    return list(paths.values())


def report(rep: dict, out) -> None:
    for sec, r in rep["sections"].items():
        ev = ", ".join(f"{k} {n}" for k, n in sorted(r["events"].items(),
                                                     key=lambda kv: (-kv[1], kv[0])))
        print(f"{sec}: {r['entries']} entries, {r['span']} s, {r['dropped']} events dropped"
              + (f" | audit events by key: {ev}" if ev else ""), file=out)
    print(f"dropped: {rep['before']} before first marker, {rep['hfw']} HFW lines, "
          f"{rep['bad']} bad lines", file=out)
    m = rep["masked"]
    print("masked: " + (", ".join(f"{k} {n}" for k, n in sorted(m.items())) or "nothing"),
          file=out)


def host_names() -> dict:
    """Text to mask -> replacement, read from this host and my login."""
    pw = pwd.getpwuid(os.getuid())
    names = {pw.pw_name: "user"}
    real = pw.pw_gecos.split(",")[0].strip()
    if real and real != pw.pw_name:
        names[real] = "Real Name"
        for part in real.split():
            if len(part) >= 3:
                names.setdefault(part, "Name")
    node = os.uname().nodename
    for h in (node, node.split(".")[0]):
        if h.lower() not in GENERIC_HOSTS:
            names.setdefault(h, "host")
    for path in ("/etc/machine-id", "/proc/sys/kernel/random/boot_id"):
        try:
            with open(path, encoding="ascii") as f:
                v = f.read().strip()
        except (OSError, ValueError):
            continue
        if len(v) >= 32:
            names[v] = re.sub(r"[0-9a-fA-F]", "0", v)
            names[v.replace("-", "")] = "0" * 32
    return names


def main(argv=None, stdin=None, stdout=None, stderr=None, names=None) -> int:
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    p = argparse.ArgumentParser(prog="journal_fixture.py",
                                description="journalctl -o json (stdin) -> test fixtures")
    p.add_argument("outdir", nargs="?")
    p.add_argument("--name", help="one section, no markers")
    p.add_argument("--drop-key", action="append", default=[], metavar="KEY",
                   help="leave out audit events with this key (repeat)")
    p.add_argument("--fields", action="store_true",
                   help="print the list for journalctl --output-fields and exit")
    a = p.parse_args(argv)
    if a.fields:
        print(",".join(f for f in FIELDS if not f.startswith("__")), file=stdout)
        return 0
    if a.outdir is None:
        p.error("OUTDIR is required")
    if names is None:
        if os.geteuid() == 0:
            print("journal_fixture: run as my login user (names to mask come from it)",
                  file=stderr)
            return 2
        names = host_names()
    try:
        sections, rep = convert(stdin, Masker(names), a.name, tuple(a.drop_key))
        paths = write(sections, a.outdir)
    except FixtureError as e:
        print(f"journal_fixture: {e}", file=stderr)
        return 2
    report(rep, stderr)
    for path in paths:
        print(path, file=stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
