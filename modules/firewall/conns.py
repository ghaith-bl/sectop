"""Parse `ss -tunaH --cgroup state established`. Pure functions.

Program = the innermost systemd unit of the socket's cgroup (no CAP_SYS_PTRACE
needed, docs/architecture.md, Privilege split; core/proc.py program(), shared with the
security module since 2026-10-26). Desktop apps run in
app[-<launcher>]-<ApplicationID>-<RANDOM>.scope or
app[-<launcher>]-<ApplicationID>[@<RANDOM>].service (systemd.io
DESKTOP_ENVIRONMENTS): the program is the ApplicationID. Other units: the unit
name without suffix and random part. `ss -p` output (users:(...)) is read too.
"""

import ipaddress
import re
from dataclasses import dataclass, field

from core.proc import _RANDOM_RE, _UNIT_SUFFIXES, _unescape, program  # noqa: F401 (moved)

# users:(("brave",pid=8100,fd=27),("other",pid=1,fd=3))
_PROC_RE = re.compile(r'\("((?:[^"\\]|\\.)*)",pid=(\d+)')
_CGROUP_RE = re.compile(r"(?:^|\s)cgroup:(\S+)")
_INO_RE = re.compile(r"(?:^|\s)ino:(\d{1,20})(?:\s|$)")
WILDCARD = ("0.0.0.0", "::", "*")


@dataclass(frozen=True)
class Conn:
    proto: str
    local: str
    peer: str
    procs: tuple       # process names, unique, in ss order
    cgroup: str = field(default="", compare=False)    # cgroup path, "" if none
    ino: int = field(default=0, compare=False)        # socket inode (ss -e), 0 if none


def _procs(text: str) -> tuple:
    seen = []
    for name, _pid in _PROC_RE.findall(text):
        if name not in seen:
            seen.append(name)
    if not seen:
        m = _CGROUP_RE.search(text)
        name = program(m.group(1)) if m else None
        if name:
            seen.append(name)
    return tuple(seen)


def parse(text: str) -> list:
    """Lines: netid recv-q send-q local peer [process | cgroup]. Bad lines skipped."""
    out = []
    for line in text.splitlines():
        # maxsplit 5: process names may contain spaces
        parts = line.split(None, 5)
        if len(parts) < 5 or parts[0] not in ("tcp", "udp"):
            continue
        rest = parts[5] if len(parts) == 6 else ""
        cg, ino = _CGROUP_RE.search(rest), _INO_RE.search(rest)
        out.append(Conn(parts[0], parts[3], parts[4], _procs(rest) if rest else (),
                        cg.group(1) if cg else "", int(ino.group(1)) if ino else 0))
    return out


def split(addr: str) -> tuple:
    """'10.2.0.2:443', '[::1]:631', '192.168.8.102%wlo1:68' -> (host, port).

    Zone id dropped, IPv6 compressed, so it compares with log fields.
    No port -> (addr, '').
    """
    if addr.startswith("["):
        host, sep, port = addr[1:].partition("]:")
    else:
        host, sep, port = addr.rpartition(":")
    if not sep:
        return addr, ""
    host = host.split("%", 1)[0]
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        pass
    return host, port


def index(conns: list) -> dict:
    """(proto, local host, local port, peer host, peer port) -> process names."""
    return {(c.proto, *split(c.local), *split(c.peer)): c.procs for c in conns}


def ports(conns: list) -> dict:
    """(proto, local port) -> [(local host, process names)] of unbound-peer sockets."""
    out = {}
    for c in conns:
        host, port = split(c.local)
        if port.isdigit():
            out.setdefault((c.proto, port), []).append((host, c.procs))
    return out


def by_port(table: dict, proto: str, host: str, port: str) -> tuple:
    """Names of the sockets on local port (exact host or a wildcard), ss order."""
    names = []
    for h, procs in table.get((proto, port), ()):
        if h == host or h in WILDCARD:
            names += [n for n in procs if n not in names]
    return tuple(names)
