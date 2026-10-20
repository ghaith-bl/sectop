"""Parse `ss -tunaH --cgroup state established`. Pure functions.

Program = the innermost systemd unit of the socket's cgroup (no CAP_SYS_PTRACE
needed, docs/architecture.md, Privilege split). Desktop apps run in
app[-<launcher>]-<ApplicationID>-<RANDOM>.scope or
app[-<launcher>]-<ApplicationID>[@<RANDOM>].service (systemd.io
DESKTOP_ENVIRONMENTS): the program is the ApplicationID. Other units: the unit
name without suffix and random part. `ss -p` output (users:(...)) is read too.
"""

import ipaddress
import re
from dataclasses import dataclass

# users:(("brave",pid=8100,fd=27),("other",pid=1,fd=3))
_PROC_RE = re.compile(r'\("((?:[^"\\]|\\.)*)",pid=(\d+)')
_CGROUP_RE = re.compile(r"(?:^|\s)cgroup:(\S+)")
_UNIT_SUFFIXES = (".service", ".scope")
# random part of a transient unit: -<uuid>, -<hex id>, -<number>
_RANDOM_RE = re.compile(
    r"-(?:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|[0-9a-f]{32,64}|[0-9]+)$")
_ESC_RE = re.compile(r"\\x([0-9a-fA-F]{2})")


@dataclass(frozen=True)
class Conn:
    proto: str
    local: str
    peer: str
    procs: tuple       # process names, unique, in ss order


def _unescape(name: str) -> str:
    """systemd unit name escaping: \\xNN -> the character."""
    return _ESC_RE.sub(lambda m: chr(int(m.group(1), 16)), name)


def program(cgroup: str) -> str | None:
    """cgroup v2 path -> program name, None if no unit in it (or unreachable)."""
    units = [p for p in cgroup.split("/") if p.endswith(_UNIT_SUFFIXES)]
    if not cgroup.startswith("/") or not units:
        return None
    base, _dot, kind = units[-1].rpartition(".")
    if kind == "service":
        base = base.split("@", 1)[0]
    if base.startswith("app-") and len(base) > 4:
        rest = base[4:]
        if kind == "scope":
            rest = rest.rpartition("-")[0] or rest      # drop -<RANDOM>
        # escaped: a dash inside the ApplicationID is \x2d, so the last part is the id
        return _unescape(rest.rsplit("-", 1)[-1]) or None
    return _unescape(_RANDOM_RE.sub("", base) if kind == "scope" else base) or None


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
        out.append(Conn(parts[0], parts[3], parts[4],
                        _procs(parts[5]) if len(parts) == 6 else ()))
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
