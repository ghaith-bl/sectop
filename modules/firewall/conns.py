"""Parse `ss -tunapH state established`. Pure functions."""

import ipaddress
import re
from dataclasses import dataclass

# users:(("brave",pid=8100,fd=27),("other",pid=1,fd=3))
_PROC_RE = re.compile(r'\("((?:[^"\\]|\\.)*)",pid=(\d+)')


@dataclass(frozen=True)
class Conn:
    proto: str
    local: str
    peer: str
    procs: tuple       # process names, unique, in ss order


def _procs(text: str) -> tuple:
    seen = []
    for name, _pid in _PROC_RE.findall(text):
        if name not in seen:
            seen.append(name)
    return tuple(seen)


def parse(text: str) -> list:
    """Lines: netid recv-q send-q local peer [process]. Bad lines skipped."""
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
