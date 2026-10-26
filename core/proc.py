"""Program of a process: the innermost systemd unit of its cgroup (docs/architecture.md,
Program card). Shared by the firewall (ss --cgroup) and the security module (audit pid).

Desktop apps run in app[-<launcher>]-<ApplicationID>-<RANDOM>.scope or
app[-<launcher>]-<ApplicationID>[@<RANDOM>].service (systemd.io DESKTOP_ENVIRONMENTS):
the program is the ApplicationID. Other units: the unit name without suffix and random
part. Moved here from modules/firewall/conns.py 2026-10-26.

Reader.program(pid, ts): an audit record names a pid; sectop reads /proc up to a few
seconds later, when the pid may belong to another process. The process must have
started before the record (/proc/<pid>/stat starttime + /proc/stat btime), else no name:
never a wrong one. Needs /proc of other users (sectop.service ProtectProc=default,
2026-10-26). Login and sudo session scopes (session-2.scope, session-c5.scope) are not
programs: no name.
"""

import collections
import os
import re

from core.module import MAX_PROGS

_UNIT_SUFFIXES = (".service", ".scope")
# random part of a transient unit: -<uuid>, -<hex id>, -<number>
_RANDOM_RE = re.compile(
    r"-(?:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|[0-9a-f]{32,64}|[0-9]+)$")
_ESC_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
NAME_RE = re.compile(r"[\x21-\x7e]{1,64}")        # row "progs" (core/module.py)
SESSION_RE = re.compile(r"session(-c?\d+)?")
SLACK = 1.0              # btime has whole seconds; journald time is after the record
MAX_READ = 64 * 1024


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


def card_name(cgroup: str) -> str | None:
    """program() for a row's `progs`: no session scopes, printable ASCII only."""
    name = program(cgroup or "")
    if not name or SESSION_RE.fullmatch(name) or not NAME_RE.fullmatch(name):
        return None
    return name


def names() -> collections.deque:
    """A row's program names (row `progs`), at most MAX_PROGS, newest kept."""
    return collections.deque(maxlen=MAX_PROGS)


def add(progs, name: str | None) -> None:
    """One more program for a row: distinct, a known one moves to the end."""
    if not name:
        return
    if name in progs:
        progs.remove(name)
    progs.append(name)


class Reader:
    """pid (+ the time of the record) -> program, from /proc. Errors -> None."""

    def __init__(self, root: str = "/proc"):
        self.root = root
        self.hz = os.sysconf("SC_CLK_TCK")
        self._btime = None

    def _read(self, path: str) -> str:
        with open(path, "rb") as f:
            return f.read(MAX_READ).decode("utf-8", errors="replace")

    def btime(self) -> float:
        if self._btime is None:
            for line in self._read(f"{self.root}/stat").splitlines():
                if line.startswith("btime "):
                    self._btime = float(line.split()[1])
                    break
            else:
                raise ValueError("no btime")
        return self._btime

    def started(self, pid: str) -> float:
        """Start of the process, epoch seconds. stat: comm may hold spaces and ')'."""
        stat = self._read(f"{self.root}/{pid}/stat")
        rest = stat[stat.rindex(")") + 2:].split()
        return self.btime() + int(rest[19]) / self.hz      # field 22: starttime

    def program(self, pid: str | None, ts: float) -> str | None:
        if not pid or not pid.isdigit() or pid == "0":
            return None
        try:
            if self.started(pid) > ts + SLACK:
                return None                         # started after the record: reused
            for line in self._read(f"{self.root}/{pid}/cgroup").splitlines():
                if line.startswith("0::"):
                    return card_name(line[3:].strip())
        except (OSError, ValueError, IndexError):
            return None
        return None
