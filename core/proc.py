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

Shared cgroup (2026-11-03): GNOME Shell's own unit (org.gnome.Shell@<x>.service) is not
an app. An app GNOME starts lands there when its launcher forks before GNOME moves the
pid into the app scope (host: Brave rpm, 10 processes). Their program would be
org.gnome.Shell: shared() finds the unit, own() tells GNOME's own processes (SHELL_OWN;
mutter-x11-frames draws the frames of X11 windows, e.g. Steam: added 2026-11-03)
from strays, strays() lists the others by comm (cgroup.procs + /proc/<pid>/comm, both
readable by every user). Used by the system module (check shared_cgroup) and the
firewall (sockets from there: org.gnome.Shell/<comm> or org.gnome.Shell/?).
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
SHELL_UNIT_RE = re.compile(r"org\.gnome\.Shell@[A-Za-z0-9_.:-]{1,64}\.service")
SHELL_OWN = ("gnome-shell", "Xwayland", "bwrap", "glycin-*",   # comm, * = prefix
             "mutter-x11-fram*")   # mutter-x11-frames (comm: 15 chars), host 2026-11-03
CGROUP_ROOT = "/sys/fs/cgroup"
MAX_PIDS = 1024          # cgroup.procs entries read per shared cgroup
MAX_HOPS = 8             # parents walked up out of a session scope
SLACK = 1.0              # btime has whole seconds; journald time is after the record
MAX_READ = 64 * 1024
MAX_SCAN = 4096          # /proc entries read by by_uid()


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


def shared(cgroup: str) -> str | None:
    """Innermost unit of cgroup when it is GNOME Shell's own (shared) unit, else None."""
    units = [p for p in (cgroup or "").split("/") if p.endswith(_UNIT_SUFFIXES)]
    if units and SHELL_UNIT_RE.fullmatch(units[-1]):
        return units[-1]
    return None


def own(comm: str) -> bool:
    """comm is one of GNOME Shell's own processes (SHELL_OWN)."""
    for name in SHELL_OWN:
        if comm == name or (name.endswith("*") and comm.startswith(name[:-1])):
            return True
    return False


def label(counts) -> str:
    """Counter comm -> n: 'brave x10, cat x2' (most first, then by name)."""
    items = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return ", ".join(f"{c} x{n}" if n > 1 else c for c, n in items)


def strays(cgroup: str, root: str = CGROUP_ROOT, proc_root: str = "/proc"):
    """Processes of a shared cgroup that are not GNOME Shell's own -> Counter comm -> n.
    None if cgroup.procs cannot be read. A pid gone between the two reads is skipped."""
    if not cgroup.startswith("/") or "/.." in cgroup or "\0" in cgroup:
        return None
    try:
        with open(f"{root}{cgroup}/cgroup.procs", "rb") as f:
            pids = f.read(MAX_READ).decode("ascii", errors="replace").split()[:MAX_PIDS]
    except OSError:
        return None
    out = collections.Counter()
    for pid in pids:
        if not pid.isdigit():
            continue
        try:
            with open(f"{proc_root}/{pid}/comm", "rb") as f:
                comm = f.read(64).decode("utf-8", errors="replace").strip()
        except OSError:
            continue
        if not own(comm):
            out[comm if NAME_RE.fullmatch(comm) else "?"] += 1
    return out


def by_uid(proc_root: str = "/proc", limit: int = MAX_SCAN) -> dict:
    """fs uid (str) -> Counter program -> processes, now (2026-11-09, firewall uid guess).
    Program None = a process with no unit (login / sudo session scope). Kernel threads
    (cgroup /), processes gone or unreadable: skipped. fsuid: the uid a socket gets."""
    try:
        pids = [p for p in os.listdir(proc_root) if p.isdigit()][:limit]
    except OSError:
        return {}
    out = collections.defaultdict(collections.Counter)
    for pid in pids:
        try:
            with open(f"{proc_root}/{pid}/status", "rb") as f:
                status = f.read(MAX_READ).decode("ascii", errors="replace")
            with open(f"{proc_root}/{pid}/cgroup", "rb") as f:
                cg = f.read(MAX_READ).decode("utf-8", errors="replace")
        except OSError:
            continue
        uid = next((ln.split()[4:5] for ln in status.splitlines() if ln.startswith("Uid:")),
                   [])
        path = next((ln[3:].strip() for ln in cg.splitlines() if ln.startswith("0::")), "")
        if not uid or not uid[0].isdigit() or path in ("", "/"):
            continue
        name = program(path)
        out[uid[0]][None if name and SESSION_RE.fullmatch(name) else name] += 1
    return dict(out)


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

    def _stat(self, pid: str) -> list:
        """Fields after comm (comm may hold spaces and ')'): [state, ppid, ...]."""
        stat = self._read(f"{self.root}/{pid}/stat")
        return stat[stat.rindex(")") + 2:].split()

    def started(self, pid: str) -> float:
        """Start of the process, epoch seconds."""
        return self.btime() + int(self._stat(pid)[19]) / self.hz   # field 22: starttime

    def _cgroup(self, pid: str) -> str:
        for line in self._read(f"{self.root}/{pid}/cgroup").splitlines():
            if line.startswith("0::"):
                return line[3:].strip()
        return ""

    def program(self, pid: str | None, ts: float) -> str | None:
        """Program of pid. In a login / sudo session scope (sudo, a root shell, a script
        run with sudo: the scope is no program): the first parent outside it, walking
        the live process tree up (/proc/<pid>/stat ppid; a running process's parent
        chain is current: a parent that ended hands its children to pid 1 or a
        subreaper, never to a stranger). 2026-10-26, host: `sudo ./install.sh` ->
        systemctl got no program, its parents sat in sudo's session."""
        if not pid or not pid.isdigit() or pid == "0":
            return None
        try:
            if self.started(pid) > ts + SLACK:
                return None                         # started after the record: reused
            for _ in range(MAX_HOPS):
                cgroup = self._cgroup(pid)
                name = card_name(cgroup)
                if name or not SESSION_RE.fullmatch(program(cgroup) or ""):
                    return name                     # a program, or nothing to walk up
                pid = self._stat(pid)[1]            # session scope: its parent
                if pid in ("0", "1"):
                    return None
        except (OSError, ValueError, IndexError):
            return None
        return None
