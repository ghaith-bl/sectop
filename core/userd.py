"""sectop user helper: sectop-user@<user>.service, runs as that user, no capabilities
(docs/architecture.md, Privilege split; 2026-11-03).

Why: a process in GNOME Shell's shared cgroup (org.gnome.Shell@<x>.service, core/proc.py
shared()) cannot be named from the cgroup: the program would be org.gnome.Shell. The
socket -> process link is /proc/<pid>/fd, readable only by the process's own user (or
CAP_SYS_PTRACE: too strong for a monitor). So a helper runs as that user and reads the
fds of the processes in its own shared cgroups, nothing else: no network, no other
cgroups, no input from anyone.

Every INTERVAL s: the user's shared cgroups (user@<uid>.service/<slice>/
org.gnome.Shell@*.service), each pid in their cgroup.procs: comm + socket inodes of its
fds (socket:[<ino>]). Not dumpable (fd unreadable) -> denied. Written whole to
/run/sectop-user/<user>/socks.json (core/statefile.py), dir 0750 <user>:sectop-feed, file
0640 <user>:sectop-feed: the collector reads it.

Group sectop-feed (2026-11-05, account split): the unit's primary group (Group=), so the
dir systemd makes (RuntimeDirectory=) and every file the helper creates get it, no chown.
Only the helper and the collector (SupplementaryGroups=) hold it, nobody is a member. The
login user needs no group: the daily user stays out of group sectop (no state.json, no
whois socket for the GNOME session).

Display only: the user can write anything into that file, and a process sets its own
comm. The collector uses it to name sockets of the shared cgroup, never for a check.

Collector side: Reader -> socket inode -> Owner (pid, comm, user, cgroup).

systemd: /usr/bin/python3 -I -B /usr/local/lib/sectop/bin/sectop-user
"""

import grp
import os
import pwd
import re
import signal
import stat
import sys
import time
from dataclasses import dataclass

from core import proc as procmod
from core import statefile
from core.module import _is_num
from core.sanitize import display

USER_DIR = "/run/sectop-user"
FILE = "socks.json"
GROUP = "sectop-feed"            # unit Group=: helper -> collector only
VERSION = 1
INTERVAL = 2.0                   # as the firewall tick
MAX_AGE = 10.0                   # older file: helper stopped or stuck, not used
MAX_SIZE = 1024 * 1024
MAX_USERS = 16
MAX_CGROUPS = 8
MAX_PROCS = 256                  # processes per file
MAX_FDS = 4096                   # fds looked at per process
MAX_SOCKS = 4096                 # inodes per file
USER_RE = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
SOCK_RE = re.compile(r"socket:\[(\d{1,20})\]")


class Quit(BaseException):
    """Raised by the SIGTERM handler."""


# --- helper ----------------------------------------------------------------

def cgroups(uid: int, root: str = procmod.CGROUP_ROOT) -> list:
    """The user's shared cgroups: paths below root, '/user.slice/...', sorted."""
    base = f"/user.slice/user-{uid}.slice/user@{uid}.service"
    out = []
    try:
        top = sorted(e.name for e in os.scandir(root + base) if e.is_dir(follow_symlinks=False))
    except OSError:
        return []
    for name in top:
        if procmod.SHELL_UNIT_RE.fullmatch(name):
            out.append(f"{base}/{name}")
            continue
        try:
            sub = sorted(e.name for e in os.scandir(f"{root}{base}/{name}")
                         if e.is_dir(follow_symlinks=False))
        except OSError:
            continue
        out += [f"{base}/{name}/{s}" for s in sub if procmod.SHELL_UNIT_RE.fullmatch(s)]
    return out[:MAX_CGROUPS]


def _pids(root: str, cgroup: str) -> list:
    with open(f"{root}{cgroup}/cgroup.procs", "rb") as f:
        text = f.read(procmod.MAX_READ).decode("ascii", errors="replace")
    return [int(p) for p in text.split() if p.isdigit()][:MAX_PROCS]


def _socks(proc_root: str, pid: int) -> tuple:
    """-> (socket inodes, denied). denied: fd dir unreadable (not dumpable)."""
    out = []
    try:
        with os.scandir(f"{proc_root}/{pid}/fd") as it:
            for i, e in enumerate(it):
                if i >= MAX_FDS:
                    break
                try:
                    m = SOCK_RE.fullmatch(os.readlink(e.path))
                except OSError:
                    continue                 # fd closed meanwhile
                if m:
                    out.append(int(m.group(1)))
    except PermissionError:
        return [], True
    except OSError:
        return [], False                     # process gone
    return sorted(set(out)), False           # dir order is the filesystem's; dup fds once


def scan(uid: int, root: str = procmod.CGROUP_ROOT, proc_root: str = "/proc") -> list:
    """Processes of the user's shared cgroups -> [{pid, comm, cgroup, socks, denied}]."""
    out, n_socks = [], 0
    for cg in cgroups(uid, root):
        try:
            pids = _pids(root, cg)
        except OSError:
            continue
        for pid in pids:
            if len(out) >= MAX_PROCS:
                return out
            try:
                if os.stat(f"{proc_root}/{pid}").st_uid != uid:
                    continue                 # not mine: never read
                with open(f"{proc_root}/{pid}/comm", "rb") as f:
                    comm = f.read(64).decode("utf-8", errors="replace").strip()
            except OSError:
                continue
            socks, denied = _socks(proc_root, pid)
            socks = socks[:max(0, MAX_SOCKS - n_socks)]
            n_socks += len(socks)
            out.append({"pid": pid, "comm": comm, "cgroup": cg, "socks": socks,
                        "denied": denied})
    return out


def doc(uid: int, ts: float, procs: list) -> dict:
    return {"v": VERSION, "uid": uid, "ts": ts, "procs": procs}


def _log(msg: str) -> None:
    print(f"sectop-user: {display(msg)}", file=sys.stderr, flush=True)


def prepare(path: str, uid: int, gid: int) -> None:
    """The runtime dir systemd made for me (RuntimeDirectory=, User= / Group=): mine,
    group sectop-feed, 0750, so the collector gets in. No chown: a wrong group means a
    wrong unit. OSError / ValueError."""
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != uid:
        raise ValueError(f"{path}: not a directory owned by uid {uid}")
    if st.st_gid != gid:
        raise ValueError(f"{path}: group {st.st_gid}, not {GROUP} ({gid}): check Group=")
    os.chmod(path, 0o750, follow_symlinks=False)


def loop(uid: int, path: str, write=statefile.write, wall=time.time,
         sleep=time.sleep, log=_log, stop=lambda: False, scan=scan) -> None:
    """New files get my primary group (sectop-feed): no fchown."""
    problem = None
    while not stop():
        try:
            write(path, doc(uid, wall(), scan(uid)), 0o640)
            err = None
        except (OSError, statefile.StateError) as e:
            err = f"{path}: {type(e).__name__}: {e}"
        if err != problem:
            log(err or "writing again")
            problem = err
        sleep(INTERVAL)


def _term(signum, frame):
    raise Quit


def main(argv: list | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        print("usage: sectop-user   (no arguments; run by sectop-user@<user>.service)",
              file=sys.stderr)
        return 2
    if os.geteuid() == 0:
        _log("refusing to run as root: runs as the login user (sectop-user@<user>.service)")
        return 2
    uid = os.getuid()
    try:
        name = pwd.getpwuid(uid).pw_name
        gid = grp.getgrnam(GROUP).gr_gid
    except KeyError as e:
        _log(f"unknown user or group: {e}")
        return 2
    if not USER_RE.fullmatch(name):
        _log(f"user name {name!r} not supported")
        return 2
    if gid != os.getgid():
        _log(f"primary group is not {GROUP} (Group={GROUP} in sectop-user@.service)")
        return 2
    d = os.path.join(USER_DIR, name)
    try:
        prepare(d, uid, gid)
    except (OSError, ValueError) as e:
        _log(f"{d}: {e} (RuntimeDirectory=sectop-user/%i in the unit)")
        return 2
    signal.signal(signal.SIGTERM, _term)
    try:
        loop(uid, os.path.join(d, FILE))
    except (KeyboardInterrupt, Quit):
        pass
    return 0


# --- collector side --------------------------------------------------------

@dataclass(frozen=True)
class Owner:
    pid: int
    comm: str        # printable ASCII (core/proc.py NAME_RE), else "?"
    user: str
    cgroup: str


def _int(v, lo: int = 0) -> bool:
    return type(v) is int and v >= lo


def check(d, uid: int) -> tuple:
    """socks.json -> ([(pid, comm, cgroup, inodes, denied)], ts). Wrong -> ValueError."""
    if not isinstance(d, dict) or type(d.get("v")) is not int or d["v"] != VERSION:
        raise ValueError(f"v: {VERSION} required")
    if d.get("uid") != uid or type(d.get("uid")) is not int:
        raise ValueError("uid: not the owner's")
    ts = d.get("ts")
    if not _is_num(ts) or ts < 0:
        raise ValueError("ts: epoch seconds required")
    procs = d.get("procs")
    if not isinstance(procs, list) or len(procs) > MAX_PROCS:
        raise ValueError(f"procs: list of max {MAX_PROCS} required")
    out, n = [], 0
    for i, p in enumerate(procs):
        if not isinstance(p, dict):
            raise ValueError(f"procs[{i}]: object required")
        pid, comm, cg, socks = p.get("pid"), p.get("comm"), p.get("cgroup"), p.get("socks")
        if not _int(pid, 1) or not isinstance(comm, str) or not isinstance(cg, str) \
                or not isinstance(socks, list) or not isinstance(p.get("denied"), bool):
            raise ValueError(f"procs[{i}]: pid, comm, cgroup, socks, denied required")
        if not all(_int(s, 1) for s in socks):
            raise ValueError(f"procs[{i}].socks: inodes required")
        n += len(socks)
        if n > MAX_SOCKS:
            raise ValueError(f"more than {MAX_SOCKS} sockets")
        if not procmod.shared(cg) or not cg.startswith(f"/user.slice/user-{uid}.slice/"):
            raise ValueError(f"procs[{i}].cgroup: not a shared cgroup of uid {uid}")
        comm = comm if procmod.NAME_RE.fullmatch(comm) and len(comm) <= 16 else "?"
        out.append((pid, comm, cg, socks, p["denied"]))
    return out, float(ts)


class Reader:
    """() -> (socket inode -> Owner, notes). No /run/sectop-user: ({}, []) (helper not
    installed). users: the helpers whose file was fresh in the last call."""

    def __init__(self, base: str = USER_DIR, wall=time.time, getpw=pwd.getpwnam):
        self.base, self.wall, self.getpw = base, wall, getpw
        self.users = []
        self.denied = {}             # (user, pid) -> comm: fds unreadable

    def __call__(self) -> tuple:
        owners, notes = {}, []
        self.users, self.denied = [], {}
        try:
            names = sorted(os.listdir(self.base))[:MAX_USERS]
        except OSError:
            return owners, notes
        for name in names:
            if not USER_RE.fullmatch(name):
                continue
            try:
                uid = self.getpw(name).pw_uid
            except KeyError:
                notes.append(f"{name}: no such user")
                continue
            path = os.path.join(self.base, name, FILE)
            try:
                d = statefile.load(path, uid, MAX_SIZE)
                if d is None:
                    notes.append(f"{name}: no file yet")
                    continue
                procs, ts = check(d, uid)
            except (statefile.StateError, ValueError) as e:
                notes.append(f"{name}: {e}")
                continue
            age = self.wall() - ts
            if age > MAX_AGE:
                notes.append(f"{name}: {int(age)} s old (sectop-user@{name}.service stuck?)")
                continue
            self.users.append(name)
            for pid, comm, cg, socks, denied in procs:
                if denied:
                    self.denied[(name, pid)] = comm
                for ino in socks:
                    owners[ino] = Owner(pid, comm, name, cg)
        return owners, notes


if __name__ == "__main__":
    sys.exit(main())
