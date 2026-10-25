"""security: screen 2 (docs/architecture.md, Security screen; docs/modules/security.md).

Phase 4 step 3: commands box. Source: core's journal follower (JOURNAL: every audit
record), assembled into events by core/audit.py. Rows: what ran as root after a login
(rule key root_cmds: execve with euid 0 and a login auid) and setuid execs
(user_emulation: uid != euid), grouped by who > as, exe and normalized argv.

Setuid execs: a launcher (sudo, pkexec, su: runs another command as root) is a launch;
any other setuid program (nvidia-modprobe, fusermount3, the polkit agent helper ...)
runs as root itself: a root run, via its parent if seen, else `setuid`.

Via: a root command whose argv equals a sudo USER_CMD (same session, within 5 s) ran
via `sudo <tty>`; a launch in the same pid (pkexec) or the parent pid (su) is its way
in; else the exe of a command seen before with the parent pid, else `ppid <n>`. No
/proc lookup: read seconds later, a pid may belong to another process.

unix_chkpwd (pam_unix helper, 1-2 per password prompt) is never a row: counted on the
row of its parent (a launch waiting for its command, else the command seen with that
pid: sudo run by root, gdm-session-worker on unlock). Parent not seen: counted only.

Secrets (core/sanitize.py mask_secrets): always masked in the cmd cell and in grouping;
the detail argv is raw, masked by the UI while mask is on (key m shows it).

A launch is a row at once ("no root command"); when its root command comes (after the
password, any time later) the launch is taken back out of that row and the command row
gets its password checks. A failed USER_CMD marks the launch row "denied". No timer:
a slow password prompt cannot turn a sudo into a launch without a command.
"""

import collections
import os
import pwd
import re
import time

from core import audit
from core.sanitize import _ADDR, mask_secrets

NAME = "security"
INTERVAL = 2.0
JOURNAL = {"groups": [["_TRANSPORT=audit"]],
           "fields": ["MESSAGE", "_AUDIT_ID", "_AUDIT_TYPE", "_AUDIT_TYPE_NAME"]}

ROOT_KEY = "root_cmds"          # hardening audit rules: execve as root after a login
LAUNCH_KEY = "user_emulation"   # setuid exec: uid != euid (sudo, pkexec, nvidia-modprobe)
LAUNCHERS = ("sudo", "pkexec", "su")   # setuid programs that run another command as root
USER_CMD = "AUDIT1123"          # sudo's own record: cmd, terminal, res
EXECVE = ("59", "322")          # execve, execveat (x86_64)
JOIN = 5.0                      # sudo USER_CMD -> its root command
UNSET = "4294967295"            # auid / ses not set (daemon, not a login)
MAX_GROUPS = 200
MAX_PIDS = 4096
MAX_ARGVS = 5
MAX_USERCMDS = 100
MAX_LAUNCHES = 256
LAUNCH_KEEP = 600.0             # a launch older than this cannot be matched any more
COLUMNS = ["last", "n", "who>as", "via", "cmd"]
TYPES = ["age", "num", "text", "text", "text"]

UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
HEX_RE = re.compile(r"\b0x[0-9a-f]+\b|\b[0-9a-f]{12,}\b", re.I)
NUM_RE = re.compile(r"\d+")


def normalize(args: list) -> str:
    """argv[1:] for grouping only: secrets, UUIDs, IPs, hex ids, numbers -> placeholders."""
    s = mask_secrets(" ".join(args))
    s = UUID_RE.sub("<uuid>", s)
    s = _ADDR.sub("<ip>", s)
    s = HEX_RE.sub("<hex>", s)
    return NUM_RE.sub("#", s)


def _user(uid: str) -> str:
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except (KeyError, ValueError, OverflowError):
        return uid


def _stamp(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


class Group:
    def __init__(self, who: str, as_: str, exe: str, ts: float):
        self.who, self.as_, self.exe = who, as_, exe
        self.n, self.first, self.last = 0, ts, ts
        self.argvs = collections.deque(maxlen=MAX_ARGVS)     # distinct, newest first
        self.vias = collections.deque(maxlen=MAX_ARGVS)      # distinct, newest first
        self.via = self.cwd = self.ses = self.pid = self.ppid = self.key = ""
        self.result = ""                                     # launches: no root command
        self.denied = 0                                      # launches with a failed USER_CMD
        self.chkpwd = 0


class Launch:
    def __init__(self, ev, ts: float, key: str):
        self.ev, self.ts, self.key = ev, ts, key     # key: its row (group)
        self.chkpwd = 0
        self.matched = self.denied = False


class State:
    def __init__(self, wall=time.time, user=_user, stamp=_stamp):
        self.wall, self.user, self.stamp = wall, user, stamp
        self.asm = audit.Assembler()
        self.groups = collections.OrderedDict()   # key -> Group, least recent first
        self.pids = collections.OrderedDict()     # pid -> (exe, row key): commands seen
        self.launches = collections.OrderedDict()  # pid -> Launch (setuid process)
        self.usercmds = collections.deque(maxlen=MAX_USERCMDS)
        self.names = {}                           # uid -> name
        self.runs = 0                             # root commands since start
        self.skipped = 0                          # failed execve in a PATH search
        self.lost_checks = 0                      # unix_chkpwd, parent not seen

    def name(self, uid: str | None) -> str:
        if not uid or uid == UNSET:
            return "-"
        if uid not in self.names:
            if len(self.names) > 256:
                self.names.clear()
            self.names[uid] = self.user(uid)
        return self.names[uid]


def _remember(st: State, pid: str, exe: str, key: str) -> None:
    st.pids.pop(pid, None)
    st.pids[pid] = (exe, key)
    while len(st.pids) > MAX_PIDS:
        st.pids.popitem(last=False)


def _key(st: State, ev, argv: list) -> str:
    who, as_ = st.name(ev.get("auid")), st.name(ev.get("euid"))
    exe = ev.get("exe") or (argv[0] if argv else "?")
    return "\x1f".join((who, as_, exe, normalize(argv[1:])))


def _group(st: State, ev, argv: list, ts: float) -> Group:
    who, as_ = st.name(ev.get("auid")), st.name(ev.get("euid"))
    exe = ev.get("exe") or (argv[0] if argv else "?")
    key = _key(st, ev, argv)
    g = st.groups.pop(key, None) or Group(who, as_, exe, ts)
    st.groups[key] = g                                     # most recent last
    while len(st.groups) > MAX_GROUPS:
        st.groups.popitem(last=False)
    g.n += 1
    g.last = max(g.last, ts)
    g.first = min(g.first, ts)
    line = " ".join(argv) or exe
    if line in g.argvs:
        g.argvs.remove(line)
    g.argvs.appendleft(line)
    g.cwd, g.ses = ev.cwd or "-", ev.get("ses") or "-"
    g.pid, g.ppid = ev.get("pid") or "-", ev.get("ppid") or "-"
    g.key = ",".join(ev.keys)
    return g


def _usercmd(st: State, ev, ts: float) -> None:
    uc = {"ts": ts, "ses": ev.get("ses"), "cmd": ev.get("cmd") or "",
          "tty": ev.get("terminal") or "?", "res": ev.get("res") or "", "pid": ev.get("pid"),
          "used": False}
    st.usercmds.append(uc)
    launch = st.launches.get(uc["pid"])
    if launch is not None and uc["res"] == "failed" and not launch.denied:
        launch.denied = True
        if launch.key in st.groups:
            st.groups[launch.key].denied += 1


def _take_back(st: State, launch: Launch) -> int:
    """The launch led to a root command: out of its launch row. -> its password checks."""
    launch.matched = True
    g = st.groups.get(launch.key)
    if g is not None:
        g.n -= 1
        g.chkpwd -= launch.chkpwd
        g.denied -= launch.denied
        if g.n <= 0:
            del st.groups[launch.key]
    n, launch.chkpwd = launch.chkpwd, 0
    return n


def _via(st: State, ev, argv: list, ts: float, fallback: str) -> tuple:
    """-> (via text, the launch it came from or None)."""
    line, ses = " ".join(argv), ev.get("ses")
    for uc in reversed(st.usercmds):
        if not uc["used"] and uc["ses"] == ses and uc["cmd"] == line \
                and abs(ts - uc["ts"]) <= JOIN and uc["res"] == "success":
            uc["used"] = True
            launch = st.launches.get(uc["pid"])
            if launch is not None and launch.matched:
                launch = None                    # its row was taken back already
            return f"sudo {uc['tty']}", launch
    pid, ppid = ev.get("pid"), ev.get("ppid")
    for p in (pid, ppid):                        # pkexec: same process; su: its child
        launch = st.launches.get(p)
        if launch is not None and not launch.matched:
            return os.path.basename(launch.ev.get("exe") or "?"), launch
    if ppid in st.pids:
        return os.path.basename(st.pids[ppid][0]), None
    return fallback, None


def _chkpwd(st: State, ev) -> None:
    """unix_chkpwd: never a row. A password check on the row of its parent."""
    ppid = ev.get("ppid")
    launch = st.launches.get(ppid)
    if launch is not None and not launch.matched:
        launch.chkpwd += 1                       # goes with its root command later
        key = launch.key
    elif ppid in st.pids:
        key = st.pids[ppid][1]                   # sudo run by root, gdm-session-worker
    else:
        st.lost_checks += 1                      # parent started before sectop
        return
    g = st.groups.get(key)
    if g is not None:
        g.chkpwd += 1


def _root(st: State, ev, ts: float, setuid: bool = False) -> None:
    """A root run: root_cmds, or a setuid program that is not a launcher."""
    argv = ev.argv
    if ev.get("success") == "no" and not argv:
        st.skipped += 1                          # PATH search: exit -2, no EXECVE
        return
    exe = ev.get("exe") or ""
    fallback = "setuid" if setuid else f"ppid {ev.get('ppid') or '?'}"
    via, launch = _via(st, ev, argv, ts, fallback)
    st.runs += 1
    checks = _take_back(st, launch) if launch is not None else 0
    key = _key(st, ev, argv)
    if launch is not None:                       # later checks under the launcher: here
        _remember(st, launch.ev.get("pid") or "", launch.ev.get("exe") or "", key)
    _remember(st, ev.get("pid") or "", exe, key)
    g = _group(st, ev, argv, ts)
    g.via, g.result = via, ""
    if via in g.vias:
        g.vias.remove(via)
    g.vias.appendleft(via)
    g.chkpwd += checks                           # the password prompt goes with it


def _launch(st: State, ev, ts: float) -> None:
    pid, key = ev.get("pid") or "", _key(st, ev, ev.argv)
    _remember(st, pid, ev.get("exe") or "", key)
    g = _group(st, ev, ev.argv, ts)
    g.via, g.result = "-", "no root command"
    st.launches.pop(pid, None)
    st.launches[pid] = Launch(ev, ts, key)


def _prune(st: State, now: float) -> None:
    """Forget launches that are too old to be matched (pids get reused)."""
    for pid in list(st.launches):
        if now - st.launches[pid].ts > LAUNCH_KEEP or len(st.launches) > MAX_LAUNCHES:
            del st.launches[pid]


def _row(st: State, key: str, g: Group) -> dict:
    result = "denied" if g.result and g.denied > 0 else g.result
    detail = [("exe", g.exe)]
    if result:
        detail.append(("result", result))
        if g.denied > 0:
            detail.append(("denied", f"{g.denied} of {g.n}"))
    detail += [("argv", a) for a in g.argvs]             # raw: the UI masks secrets
    if len(g.vias) > 1:
        detail.append(("via seen", ", ".join(g.vias)))
    detail += [("cwd", g.cwd), ("first", st.stamp(g.first)), ("ses", g.ses),
               ("pid / ppid", f"{g.pid} / {g.ppid}"), ("key", g.key or "-")]
    if g.chkpwd:
        detail.append(("password checks", str(g.chkpwd)))
    row = {"cells": [f"{g.last:.3f}", str(g.n), f"{g.who}>{g.as_}", result or g.via,
                     mask_secrets(g.argvs[0] if g.argvs else g.exe)],
           "sev": "ok", "id": key, "detail": [{"k": k, "v": v} for k, v in detail]}
    if result:
        row["tone"] = "dim"                              # launch without a root command
    return row


def init(cfg: dict) -> State:
    if cfg:
        raise ValueError(f"unknown option(s): {', '.join(sorted(cfg))}")
    return State()


def collect(st: State, ctx) -> dict:
    now = st.wall()
    for ev in st.asm.feed(ctx.journal, now):
        ts = ev.ts or now
        if ev.kind == USER_CMD:
            _usercmd(st, ev, ts)
        elif ev.kind == "SYSCALL" and ev.get("syscall") in EXECVE:
            exe = ev.get("exe") or ""
            if LAUNCH_KEY not in ev.keys and ROOT_KEY not in ev.keys:
                continue
            if exe.endswith("/unix_chkpwd"):
                _chkpwd(st, ev)                  # either key: never a row
            elif LAUNCH_KEY not in ev.keys:
                _root(st, ev, ts)
            elif os.path.basename(exe) in LAUNCHERS:
                _launch(st, ev, ts)
            else:
                _root(st, ev, ts, setuid=True)   # the setuid program runs as root itself
    _prune(st, now)
    groups = sorted(st.groups.items(), key=lambda kv: -kv[1].last)
    rows = [_row(st, key, g) for key, g in groups]
    title = f"commands {len(rows)}  ({st.runs} root runs since start)"
    items_note = ctx.journal_note if ctx.journal_up else (ctx.journal_note or "follower down")
    if items_note:
        title += f"  (journal: {items_note})"
    panel = {"id": "commands", "title": title, "type": "table", "columns": list(COLUMNS),
             "types": list(TYPES), "rows": rows, "width": "full"}
    summary = f"root runs {st.runs} | groups {len(rows)}"
    return {"v": 2, "status": "ok", "summary": summary, "panels": [panel], "events": [],
            "checks": []}
