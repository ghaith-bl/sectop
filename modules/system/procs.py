"""Programs box: what uses the cpu and the memory, one row per program
(docs/architecture.md, Processes screen; my ask 2026-10-27: "enter or c on memory must
show what takes it").

One /proc scan per collect: /proc/<pid>/stat (state, ppid, cpu ticks, rss, threads,
start) and the owner uid (os.stat). /proc/<pid>/cgroup once per process (pid + start:
pid reuse). No cmdline, no status, no fd, no environ.

Program = core/proc.py name of the cgroup (innermost unit / app id). A process in a
login or sudo session scope has no program name: its row is its comm + ` (session)`
(`bash (session)`), without `progs` (no card); no unit at all: its comm. Kernel threads
(pid 2 and its children): left out.

Stuck processes (Severity, 2026-10-27 my ask): every zombie (Z: ended, its parent has
not reaped it) and every process in D (uninterruptible wait, mostly disk / nfs) gets its
own row on top, outside its program's sums. Row: info while it is new, warn + check
when it stays STUCK s (60) in that state (counted from the first scan that saw it so).
A zombie row names its parent (pid, comm, program); c = the parent's card (the parent
is the one that must reap it). More than MAX_STUCK_CHECKS: one check for the rest.

Shared cgroup (2026-11-03, my ask: no app may hide in GNOME Shell's cgroup): a process in
org.gnome.Shell@<x>.service that is not GNOME Shell's own (core/proc.py SHELL_OWN:
gnome-shell, Xwayland, bwrap, glycin-*) is a stray: an app whose launcher forked before
GNOME moved it into its scope (host: Brave rpm). The org.gnome.Shell row names them
(detail lines, yellow); after STRAY s one warn check per cgroup, `shared_cgroup:<unit>`.
Its network shows as org.gnome.Shell on the firewall screen.

cpu % = ticks of the program since the last scan / ticks of the whole machine in the
same time (all cores = 100 %, as the cpu row). mem = sum of rss (shared pages count in
each process, as top). peak = highest of the last 60 scans (5 min).
"""

import collections
import pwd

from core import proc as procmod

TOP = 30                         # programs in the box
TOP_DETAIL = 20                  # processes in a program's detail
TOP_SYSTEM = 8                   # programs in the detail of the cpu / memory rows
HIST = 60
KTHREADD = 2
STUCK = 60.0                     # s in Z / D before warn + check
STUCK_STATES = {"Z": "zombie", "D": "D, uninterruptible"}
MAX_STUCK_ROWS = 20
MAX_STUCK_CHECKS = 10
STRAY = 10.0                     # s in GNOME Shell's cgroup before warn + check (a launch
                                 # moves in milliseconds: one scan may catch it there)
MAX_STRAY_LINES = 10
COLUMNS = ["program", "procs", "cpu", "peak", "mem", "peak", "user"]
TYPES = ["text", "num", "num", "num", "num", "num", "text"]
ROLES = ["name", "note", "value", "peak", "value", "peak", "note"]


class Procs:
    def __init__(self):
        self.seen = {}                   # (pid, start) -> (ticks, program, card, shared unit)
        self.hist = {}                   # program -> (cpu deque, mem deque, last scan n)
        self.n = 0                       # scans
        self.rows = []                   # last result, sorted: [Prog]
        self.since = {}                  # (pid, start, state) -> mono first seen so
        self.stuck = []                  # last result: [Stuck], oldest first
        self.stray_since = {}            # (pid, start) -> mono first seen in a shared cgroup
        self.strays = []                 # last result: [(Proc, uid, unit, since)]


class Stuck:
    def __init__(self, p, uid: int, since: float, parent, prog: str, card: str | None):
        self.p, self.uid, self.since = p, uid, since
        self.parent = parent             # (Proc, program name, card) or None
        self.prog, self.card = prog, card


class Prog:
    def __init__(self, name: str, card: str | None):
        self.name, self.card = name, card
        self.procs = []                  # (Proc, uid, cpu %)
        self.cpu = 0.0
        self.mem = 0
        self.uids = set()
        self.peak_cpu = self.peak_mem = 0.0
        self.strays = []                 # (Proc, unit, since): not GNOME Shell's own


def _user(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def scan(ps: Procs, host, dtotal: int | None, now: float = 0.0) -> list:
    """One scan -> programs sorted by memory (ps.stuck: zombies and D processes).
    dtotal: machine ticks since the last scan (None: first scan, cpu unknown)."""
    ps.n += 1
    page = host.page
    procs = host.procs()
    kernel = {p.pid for p, _ in procs if p.pid == KTHREADD or p.ppid == KTHREADD}
    seen, progs, stuck, since = {}, {}, [], {}
    strays, stray_since = [], {}
    for p, uid in procs:
        if p.pid in kernel:
            continue
        key = (p.pid, p.start)
        old = ps.seen.get(key)
        if old is None:
            cg = host.cgroup(p.pid)
            card = procmod.card_name(cg)
            unit = procmod.program(cg) or ""
            name = card or (f"{p.comm} (session)" if procmod.SESSION_RE.fullmatch(unit)
                            else p.comm)
            shared = procmod.shared(cg)
        else:
            _, name, card, shared = old
        seen[key] = (p.ticks, name, card, shared)
        if shared and not procmod.own(p.comm):
            stray_since[key] = ps.stray_since.get(key, now)
            strays.append((p, uid, shared, stray_since[key]))
        if p.state in STUCK_STATES:
            k = (p.pid, p.start, p.state)
            since[k] = ps.since.get(k, now)
            stuck.append((p, uid, since[k], name, card))
            if p.state == "Z":
                continue                 # ended: not in its program's sums
        cpu = 0.0
        if old is not None and dtotal:
            cpu = max(0.0, (p.ticks - old[0]) / dtotal * 100)
        g = progs.get(name)
        if g is None:
            g = progs[name] = Prog(name, card)
        g.procs.append((p, uid, cpu))
        g.cpu += cpu
        g.mem += p.rss * page
        g.uids.add(uid)
        if key in stray_since:
            g.strays.append((p, shared, stray_since[key]))
    ps.seen = seen
    ps.since = since
    ps.stray_since, ps.strays = stray_since, strays
    by_pid = {p.pid: p for p, _ in procs}
    ps.stuck = []
    for p, uid, t, name, card in sorted(stuck, key=lambda x: (x[2], x[0].pid)):
        par = by_pid.get(p.ppid)
        parent = None
        if par is not None:
            _, pname, pcard, _sh = seen.get((par.pid, par.start), (0, par.comm, None, None))
            parent = (par, pname, pcard)
        ps.stuck.append(Stuck(p, uid, t, parent, name, card))
    for name, g in progs.items():
        h = ps.hist.get(name)
        if h is None:
            h = ps.hist[name] = [collections.deque(maxlen=HIST),
                                 collections.deque(maxlen=HIST), 0]
        if dtotal:
            h[0].append(g.cpu)
        h[1].append(g.mem)
        h[2] = ps.n
        g.peak_cpu = max(h[0], default=g.cpu)
        g.peak_mem = max(h[1])
    for name in [n for n, h in ps.hist.items() if ps.n - h[2] > HIST]:
        del ps.hist[name]                # not seen for 5 min
    ps.rows = sorted(progs.values(), key=lambda g: (-g.mem, -g.cpu, g.name))
    return ps.rows


def _pct(v: float) -> str:
    return f"{v:.1f}%" if v < 10 else f"{v:.0f}%"


def _users(g: Prog, user) -> str:
    if len(g.uids) == 1:
        return user(next(iter(g.uids)))
    return f"{len(g.uids)} users"


def _stuck_row(s: Stuck, now: float, size, page: int, user) -> dict:
    """A zombie / D process: own row, info while new, warn after STUCK s."""
    p, zombie = s.p, s.p.state == "Z"
    age = now - s.since
    sev = "warn" if age >= STUCK else "info"
    if s.parent is not None:
        par, pname, pcard = s.parent
        parent = f"pid {par.pid} {par.comm} ({pname})"
    else:
        par, pname, pcard = None, "", None
        parent = f"pid {p.ppid} (gone)"
    if zombie:
        label = f"{p.comm} (zombie, parent {par.comm if par else p.ppid})"
        why = ("ended, the parent has not reaped it (wait()). It goes when the parent "
               "reaps it or exits; c = the parent's card")
        card = pcard
    else:
        label = f"{p.comm} (D)"
        why = ("waits in the kernel and cannot be killed (mostly disk / network fs io); "
               "long = a stuck device or driver")
        card = s.card
    detail = [{"k": "state", "v": f"{p.state} = {STUCK_STATES[p.state]}, seen so for "
                                  f"{age:.0f} s", "sev": sev},
              {"k": "pid", "v": str(p.pid)}, {"k": "comm", "v": p.comm},
              {"k": "program", "v": s.prog}, {"k": "user", "v": user(s.uid)},
              {"k": "parent", "v": parent, "sev": sev if zombie else "ok"},
              {"k": "why", "v": why}]
    row = {"id": f"stuck:{p.pid}:{p.start}",
           "cells": [label, "1", "-", "-", size(p.rss * page), "-", user(s.uid)],
           "sev": sev, "detail": detail}
    if card:
        row["progs"] = [card]
    return row


def stuck_checks(ps: Procs, now: float) -> list:
    """warn checks for processes in Z / D for STUCK s and more."""
    old = [s for s in ps.stuck if now - s.since >= STUCK]
    out = []
    for s in old[:MAX_STUCK_CHECKS]:
        p = s.p
        what = "zombie" if p.state == "Z" else "D (uninterruptible)"
        par = f", parent {s.parent[0].comm} pid {s.parent[0].pid}" if s.parent else ""
        out.append({"key": f"stuck:{p.pid}:{p.start}", "sev": "warn",
                    "title": f"{what} {p.comm} pid {p.pid} for {now - s.since:.0f} s{par}",
                    "detail": f"program {s.prog}"})
    if len(old) > MAX_STUCK_CHECKS:
        out.append({"key": "stuck:more", "sev": "warn",
                    "title": f"{len(old) - MAX_STUCK_CHECKS} more zombie / D processes",
                    "n": len(old) - MAX_STUCK_CHECKS})
    return out


def stray_checks(ps: Procs, now: float) -> list:
    """One warn check per shared cgroup holding strays for STRAY s and more."""
    by_unit = {}
    for p, _uid, unit, since in ps.strays:
        if now - since >= STRAY:
            by_unit.setdefault(unit, collections.Counter())[p.comm] += 1
    out = []
    for unit, comms in sorted(by_unit.items()):
        n = sum(comms.values())
        key = "shared_cgroup:" + "".join(ch if ch.isalnum() or ch in "_.:@-" else "_"
                                         for ch in unit)
        out.append({"key": key[:128], "sev": "warn",
                    "title": f"{n} process{'es' if n != 1 else ''} in {unit}: "
                             f"{procmod.label(comms)}",
                    "detail": "not GNOME Shell's own: started from GNOME without a scope of "
                              "their own, their network shows as org.gnome.Shell. Fix: "
                              "app-unit (silverblue-cis-hardening appunit)",
                    "n": n})
    return out


def _stray_lines(g: Prog, now: float) -> tuple:
    """-> (detail lines, row sev) for the strays of a program row (GNOME Shell's)."""
    if not g.strays:
        return [], "ok"
    old = any(now - t >= STRAY for _p, _u, t in g.strays)
    sev = "warn" if old else "info"
    comms = collections.Counter(p.comm for p, _u, _t in g.strays)
    units = sorted({u for _p, u, _t in g.strays})
    lines = [{"k": "not GNOME's own", "v": f"{procmod.label(comms)} in {', '.join(units)}",
              "sev": sev},
             {"k": "why", "v": "an app whose launcher forked before GNOME moved it into its "
                               "scope; fix: app-unit (silverblue-cis-hardening appunit)"}]
    for p, _u, t in sorted(g.strays, key=lambda x: (x[2], x[0].pid))[:MAX_STRAY_LINES]:
        lines.append({"k": f"pid {p.pid}", "v": f"{p.comm}  here {now - t:.0f} s",
                      "sev": sev})
    return lines, sev


def rows(ps: Procs, size, page: int, cpu_known: bool, user=_user, now: float = 0.0) -> list:
    """Table rows of the programs box: stuck processes (zombie, D) first, then the top
    TOP programs by memory."""
    out = [_stuck_row(s, now, size, page, user) for s in ps.stuck[:MAX_STUCK_ROWS]]
    shown = ps.rows[:TOP] + [g for g in ps.rows[TOP:] if g.strays]    # strays always shown
    for g in shown:
        cpu = _pct(g.cpu) if cpu_known else "-"
        top = sorted(g.procs, key=lambda x: (-x[0].rss, -x[2], x[0].pid))[:TOP_DETAIL]
        stray, sev = _stray_lines(g, now)
        detail = stray + [{"k": "processes", "v": f"{len(g.procs)}, top {len(top)} by memory"}]
        for p, uid, c in top:
            detail.append({"k": f"pid {p.pid}",
                           "v": f"{p.comm}  {size(p.rss * page)}  "
                                f"{_pct(c) if cpu_known else '-'} cpu  {p.state}  "
                                f"{p.threads} threads  {user(uid)}"})
        row = {"id": f"prog:{g.name}",
               "cells": [g.name, str(len(g.procs)), cpu, _pct(g.peak_cpu),
                         size(g.mem), size(g.peak_mem), _users(g, user)],
               "sev": sev, "detail": detail[:40]}
        if g.card:
            row["progs"] = [g.card]
            if len(g.card) <= 60:
                row["filter"] = g.card           # f / x on this program
        out.append(row)
    return out


def top_lines(ps: Procs, size, by: str, cpu_known: bool) -> tuple:
    """Detail lines + progs for the cpu / memory rows of the system box: the programs
    that use the most (by "cpu" or "mem")."""
    if by == "cpu" and not cpu_known:
        return [("top programs", "after the next scan")], []
    key = (lambda g: (-g.cpu, -g.mem)) if by == "cpu" else (lambda g: (-g.mem, -g.cpu))
    top = sorted(ps.rows, key=key)[:TOP_SYSTEM]
    lines = [("", "")]
    for i, g in enumerate(top, 1):
        v = _pct(g.cpu) if by == "cpu" else size(g.mem)
        lines.append((f"top {i}", f"{g.name}  {v}  ({len(g.procs)} procs)"))
    progs = [g.card for g in top if g.card][:5]
    return lines, progs
