"""system: screen 3, the system box (docs/architecture.md, Processes screen).

Step 2 of the screen 3 plan. One row per metric: cpu, load, memory, swap, pressure
(cpu, memory, io), io per whole disk, free space of /var and /boot, one row per
temperature sensor. Columns: metric, now, trend (spark column, last 60 reads = 5 min),
info. Files only (modules/system/host.py): no commands, no root, no capability.

Checks (Severity, red rule 2026-10-25):
- crit: a sensor at or over its temp*_crit (no crit file: never red).
- crit: /var free below auditd admin_space_left (audit suspended, hardening repo).
- warn: /var free below auditd space_left.
- warn: a sensor at or over its warn limit for temp_warn_for s (row yellow at once).
  Warn limit: config temp_warn for that hwmon name, else temp*_max when below crit.
  Defaults 2026-10-27: coretemp 90 (max = crit = 100 on host), spd5118 70 (sensor max
  55 is reached while gaming; idle 37-43), nvme: sensor max 80.8.
- warn: a source that cannot be read (row shows why).
Pressure: shown only, no limit yet (limits from a week of my host's numbers).
/boot: row only.
"""

import collections
import time

from core.module import worst
from modules.system import host as hostmod
from modules.system.host import PSI

NAME = "system"
INTERVAL = 5.0
SPACE_EVERY = 60.0               # statvfs of the mounts
HIST = 60                        # trend points (MAX_SPARK_CELL)
MOUNTS = ("/var", "/boot")       # Silverblue: / is the image
AUDIT_MOUNT = "/var"             # auditd log (space_left / admin_space_left)
MIB = 1024 * 1024
COLUMNS = ["metric", "now", "trend", "info"]
TYPES = ["text", "num", "spark", "text"]

SENSORS = ("coretemp:Package id 0", "nvme:Composite", "spd5118")
SHORT = {"coretemp": "cpu", "nvme": "nvme", "spd5118": "ram"}
TEMP_WARN = {"coretemp": 90.0, "spd5118": 70.0}
TEMP_WARN_FOR = 60.0
SPACE_LEFT = 75                  # MiB, auditd.conf on host 2026-10-27 (root 0640: copied)
ADMIN_SPACE_LEFT = 50
OPTIONS = {"sensors", "temp_warn", "temp_warn_for", "audit_space_left",
           "audit_admin_space_left"}


def size(b: float) -> str:
    """Bytes -> 5.2G, 812M, 12K, 0B (1024 based)."""
    for unit, n in (("T", 1024 ** 4), ("G", 1024 ** 3), ("M", MIB), ("K", 1024)):
        if b >= n:
            v = b / n
            return f"{v:.1f}{unit}" if v < 10 else f"{v:.0f}{unit}"
    return f"{b:.0f}B"


def _num(v: float, digits: int = 0) -> str:
    s = f"{v:.{digits}f}"
    return s.rstrip("0").rstrip(".") if "." in s else s


def spark(vals, top: float | None = None, digits: int = 0) -> str:
    """Trend cell (core/module.py spark_cell): values as text, optional /top."""
    body = " ".join(_num(v, digits) for v in vals)
    return body + (f"/{_num(top, 1)}" if top else "") if body else ""


class State:
    def __init__(self, host=None, mono=time.monotonic, sensors=SENSORS, temp_warn=None,
                 warn_for=TEMP_WARN_FOR, space_left=SPACE_LEFT,
                 admin_space_left=ADMIN_SPACE_LEFT):
        self.host = host or hostmod.Host()
        self.mono = mono
        self.sensors = tuple(sensors)
        self.temp_warn = dict(TEMP_WARN if temp_warn is None else temp_warn)
        self.warn_for = float(warn_for)
        self.space_left, self.admin_space_left = space_left, admin_space_left
        self.hist = collections.defaultdict(lambda: collections.deque(maxlen=HIST))
        self.cpu = None                  # (busy, total) of the last read
        self.io = {}                     # disk -> (read, written, mono)
        self.space = {}                  # mount -> (free, size) or error text
        self.space_at = None
        self.hot = {}                    # sensor key -> mono since it is at / over warn
        self.cpus = 0


# --- options ---------------------------------------------------------------

def _limit(v, what: str, lo: float, hi: float) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not lo <= v <= hi:
        raise ValueError(f"{what}: number {lo:g}..{hi:g} required")
    return float(v)


def init(cfg: dict) -> State:
    unknown = set(cfg) - OPTIONS
    if unknown:
        raise ValueError(f"unknown option(s): {', '.join(sorted(unknown))}")
    sensors = cfg.get("sensors", list(SENSORS))
    if (not isinstance(sensors, list) or not sensors or len(sensors) > 16
            or not all(isinstance(s, str) and 0 < len(s) <= 64 and s.isprintable()
                       and s.partition(":")[0] for s in sensors)):
        raise ValueError('sensors: 1..16 of "<hwmon name>" or "<hwmon name>:<label>"')
    warn = cfg.get("temp_warn", TEMP_WARN)
    if not isinstance(warn, dict) or not all(isinstance(k, str) for k in warn):
        raise ValueError("temp_warn: table of <hwmon name> = C required")
    warn = {k: _limit(v, f"temp_warn.{k}", 20, 150) for k, v in warn.items()}
    space = _limit(cfg.get("audit_space_left", SPACE_LEFT), "audit_space_left", 0, 10 ** 6)
    admin = _limit(cfg.get("audit_admin_space_left", ADMIN_SPACE_LEFT),
                   "audit_admin_space_left", 0, 10 ** 6)
    if admin > space:
        raise ValueError("audit_admin_space_left: not above audit_space_left")
    return State(sensors=sensors, temp_warn=warn,
                 warn_for=_limit(cfg.get("temp_warn_for", TEMP_WARN_FOR), "temp_warn_for",
                                 0, 3600),
                 space_left=space, admin_space_left=admin)


# --- rows ------------------------------------------------------------------

def _row(rid: str, metric: str, now: str, trend: str, info: str, sev: str = "ok",
         detail=()) -> dict:
    r = {"id": rid, "cells": [metric, now, trend, info], "sev": sev}
    if detail:
        r["detail"] = [{"k": k, "v": v} for k, v in detail]
    return r


def _err(e: BaseException) -> str:
    msg = e.strerror if isinstance(e, OSError) and e.strerror else str(e)
    return f"{type(e).__name__}: {msg}"[:120]


def _unreadable(rows, checks, rid: str, metric: str, what: str, why: str) -> None:
    rows.append(_row(rid, metric, "?", "", f"{what}: {why}", "warn"))
    checks.append({"key": "read:" + what.replace(" ", ""), "sev": "warn", "title": f"system: {what} unreadable",
                   "detail": why})


def _cpu(st: State, rows, checks, out: dict) -> None:
    try:
        busy, total, cpus = hostmod.cpu_times(st.host.read("/proc/stat"))
    except (OSError, ValueError) as e:
        _unreadable(rows, checks, "cpu", "cpu", "/proc/stat", _err(e))
        return
    st.cpus = cpus
    pct = None
    if st.cpu and total > st.cpu[1]:
        pct = max(0.0, min(100.0, (busy - st.cpu[0]) / (total - st.cpu[1]) * 100))
        st.hist["cpu"].append(pct)
    st.cpu = (busy, total)
    out["cpu"] = pct
    rows.append(_row("cpu", "cpu", "-" if pct is None else f"{pct:.0f}%",
                     spark(st.hist["cpu"], 100), f"{cpus} cpus, all = 100%",
                     detail=[("busy", "-" if pct is None else f"{pct:.1f}% since the last read"),
                             ("cpus", str(cpus))]))


def _load(st: State, rows, checks) -> None:
    try:
        l1, l5, l15 = hostmod.loadavg(st.host.read("/proc/loadavg"))
    except (OSError, ValueError) as e:
        _unreadable(rows, checks, "load", "load", "/proc/loadavg", _err(e))
        return
    st.hist["load"].append(l1)
    rows.append(_row("load", "load", f"{l1:.2f}", spark(st.hist["load"], st.cpus or None, 2),
                     f"5m {l5:.2f}  15m {l15:.2f}",
                     detail=[("1 min", f"{l1:.2f}"), ("5 min", f"{l5:.2f}"),
                             ("15 min", f"{l15:.2f}"), ("cpus", str(st.cpus or "?"))]))


def _memory(st: State, rows, checks, out: dict) -> None:
    try:
        m = hostmod.meminfo(st.host.read("/proc/meminfo"))
    except (OSError, ValueError) as e:
        _unreadable(rows, checks, "memory", "memory", "/proc/meminfo", _err(e))
        return
    total, avail = m["MemTotal"], m["MemAvailable"]
    used = max(0, total - avail)
    st.hist["memory"].append(used / total * 100 if total else 0)
    out["memory"] = (used, total)
    rows.append(_row("memory", "memory", size(used), spark(st.hist["memory"], 100),
                     f"of {size(total)}, available {size(avail)}",
                     detail=[("used", f"{size(used)} (total - available)"),
                             ("available", size(avail)), ("total", size(total))]))
    stot, sfree = m["SwapTotal"], m["SwapFree"]
    sused = max(0, stot - sfree)
    st.hist["swap"].append(sused / stot * 100 if stot else 0)
    rows.append(_row("swap", "swap", size(sused), spark(st.hist["swap"], 100),
                     f"of {size(stot)}" if stot else "no swap",
                     detail=[("used", size(sused)), ("total", size(stot))]))


def _pressure(st: State, rows, checks) -> None:
    for what in PSI:
        path = f"/proc/pressure/{what}"
        rid = f"psi:{what}"
        try:
            p = hostmod.pressure(st.host.read(path))
        except (OSError, ValueError) as e:
            _unreadable(rows, checks, rid, f"pressure {what}", path, _err(e))
            continue
        some = p["some"]
        st.hist[rid].append(some["avg10"])
        full = p.get("full")
        info = f"some avg10 {some['avg10']:.2f}"
        if full and what != "cpu":           # system cpu full: always 0
            info += f"  full avg60 {full['avg60']:.2f}"
        detail = [("some avg10", f"{some['avg10']:.2f}%"), ("some avg60", f"{some['avg60']:.2f}%")]
        if full:
            detail += [("full avg10", f"{full['avg10']:.2f}%"),
                       ("full avg60", f"{full['avg60']:.2f}%")]
        detail.append(("limit", "none yet (set from a week of my host's numbers)"))
        rows.append(_row(rid, f"pressure {what}", f"{some['avg60']:.2f}%",
                         spark(st.hist[rid], digits=2), info, detail=detail))


def _io(st: State, rows, checks, now: float) -> None:
    try:
        disks = st.host.disks()
        stats = hostmod.diskstats(st.host.read("/proc/diskstats"), set(disks))
    except (OSError, ValueError) as e:
        _unreadable(rows, checks, "io", "io", "/proc/diskstats", _err(e))
        return
    for name in disks:
        if name not in stats:
            continue
        r, w = stats[name]
        prev = st.io.get(name)
        st.io[name] = (r, w, now)
        rid = f"io:{name}"
        if prev and now > prev[2] and r >= prev[0] and w >= prev[1]:
            dt = now - prev[2]
            rs, ws = (r - prev[0]) / dt, (w - prev[1]) / dt
            st.hist[rid].append((rs + ws) / 1024)
            cells = (size(rs + ws) + "/s", f"read {size(rs)}/s  write {size(ws)}/s")
        else:
            cells = ("-", "first read")
        rows.append(_row(rid, f"io {name}", cells[0], spark(st.hist[rid]), cells[1],
                         detail=[("read since boot", size(r)),
                                 ("written since boot", size(w)),
                                 ("trend unit", "KiB/s, read + write")]))


def _space(st: State, rows, checks, now: float) -> None:
    if st.space_at is None or now - st.space_at >= SPACE_EVERY:
        st.space_at = now
        for m in MOUNTS:
            try:
                st.space[m] = st.host.statvfs(m)
            except OSError as e:
                st.space[m] = _err(e)
    for m in MOUNTS:
        got, rid = st.space.get(m), f"space:{m}"
        if isinstance(got, str) or got is None:
            _unreadable(rows, checks, rid, m, f"statvfs {m}", got or "not read")
            continue
        free, total = got
        used = (total - free) / total * 100 if total else 0
        sev, detail = "ok", [("free", f"{size(free)} (for non-root)"), ("size", size(total)),
                             ("used", f"{used:.0f}%"), ("checked", f"every {SPACE_EVERY:g} s")]
        if m == AUDIT_MOUNT:
            detail += [("audit space_left", f"{st.space_left:g}M (warn)"),
                       ("audit admin_space_left", f"{st.admin_space_left:g}M (crit: audit "
                                                  "suspended)")]
            if free < st.admin_space_left * MIB:
                sev = "crit"
                checks.append({"key": f"space_audit:{m}", "sev": "crit",
                               "title": f"{m} free {size(free)}: audit suspended",
                               "detail": f"below auditd admin_space_left "
                                         f"{st.admin_space_left:g}M"})
            elif free < st.space_left * MIB:
                sev = "warn"
                checks.append({"key": f"space_audit:{m}", "sev": "warn",
                               "title": f"{m} free {size(free)}: audit space low",
                               "detail": f"below auditd space_left {st.space_left:g}M"})
        rows.append(_row(rid, m, size(free), "", f"free of {size(total)}, {used:.0f}% used",
                         sev, detail))


def _name(s, dup: bool) -> str:
    short = SHORT.get(s.hw, s.hw)
    return f"{short} {s.device}" if dup else short


def _temps(st: State, rows, checks, now: float, out: dict) -> None:
    try:
        sensors = st.host.sensors(st.sensors)
    except (OSError, ValueError) as e:
        _unreadable(rows, checks, "temp", "temp", "/sys/class/hwmon", _err(e))
        return
    count = collections.Counter(s.hw for s in sensors)
    seen = set()
    for s in sensors:
        key = s.key
        seen.add(key)
        name = _name(s, count[s.hw] > 1)
        if s.hw in st.temp_warn:
            warn, src = st.temp_warn[s.hw], "config"
        elif s.max is not None and (s.crit is None or s.max < s.crit):
            warn, src = s.max, "sensor max"
        else:
            warn, src = None, ""
        rid = f"temp:{key}"
        st.hist[rid].append(s.temp)
        sev = "ok"
        if s.crit is not None and s.temp >= s.crit:
            sev = "crit"
            checks.append({"key": f"temp_crit:{key}", "sev": "crit",
                           "title": f"{name} {s.temp:.0f} C: at crit {s.crit:g} C",
                           "detail": f"hwmon {s.hw} {s.device} temp{s.n}"})
        if warn is not None and s.temp >= warn:
            since = st.hot.setdefault(key, now)
            sev = worst(sev, "warn")
            if now - since >= st.warn_for and sev != "crit":
                checks.append({"key": f"temp_hot:{key}", "sev": "warn",
                               "title": f"{name} {s.temp:.0f} C for {now - since:.0f} s",
                               "detail": f"warn {warn:g} C ({src}) for {st.warn_for:g} s"})
        else:
            st.hot.pop(key, None)
        info = "  ".join(x for x in (f"warn {warn:g}" if warn is not None else "",
                                     f"crit {s.crit:g}" if s.crit is not None else "") if x)
        top = s.crit or warn
        detail = [("sensor", f"{s.hw} {s.device} temp{s.n}"),
                  ("label", s.label or "-"), ("now", f"{s.temp:.1f} C"),
                  ("max (sensor)", "-" if s.max is None else f"{s.max:g} C"),
                  ("crit (sensor)", "-" if s.crit is None else f"{s.crit:g} C"),
                  ("warn", "-" if warn is None else f"{warn:g} C ({src}) for "
                                                    f"{st.warn_for:g} s")]
        if key in st.hot:
            detail.append(("at / over warn", f"{now - st.hot[key]:.0f} s"))
        out.setdefault("temp", (name, s.temp))
        rows.append(_row(rid, f"temp {name}", f"{s.temp:.0f} C", spark(st.hist[rid], top),
                         info or "no limits", sev, detail))
    for key in set(st.hot) - seen:
        del st.hot[key]


# --- module API -------------------------------------------------------------

def collect(st: State, ctx) -> dict:
    now = st.mono()
    rows, checks, out = [], [], {}
    _cpu(st, rows, checks, out)
    _load(st, rows, checks)
    _memory(st, rows, checks, out)
    _pressure(st, rows, checks)
    _io(st, rows, checks, now)
    _space(st, rows, checks, now)
    _temps(st, rows, checks, now, out)

    parts = []
    if out.get("cpu") is not None:
        parts.append(f"cpu {out['cpu']:.0f}%")
    if "memory" in out:
        parts.append(f"mem {size(out['memory'][0])} / {size(out['memory'][1])}")
    if "temp" in out:
        parts.append(f"{out['temp'][0]} {out['temp'][1]:.0f} C")
    problems = [c["title"] for c in checks if c["sev"] in ("warn", "crit")]
    summary = " | ".join(parts + problems[:3]) or "-"
    panel = {"id": "system", "title": "system", "type": "table", "columns": list(COLUMNS),
             "types": list(TYPES), "rows": rows, "width": "full",
             "sev": worst(*(r["sev"] for r in rows))}
    return {"v": 2, "status": worst(*(c["sev"] for c in checks)), "summary": summary,
            "panels": [panel], "events": [], "checks": checks}
