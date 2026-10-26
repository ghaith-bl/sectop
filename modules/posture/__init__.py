"""posture: is my baseline still true (docs/modules/posture.md; docs/architecture.md,
Security posture). Screen 2, below the security boxes. Phase 4 step 6.

Baseline = silverblue-cis-hardening. Policy /etc/sectop/posture.toml (policy.py): which
check, the value my baseline wants, the severity when it fails, an optional ref
(accepted deviation: dim, no alert). Kinds are fixed code (checks.py): files first,
commands only where there is no file. Every INTERVAL (5 min); rpm-ostree once a day.

Audit counts (rules loaded, audit_enabled) come from the journal: CONFIG_CHANGE (1305)
of this boot, one scan in init (journalctl -b), then core's follower (JOURNAL). The
scan and the follower overlap from the collector start to the scan: entries the scan
saw are skipped by cursor.

Result per check: pass, fail, accepted (fail with a ref), unknown (could not read).
Row sev: fail = the check's sev, unknown = warn, accepted / pass = ok (accepted dim).
Alert (decided 2026-10-25: red only): a crit fail without ref -> check <id>.
"""

import json
import time

from core.audit import fields
from core.run import run as core_run
from modules.posture import checks as kinds
from modules.posture import policy

NAME = "posture"
INTERVAL = 300.0
JOURNAL = {"groups": [["_TRANSPORT=audit", "_AUDIT_TYPE=1305"]],
           "fields": ["MESSAGE", "_AUDIT_TYPE"]}
POLICY_PATH = policy.DEFAULT_PATH
POLICY_OWNER = 0                     # root-owned (tests: their own uid)
JOURNALCTL = "/usr/bin/journalctl"
SCAN_TIMEOUT = 5.0
SCAN_KEEP = 3600.0                   # scan cursors kept this long (follower overlap)
MAX_CURSORS = 20000
CONFIG_CHANGE = "1305"
COLUMNS = ["check", "result", "have", "want"]
TYPES = ["text", "text", "text", "text"]
RANK = {("fail", "crit"): 0, ("fail", "warn"): 1, ("fail", "info"): 2, ("unknown", ""): 3,
        ("accepted", ""): 4, ("pass", ""): 5}


class Audit:
    def __init__(self):
        self.added = self.removed = 0
        self.enabled = None            # last audit_enabled value set this boot
        self.err = ""                  # boot scan failed: audit checks unknown
        self.cursors = set()           # seen by the scan
        self.until = 0.0               # wall time: drop the cursors after this


class State:
    def __init__(self, checks=None, host=None, wall=time.time, stamp=None):
        self.checks = checks or ()
        self.policy_file = checks is not None
        self.host = host or kinds.Host()
        self.wall = wall
        self.stamp = stamp or (lambda ts: time.strftime("%H:%M:%S", time.localtime(ts)))
        self.audit = Audit()
        self.ostree = {}               # rpm-ostree status cache (checks.py)
        self.units = sorted({u for c in self.checks if c.kind == "units" for u, _ in c.units})


def config_change(a: Audit, message: str) -> None:
    """One CONFIG_CHANGE record: op=add_rule / remove_rule (res=1), audit_enabled=."""
    f = fields(message)
    if f.get("res") not in ("1", "success"):
        return
    if f.get("op") == "add_rule":
        a.added += 1
    elif f.get("op") == "remove_rule":
        a.removed += 1
    elif "audit_enabled" in f:
        a.enabled = f["audit_enabled"]


def scan(a: Audit, out: str) -> None:
    """journalctl -b -o json output of this boot's CONFIG_CHANGE entries."""
    for line in out.splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if not isinstance(e, dict) or e.get("_AUDIT_TYPE") != CONFIG_CHANGE:
            continue
        msg = e.get("MESSAGE")
        if isinstance(msg, str):
            config_change(a, msg)
        cur = e.get("__CURSOR")
        if isinstance(cur, str) and len(a.cursors) < MAX_CURSORS:
            a.cursors.add(cur)


def boot_scan(st: State, run=core_run) -> None:
    res = run([JOURNALCTL, "-b", "-q", "--no-pager", "-o", "json",
               "--output-fields=MESSAGE,_AUDIT_TYPE", "_TRANSPORT=audit",
               f"_AUDIT_TYPE={CONFIG_CHANGE}"], timeout=SCAN_TIMEOUT)
    if res.rc != 0 or res.timed_out or res.truncated:
        st.audit.err = "journal scan: " + (res.err.strip().splitlines() or [f"rc {res.rc}"])[-1][:80]
        return
    scan(st.audit, res.out)
    st.audit.until = st.wall() + SCAN_KEEP


def follow(st: State, entries, now: float) -> None:
    a = st.audit
    if a.cursors and now > a.until:
        a.cursors = set()
    for e in entries:
        if e.get("_TRANSPORT") != "audit" or e.get("_AUDIT_TYPE") != CONFIG_CHANGE:
            continue
        if e.get("__CURSOR") in a.cursors:
            continue                    # the boot scan counted it
        msg = e.get("MESSAGE")
        if isinstance(msg, str):
            config_change(a, msg)


def init(cfg: dict) -> State:
    if cfg:
        raise ValueError(f"unknown option(s): {', '.join(sorted(cfg))}")
    st = State(checks=policy.load(POLICY_PATH, POLICY_OWNER))   # bad file: init fails
    if any(c.kind.startswith("audit-") for c in st.checks):
        boot_scan(st)
    return st


def _row(c, res, checked: str) -> tuple:
    result = res.status
    if result == "fail" and c.ref:
        result = "accepted"
    sev = {"fail": c.sev, "unknown": "warn"}.get(result, "ok")
    detail = [("why", c.why), ("kind", c.kind), ("source", res.source or "-")]
    if c.ref:
        detail.append(("ref", c.ref))
    detail += res.lines
    detail.append(("checked", checked))
    row = {"cells": [c.id, result, res.have, kinds.want_text(c)], "sev": sev, "id": c.id,
           "detail": [{"k": k, "v": v} for k, v in detail]}
    if result == "accepted":
        row["tone"] = "dim"
    rank = RANK[(result, c.sev if result == "fail" else "")]
    return rank, row, result


def collect(st: State, ctx) -> dict:
    now = st.wall()
    follow(st, ctx.journal, now)
    cx = kinds.Cx(st.host, now, audit=st.audit, ostree=st.ostree)
    out, alerts = [], []
    counts = dict.fromkeys(("pass", "fail", "unknown", "accepted"), 0)
    checked = st.stamp(now)
    for i, c in enumerate(st.checks):
        try:
            res = kinds.check(c, cx, st.units)
        except (OSError, ValueError) as e:              # a bug in one kind: that row only
            res = kinds.Res("unknown", f"{type(e).__name__}: {e}"[:80])
        rank, row, result = _row(c, res, checked)
        counts[result] += 1
        out.append((rank, i, row))
        if result == "fail" and c.sev == "crit":
            alerts.append({"key": c.id, "sev": "crit", "title": f"{c.why}: {res.have}"[:160],
                           "detail": f"posture {c.id}, {res.source}"[:300]})
    rows = [r for _, _, r in sorted(out, key=lambda x: x[:2])]
    if st.policy_file:
        summary = " | ".join(f"{k} {v}" for k, v in counts.items())
    else:
        summary = "no posture.toml"
    title = (f"posture {len(rows)}  ({counts['fail']} fail, {counts['unknown']} unknown, "
             f"{counts['accepted']} accepted; every {INTERVAL / 60:g} min, last {checked})")
    panel = {"id": "posture", "title": title, "type": "table", "columns": list(COLUMNS),
             "types": list(TYPES), "rows": rows, "width": "full"}
    return {"v": 2, "status": "ok", "summary": summary, "panels": [panel], "events": [],
            "checks": alerts}
