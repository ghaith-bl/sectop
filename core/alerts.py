"""Alert engine: module checks -> alert state.

Pure: step() returns a new state and never changes its input. No I/O, no
clock (the caller passes `now`, epoch seconds). The state is plain JSON
data, so after the privilege split the collector service can hand it to
the UI as is (docs/architecture.md, Alerts).

Input: the `checks` of one validated Snapshot (core/module.py). A check is
a condition that is true now. A condition that is no longer true is left out.
State check (no `at`): true while its condition is. Event check (`at` = time of
its newest occurrence, e.g. a journal line): reported when new occurrences come.

Per alert (key = "<module>/<check key>"):
- open:   reported in the last step of its module
- held:   not reported any more, still firing until `hold` seconds after it
          was last seen (anti-flapping, like Prometheus keep_firing_for).
          Reported again within hold -> the same alert goes on
- last:   state check: the step it was reported. Event check: `at`, so the
          age and the hold count from the occurrence, not from the report.
          An event check with `at` not newer than the alert's last is a
          re-report of what the alert already has: dropped (a module that
          reads a journal window again cannot keep an alert open).
          An occurrence older than its hold opens nothing: record only
- hold:   the check's own `hold`, else event check: EVENT_HOLD by severity
          (crit 10 min, warn 5 min, info 1 min), state check: DEFAULT_HOLD
- closed: hold over. Record kept (first, last, count) until MAX_RECORDS
          pushes it out, oldest last seen first
- count:  + max(n, 1) when the check turns true (new, held or closed),
          + n while it stays true (n = new occurrences, e.g. packets)

A module that fails to collect is not stepped: its alerts keep their state.
Ack is not kept here. The UI keeps it, so the channel stays one-way.
Noise list (core/noise.py): applied in active(), the alert is still tracked.
"""

from core import noise as noisemod
from core.module import SEV_RANK

DEFAULT_HOLD = 60.0
EVENT_HOLD = {"crit": 600.0, "warn": 300.0, "info": 60.0}
MAX_RECORDS = 500


def empty() -> dict:
    return {"alerts": {}}


def event_hold(sev: str, hold: float | None = None) -> float:
    """Hold of an event check: `hold` when the module sets one, else by severity."""
    return float(hold) if hold is not None else EVENT_HOLD.get(sev, DEFAULT_HOLD)


def status(rec: dict, now: float) -> str:
    """open, held or closed."""
    if rec["true"]:
        return "open"
    return "held" if now - rec["last"] < rec["hold"] else "closed"


def step(state: dict, module: str, checks: list, now: float) -> dict:
    """New state after one successful collect of `module`."""
    old = state["alerts"]
    new = dict(old)
    seen = set()
    for c in checks:
        key = f"{module}/{c['key']}"
        rec = old.get(key)
        event = "at" in c
        at = min(float(c["at"]), now) if event else now
        if event and rec is not None and at <= rec["last"]:
            continue                             # nothing newer than the alert has
        hold = float(c["hold"]) if "hold" in c else (
            event_hold(c["sev"]) if event else DEFAULT_HOLD)
        seen.add(key)
        if rec is None:
            rec = {"key": key, "module": module, "first": at, "since": at,
                   "count": max(c["n"], 1)}
        elif rec["true"]:
            rec = {**rec, "count": rec["count"] + c["n"]}
        else:
            since = rec["since"] if status(rec, now) == "held" else at
            rec = {**rec, "since": since, "count": rec["count"] + max(c["n"], 1)}
        rec.update(sev=c["sev"], title=c["title"], detail=c["detail"], hold=hold, last=at,
                   true=not event or now - at < hold)
        new[key] = rec
    for key, rec in old.items():
        if rec["module"] == module and rec["true"] and key not in seen:
            new[key] = {**rec, "true": False}
    return {"alerts": _trim(new, now)}


def active(state: dict, now: float, noise=()) -> list:
    """Open and held alerts. Each is a copy of its record plus `state` and
    `noise` (reason from the noise list, else None). Order: noise last, worst
    first, open before held, newest since first, then key."""
    out = [{**rec, "state": st, "noise": noisemod.reason(noise, rec["key"], now)}
           for rec in state["alerts"].values() if (st := status(rec, now)) != "closed"]
    out.sort(key=lambda r: (r["noise"] is not None, -SEV_RANK[r["sev"]],
                            r["state"] != "open", -r["since"], r["key"]))
    return out


def _trim(alerts: dict, now: float) -> dict:
    """Keep at most MAX_RECORDS: closed out first, then held, oldest last seen
    first. Open alerts are never dropped (bounded by MAX_CHECKS per module)."""
    over = len(alerts) - MAX_RECORDS
    if over <= 0:
        return alerts
    rank = {"closed": 0, "held": 1}
    drop = sorted((r for r in alerts.values() if not r["true"]),
                  key=lambda r: (rank[status(r, now)], r["last"], r["key"]))[:over]
    for r in drop:
        del alerts[r["key"]]
    return alerts
