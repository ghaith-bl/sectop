"""Alert engine: module checks -> alert state.

Pure: step() returns a new state and never changes its input. No I/O, no
clock (the caller passes `now`, epoch seconds). The state is plain JSON
data, so after the privilege split the collector service can hand it to
the UI as is (docs/architecture.md, Alerts).

Input: the `checks` of one validated Snapshot (core/module.py). A check is
a condition that is true now. A condition that is no longer true is left out.

Per alert (key = "<module>/<check key>"):
- open:   reported in the last step of its module
- held:   not reported any more, still firing until `hold` seconds after it
          was last reported (anti-flapping, like Prometheus keep_firing_for).
          Reported again within hold -> the same alert goes on
- closed: hold over. Record kept (first, last, count) until MAX_RECORDS
          pushes it out, oldest last seen first
- count:  + max(n, 1) when the check turns true (new, held or closed),
          + n while it stays true (n = new occurrences, e.g. packets)

A module that fails to collect is not stepped: its alerts keep their state.
Ack is not kept here. The UI keeps it, so the channel stays one-way.
"""

from core.module import SEV_RANK

DEFAULT_HOLD = 60.0
MAX_RECORDS = 500


def empty() -> dict:
    return {"alerts": {}}


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
        seen.add(key)
        rec = old.get(key)
        if rec is None:
            rec = {"key": key, "module": module, "first": now, "since": now,
                   "count": max(c["n"], 1)}
        elif rec["true"]:
            rec = {**rec, "count": rec["count"] + c["n"]}
        else:
            since = rec["since"] if status(rec, now) == "held" else now
            rec = {**rec, "since": since, "count": rec["count"] + max(c["n"], 1)}
        rec.update(sev=c["sev"], title=c["title"], detail=c["detail"],
                   hold=float(c.get("hold", DEFAULT_HOLD)), last=now, true=True)
        new[key] = rec
    for key, rec in old.items():
        if rec["module"] == module and rec["true"] and key not in seen:
            new[key] = {**rec, "true": False}
    return {"alerts": _trim(new, now)}


def active(state: dict, now: float) -> list:
    """Open and held alerts: worst first, open before held, newest first.
    Each is a copy of its record plus `state`."""
    out = [{**rec, "state": st} for rec in state["alerts"].values()
           if (st := status(rec, now)) != "closed"]
    out.sort(key=lambda r: (-SEV_RANK[r["sev"]], r["state"] != "open", -r["since"], r["key"]))
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
