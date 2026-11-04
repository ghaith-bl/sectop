"""Log cards: enter on a table row with `logs` (a rule name) opens every logged line of
that rule this boot (firewall: a hostfw counter, modules/firewall/logcard.py).

Runs in the UI process (my user), on enter only: one fixed journal query, then the card
is built once and kept in the UI state (core/ui.py logdata) until it closes. Not
collecting: nothing runs on a tick, the collector is not asked (the channel stays
one-way, docs/architecture.md, Privilege split). The builder per module is static here
(like core/registry.py): a row can only name a rule, never what gets imported.
"""

import importlib

from core.run import run as _run

CARDS = {"firewall": "modules.firewall.logcard"}   # module name -> its card builder


def info(view: list, box: str, rule: str) -> dict:
    """The row that opened the card (still in the view, frozen while paused):
    pkts = its second cell, the rest from its detail (verdict, meaning, match, log)."""
    module, _sep, pid = box.partition("/")
    for m in view:
        if m.get("name") != module:
            continue
        for p in m.get("panels", ()):
            if p.get("id") != pid or p.get("type") != "table":
                continue
            for r in p["rows"]:
                if r.get("logs") == rule:
                    out = {it["k"]: it["v"] for it in r.get("detail", ()) if it["k"]}
                    out["pkts"] = r["cells"][1] if len(r["cells"]) > 1 else "?"
                    return out
    return {}


def load(req: tuple, view: list, run=_run) -> dict:
    """req = (module, box key, rule) -> the card (its builder's dict), or {"error": why}."""
    module, box, rule = req
    name = CARDS.get(module)
    if name is None:
        return {"error": f"no log card for module {module}"}
    try:
        mod = importlib.import_module(name)
        return mod.card(rule, info(view, box, rule), run=run)
    except (ImportError, ValueError, OSError) as e:
        return {"error": f"log card: {type(e).__name__}: {e}"}
