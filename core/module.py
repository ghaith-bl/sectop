"""Module contract: check module objects and validate Snapshots.

See docs/module-interface.md. validate() returns a new, normalized
Snapshot (known keys only, defaults filled, limits applied) or raises
InvalidSnapshot. Core never draws a Snapshot that did not pass here.
"""

import json
import math
import re

from core.sanitize import truncate

STATUSES = ("ok", "info", "warn", "crit", "unknown")
SEVS = ("ok", "info", "warn", "crit")
EVENT_SEVS = ("info", "warn", "crit")
SEV_RANK = {"ok": 0, "info": 1, "warn": 2, "crit": 3}
PANEL_TYPES = ("kv", "table", "spark")

MAX_STR = 512
MAX_PANELS = 8
MAX_ITEMS = 50
MAX_COLUMNS = 12
MAX_ROWS = 200
MAX_DETAIL = 40          # k / v pairs per table row, shown on enter
MAX_SPARK = 120
MAX_EVENTS = 100
MIN_INTERVAL = 1.0

NAME_RE = re.compile(r"[a-z0-9_]+")


class InvalidSnapshot(ValueError):
    pass


def worst(*sevs: str) -> str:
    """Highest severity of the given ones. Empty -> ok."""
    return max(sevs, key=SEV_RANK.__getitem__, default="ok")


# --- module object --------------------------------------------------------

def check_module(mod) -> None:
    """Raise ValueError if mod does not follow the module API."""
    name = getattr(mod, "NAME", None)
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise ValueError(f"{mod!r}: NAME must match [a-z0-9_]+")
    interval = getattr(mod, "INTERVAL", None)
    if not _is_num(interval) or interval < MIN_INTERVAL:
        raise ValueError(f"{name}: INTERVAL must be a number >= {MIN_INTERVAL}")
    for fn in ("init", "collect"):
        if not callable(getattr(mod, fn, None)):
            raise ValueError(f"{name}: {fn}() missing")
    close = getattr(mod, "close", None)
    if close is not None and not callable(close):
        raise ValueError(f"{name}: close is not callable")


# --- helpers --------------------------------------------------------------

def _is_num(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


def _str(d: dict, key: str, where: str, default: str | None = None) -> str:
    v = d.get(key, default)
    if not isinstance(v, str):
        raise InvalidSnapshot(f"{where}.{key}: str required")
    return truncate(v, MAX_STR)


def _list(d: dict, key: str, where: str) -> list:
    v = d.get(key)
    if not isinstance(v, list):
        raise InvalidSnapshot(f"{where}.{key}: list required")
    return v


def _dict(x, where: str) -> dict:
    if not isinstance(x, dict):
        raise InvalidSnapshot(f"{where}: dict required")
    return x


def _choice(d: dict, key: str, allowed: tuple, where: str, default: str | None = None) -> str:
    v = d.get(key, default)
    if v not in allowed:
        raise InvalidSnapshot(f"{where}.{key}: one of {', '.join(allowed)}")
    return v


# --- panels ---------------------------------------------------------------

def _kv(p: dict, w: str) -> dict:
    items = []
    for i, it in enumerate(_list(p, "items", w)[:MAX_ITEMS]):
        wi = f"{w}.items[{i}]"
        it = _dict(it, wi)
        items.append({"k": _str(it, "k", wi), "v": _str(it, "v", wi),
                      "sev": _choice(it, "sev", SEVS, wi, "ok")})
    return {"items": items}


def _table(p: dict, w: str) -> dict:
    cols = _list(p, "columns", w)
    if not cols or len(cols) > MAX_COLUMNS:
        raise InvalidSnapshot(f"{w}.columns: 1..{MAX_COLUMNS} required")
    if not all(isinstance(c, str) for c in cols):
        raise InvalidSnapshot(f"{w}.columns: str required")
    rows = []
    for i, r in enumerate(_list(p, "rows", w)[:MAX_ROWS]):
        wr = f"{w}.rows[{i}]"
        r = _dict(r, wr)
        cells = _list(r, "cells", wr)
        if len(cells) != len(cols) or not all(isinstance(c, str) for c in cells):
            raise InvalidSnapshot(f"{wr}.cells: {len(cols)} str required")
        row = {"cells": [truncate(c, MAX_STR) for c in cells],
               "sev": _choice(r, "sev", SEVS, wr, "ok")}
        if "detail" in r:
            row["detail"] = _detail(r, wr)
        rows.append(row)
    return {"columns": [truncate(c, MAX_STR) for c in cols], "rows": rows}


def _detail(r: dict, w: str) -> list:
    out = []
    for i, it in enumerate(_list(r, "detail", w)[:MAX_DETAIL]):
        wi = f"{w}.detail[{i}]"
        it = _dict(it, wi)
        out.append({"k": _str(it, "k", wi), "v": _str(it, "v", wi)})
    return out


def _spark(p: dict, w: str) -> dict:
    vals = _list(p, "values", w)
    if not all(_is_num(v) for v in vals):
        raise InvalidSnapshot(f"{w}.values: finite numbers required")
    return {"values": vals[-MAX_SPARK:], "unit": _str(p, "unit", w, "")}


_PANEL = {"kv": _kv, "table": _table, "spark": _spark}


def _panel(p, i: int, seen: set) -> dict:
    w = f"panels[{i}]"
    p = _dict(p, w)
    pid = _str(p, "id", w)
    if pid in seen:
        raise InvalidSnapshot(f"{w}.id: duplicate {pid!r}")
    seen.add(pid)
    ptype = _choice(p, "type", PANEL_TYPES, w)
    out = {"id": pid, "title": _str(p, "title", w), "type": ptype,
           "sev": _choice(p, "sev", SEVS, w, "ok")}
    out.update(_PANEL[ptype](p, w))
    return out


# --- events ---------------------------------------------------------------

def _event(e, i: int) -> dict:
    w = f"events[{i}]"
    e = _dict(e, w)
    ts = e.get("ts")
    if not _is_num(ts) or ts < 0:
        raise InvalidSnapshot(f"{w}.ts: epoch seconds required")
    return {"ts": float(ts), "sev": _choice(e, "sev", EVENT_SEVS, w),
            "code": _str(e, "code", w), "msg": _str(e, "msg", w)}


# --- snapshot -------------------------------------------------------------

def validate(snap) -> dict:
    """Return a normalized copy of snap, or raise InvalidSnapshot."""
    try:
        json.dumps(snap, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as e:
        raise InvalidSnapshot(f"not JSON-serializable: {e}") from None

    snap = _dict(snap, "snapshot")
    v = snap.get("v")
    if type(v) is not int or v != 1:
        raise InvalidSnapshot("v: 1 required")

    seen: set = set()
    panels = [_panel(p, i, seen)
              for i, p in enumerate(_list(snap, "panels", "snapshot")[:MAX_PANELS])]
    events = _list(snap, "events", "snapshot")[-MAX_EVENTS:]
    return {
        "v": 1,
        "status": _choice(snap, "status", STATUSES, "snapshot"),
        "summary": _str(snap, "summary", "snapshot"),
        "panels": panels,
        "events": [_event(e, i) for i, e in enumerate(events)],
    }
