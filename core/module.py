"""Module contract: check module objects and validate Snapshots.

See docs/module-interface.md. validate() returns a new, normalized
Snapshot (known keys only, defaults filled, limits applied) or raises
InvalidSnapshot. Core never draws a Snapshot that did not pass here.
Context is the second argument of collect().
"""

import inspect
import ipaddress
import json
import math
import re
from dataclasses import dataclass

from core import journal
from core.sanitize import truncate

VERSIONS = (1, 2)       # v2 = v1 + checks
STATUSES = ("ok", "info", "warn", "crit", "unknown")
SEVS = ("ok", "info", "warn", "crit")
EVENT_SEVS = ("info", "warn", "crit")
CHECK_SEVS = ("info", "warn", "crit")   # a check is a problem that is true now
SEV_RANK = {"ok": 0, "info": 1, "warn": 2, "crit": 3}
PANEL_TYPES = ("kv", "table", "spark")
WIDTHS = ("auto", "full")                # panel layout hint: full = a grid row of its own
TONES = ("plain", "red", "blue", "yellow", "green", "dim")   # optional hint, not severity
COL_TYPES = ("text", "num", "age", "spark")   # table column hint: num / age / spark right;
                                              # age = epoch s, spark = numbers as text

ROLES = ("name", "text", "value", "peak", "note")   # table column colors (ok rows)
LEVELS = ("high",)                       # row level: its value cells near their limit
MAX_STR = 512
MAX_PANELS = 8
MAX_ITEMS = 50
MAX_COLUMNS = 12
MAX_ROWS = 200
MAX_DETAIL = 40          # k / v pairs per table row, shown on enter
MAX_SPARK = 120
MAX_SPARK_CELL = 60      # values in a spark cell (a cell is at most MAX_STR chars)
MAX_EVENTS = 100
MAX_CHECKS = 50
MAX_N = 10 ** 9
MAX_HOLD = 3600.0
MIN_INTERVAL = 1.0

NAME_RE = re.compile(r"[a-z0-9_]+")
PICK_RE = re.compile(r"[ -~]{1,60}")    # row filter: printable ASCII, the filter prompt's chars
PROG_RE = re.compile(r"[\x21-\x7e]{1,64}")         # row progs: program names (core/proc.py)
LOGS_RE = re.compile(r"[a-z][a-z0-9_]{0,39}")      # row logs: rule name (core/logs.py)
REF_RE = re.compile(r"[\x20-\x7e]{1,200}")          # row ref: one flow across boxes
MAX_PROGS = 5
KEY_RE = re.compile(r"[A-Za-z0-9_.:/@%+-]{1,128}")    # check key: rule + subject


class InvalidSnapshot(ValueError):
    pass


@dataclass(frozen=True)
class Context:
    """What core gives collect(state, ctx) besides the module's own state."""
    journal: tuple = ()          # entries since the last collect (module with JOURNAL)
    journal_up: bool = False     # the follower runs (core/journal.py)
    journal_note: str = ""       # what went wrong since the last collect, "" = nothing


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
    try:
        inspect.signature(mod.collect).bind(None, None)
    except TypeError:
        raise ValueError(f"{name}: collect(state, ctx) required") from None
    close = getattr(mod, "close", None)
    if close is not None and not callable(close):
        raise ValueError(f"{name}: close is not callable")
    if getattr(mod, "JOURNAL", None) is not None:
        try:
            journal.spec(mod.JOURNAL)
        except ValueError as e:
            raise ValueError(f"{name}: {e}") from None


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
        item = {"k": _str(it, "k", wi), "v": _str(it, "v", wi),
                "sev": _choice(it, "sev", SEVS, wi, "ok")}
        _tone(it, item, wi)
        _ip(it, item, wi)
        items.append(item)
    return {"items": items}


def _ip(src: dict, out: dict, w: str) -> None:
    """Optional `ip`: the address of this line, core can look it up (whois)."""
    if "ip" in src:
        v = src["ip"]
        try:
            out["ip"] = str(ipaddress.ip_address(v)) if isinstance(v, str) else None
        except ValueError:
            out["ip"] = None
        if out["ip"] is None:
            raise InvalidSnapshot(f"{w}.ip: IP address required")


def _tone(src: dict, out: dict, w: str) -> None:
    """Optional `tone`: copied only when given."""
    if "tone" in src:
        out["tone"] = _choice(src, "tone", TONES, w)


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
        _tone(r, row, wr)
        _ip(r, row, wr)
        if "level" in r:                 # value cells near their limit (orange)
            row["level"] = _choice(r, "level", LEVELS, wr)
        if "id" in r:                    # stable row key: the cursor follows it
            row["id"] = _str(r, "id", wr)
        if "ref" in r:                   # one flow / event across boxes: alerts view merges
            v = r["ref"]
            if not isinstance(v, str) or not REF_RE.fullmatch(v):
                raise InvalidSnapshot(f"{wr}.ref: 1..200 printable ASCII chars required")
            row["ref"] = v
        if "filter" in r:                # f follow / x hide (core/ui.py)
            v = r["filter"]
            if not isinstance(v, str) or not PICK_RE.fullmatch(v) or not v.strip():
                raise InvalidSnapshot(f"{wr}.filter: 1..60 printable ASCII chars required")
            row["filter"] = v
        if "progs" in r:                 # c = program card (core/ui.py, docs: Rows)
            v = r["progs"]
            if not isinstance(v, list) or not 1 <= len(v) <= MAX_PROGS or not all(
                    isinstance(x, str) and PROG_RE.fullmatch(x) for x in v):
                raise InvalidSnapshot(f"{wr}.progs: 1..{MAX_PROGS} names of 1..64 printable "
                                      "ASCII chars, no space, required")
            row["progs"] = list(v)
        if "logs" in r:                  # enter = log card of this rule (core/logs.py)
            v = r["logs"]
            if not isinstance(v, str) or not LOGS_RE.fullmatch(v):
                raise InvalidSnapshot(f"{wr}.logs: rule name [a-z][a-z0-9_]{{0,39}} required")
            row["logs"] = v
        if "detail" in r:
            row["detail"] = _detail(r, wr)
        rows.append(row)
    out = {"columns": [truncate(c, MAX_STR) for c in cols], "rows": rows}
    if "types" in p:
        types = _list(p, "types", w)
        if len(types) != len(cols) or not all(t in COL_TYPES for t in types):
            raise InvalidSnapshot(f"{w}.types: {len(cols)} of {', '.join(COL_TYPES)} required")
        for i, row in enumerate(rows):
            for j, t in enumerate(types):
                if t == "age" and not _epoch(row["cells"][j]):
                    raise InvalidSnapshot(f"{w}.rows[{i}].cells[{j}]: epoch seconds or - "
                                          "required (age column)")
                if t == "spark" and spark_cell(row["cells"][j]) is None:
                    raise InvalidSnapshot(f"{w}.rows[{i}].cells[{j}]: numbers, optional "
                                          f"/top, max {MAX_SPARK_CELL} required (spark column)")
        out["types"] = list(types)
    if "roles" in p:
        roles = _list(p, "roles", w)
        if len(roles) != len(cols) or not all(x in ROLES for x in roles):
            raise InvalidSnapshot(f"{w}.roles: {len(cols)} of {', '.join(ROLES)} required")
        out["roles"] = list(roles)
    return out


def _epoch(cell: str) -> bool:
    """Age cell: epoch seconds as text, or - / empty for none."""
    if cell in ("", "-"):
        return True
    try:
        v = float(cell)
    except ValueError:
        return False
    return math.isfinite(v) and v >= 0


def spark_cell(cell: str):
    """Spark cell: values as text, space separated, optional `/top` (scale), e.g.
    "35 36 37/100". -> (values, top or None); "" -> ([], None); bad -> None.
    The scale starts at 0 (or the lowest value if below 0) and ends at top, else at
    the highest value."""
    body, sep, top = cell.partition("/")
    try:
        vals = [float(x) for x in body.split()]
        hi = float(top) if sep else None
    except ValueError:
        return None
    if len(vals) > MAX_SPARK_CELL or not all(math.isfinite(v) for v in vals):
        return None
    if hi is not None and not (math.isfinite(hi) and hi > 0):
        return None
    return vals, hi


def _detail(r: dict, w: str) -> list:
    out = []
    for i, it in enumerate(_list(r, "detail", w)[:MAX_DETAIL]):
        wi = f"{w}.detail[{i}]"
        it = _dict(it, wi)
        item = {"k": _str(it, "k", wi), "v": _str(it, "v", wi)}
        if "sev" in it:                  # a problem line: shown in its color
            item["sev"] = _choice(it, "sev", SEVS, wi)
        out.append(item)
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
           "sev": _choice(p, "sev", SEVS, w, "ok"),
           "width": _choice(p, "width", WIDTHS, w, "auto")}
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


# --- checks (v2) ----------------------------------------------------------

def _check(c, i: int, seen: set) -> dict:
    w = f"checks[{i}]"
    c = _dict(c, w)
    key = c.get("key")
    if not isinstance(key, str) or not KEY_RE.fullmatch(key):
        raise InvalidSnapshot(f"{w}.key: 1..128 of A-Z a-z 0-9 _ . : / @ % + - required")
    if key in seen:
        raise InvalidSnapshot(f"{w}.key: duplicate {key!r}")
    seen.add(key)
    n = c.get("n", 0)
    if type(n) is not int or not 0 <= n <= MAX_N:
        raise InvalidSnapshot(f"{w}.n: int 0..{MAX_N} required")
    out = {"key": key, "sev": _choice(c, "sev", CHECK_SEVS, w),
           "title": _str(c, "title", w), "detail": _str(c, "detail", w, ""), "n": n}
    if "hold" in c:
        hold = c["hold"]
        if not _is_num(hold) or not 0 <= hold <= MAX_HOLD:
            raise InvalidSnapshot(f"{w}.hold: seconds 0..{MAX_HOLD:g} required")
        out["hold"] = float(hold)
    if "at" in c:                    # event check: time of its newest occurrence
        at = c["at"]
        if not _is_num(at) or at < 0:
            raise InvalidSnapshot(f"{w}.at: epoch seconds required")
        out["at"] = float(at)
    return out


def _checks(snap: dict) -> list:
    """All checks validated. Over MAX_CHECKS: the worst kept (stable sort)."""
    seen: set = set()
    checks = [_check(c, i, seen) for i, c in enumerate(_list(snap, "checks", "snapshot"))]
    if len(checks) > MAX_CHECKS:
        checks = sorted(checks, key=lambda c: -SEV_RANK[c["sev"]])[:MAX_CHECKS]
    return checks


# --- snapshot -------------------------------------------------------------

def validate(snap) -> dict:
    """Return a normalized copy of snap, or raise InvalidSnapshot."""
    try:
        json.dumps(snap, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as e:
        raise InvalidSnapshot(f"not JSON-serializable: {e}") from None

    snap = _dict(snap, "snapshot")
    v = snap.get("v")
    if type(v) is not int or v not in VERSIONS:
        raise InvalidSnapshot("v: 1 or 2 required")

    seen: set = set()
    panels = [_panel(p, i, seen)
              for i, p in enumerate(_list(snap, "panels", "snapshot")[:MAX_PANELS])]
    events = _list(snap, "events", "snapshot")[-MAX_EVENTS:]
    checks = _checks(snap) if v == 2 else []
    return {
        "v": v,
        "status": _choice(snap, "status", STATUSES, "snapshot"),
        "summary": _str(snap, "summary", "snapshot"),
        "panels": panels,
        "events": [_event(e, i) for i, e in enumerate(events)],
        "checks": checks,
    }
