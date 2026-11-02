"""State files between sectop's parts (docs/architecture.md, Privilege split).

- /run/sectop/state.json: collector -> UI (module view, feed, alerts)
- /run/sectop-net/<name>.json: net unit -> collector (core/netd.py)

One JSON file, replaced whole: written to a temp file in the same directory,
then renamed over the old one (rename(2) is atomic), so a reader sees the old
or the new file, never a half one.

Reading: same file checks as the config (core/config.py, read_file): owner,
not group/other writable, regular file, no symlink, size. The content is
never trusted: check_state() validates every field the UI draws, with the
Snapshot rules of core/module.py. The writer is a less trusted process.
"""

import json
import os
import re

from core import alerts as alertsmod
from core import module as m
from core.config import ConfigError, read_file
from core.sanitize import truncate

VERSION = 1
MAX_SIZE = 8 * 1024 * 1024
MAX_MODULES = 32
MAX_FEED = 500
MAX_FLAGS = 20
MAX_COUNT = 10 ** 12
# [ / { nesting: state.json and the net unit's nft JSON stay under ~12. Checked before
# json.loads, not left to RecursionError: how deep json.loads gets depends on the build
# (3.14 checks the C stack: a CI runner parsed 100000 levels, my host did not).
MAX_DEPTH = 64
_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')
_NOT_BRACKET = re.compile(r"[^\[\]{}]+")
VIEW_STATUSES = m.STATUSES + ("off",)
ALERT_STATES = ("open", "held")


class StateError(ValueError):
    pass


def encode(obj) -> bytes:
    """Compact JSON, ASCII only. NaN / Infinity / not serializable -> StateError."""
    try:
        return json.dumps(obj, separators=(",", ":"), allow_nan=False).encode("ascii")
    except (TypeError, ValueError, RecursionError) as e:
        raise StateError(f"not JSON-serializable: {e}") from None


def write(path: str, obj, mode: int = 0o640) -> None:
    """Replace path with obj as JSON. mode is set with fchmod: umask does not matter."""
    data = encode(obj)
    d, name = os.path.split(os.path.abspath(path))
    tmp = os.path.join(d, f".{name}.tmp")
    try:
        os.unlink(tmp)                  # left over from a crash
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 mode)
    try:
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
    finally:
        os.close(fd)
    os.replace(tmp, path)


def depth(text: str) -> int:
    """Deepest [ / { nesting outside JSON strings (brackets only, no validation)."""
    deepest = level = 0
    for ch in _NOT_BRACKET.sub("", _STRING.sub("", text)):
        if ch in "[{":
            level += 1
            deepest = max(deepest, level)
        else:
            level -= 1
    return deepest


def load(path: str, owner_uid: int, max_size: int = MAX_SIZE):
    """-> parsed JSON, None if the file is missing. Unsafe file or bad JSON -> StateError."""
    try:
        data = read_file(path, owner_uid, max_size)
    except ConfigError as e:
        raise StateError(str(e)) from None
    if data is None:
        return None
    try:
        text = data.decode("utf-8")
        if depth(text) > MAX_DEPTH:
            raise StateError(f"{path}: bad JSON: nested deeper than {MAX_DEPTH}")
        return json.loads(text)
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise StateError(f"{path}: bad JSON: {e}") from None


# --- state.json -----------------------------------------------------------

def state(ts: float, interval: float, view: list, feed: list, alerts: list) -> dict:
    """What the collector writes. interval = longest time between two writes outside a
    collect (core/collector.py period(); UI: stale limit)."""
    return {"v": VERSION, "ts": ts, "interval": interval, "modules": view,
            "feed": feed[:MAX_FEED], "alerts": alerts}


def _num(d: dict, key: str, where: str, lo: float = 0.0) -> float:
    v = d.get(key)
    if not m._is_num(v) or v < lo:
        raise StateError(f"{where}.{key}: number >= {lo:g} required")
    return float(v)


def _bool(d: dict, key: str, where: str, default: bool = False) -> bool:
    v = d.get(key, default)
    if not isinstance(v, bool):
        raise StateError(f"{where}.{key}: true or false required")
    return v


def _text(d: dict, key: str, where: str, default: str | None = None) -> str:
    v = d.get(key, default)
    if not isinstance(v, str):
        raise StateError(f"{where}.{key}: str required")
    return truncate(v, m.MAX_STR)


def _list(d: dict, key: str, where: str, limit: int) -> list:
    v = d.get(key)
    if not isinstance(v, list):
        raise StateError(f"{where}.{key}: list required")
    if len(v) > limit:
        raise StateError(f"{where}.{key}: more than {limit} items")
    return v


def _dict(x, where: str) -> dict:
    if not isinstance(x, dict):
        raise StateError(f"{where}: object required")
    return x


def _name(d: dict, key: str, where: str) -> str:
    v = d.get(key)
    if not isinstance(v, str) or not m.NAME_RE.fullmatch(v):
        raise StateError(f"{where}.{key}: [a-z0-9_]+ required")
    return v


def _module(x, i: int) -> dict:
    w = f"modules[{i}]"
    d = _dict(x, w)
    status = d.get("status")
    if status not in VIEW_STATUSES:
        raise StateError(f"{w}.status: one of {', '.join(VIEW_STATUSES)} required")
    flags = _list(d, "flags", w, MAX_FLAGS)
    if not all(isinstance(f, str) for f in flags):
        raise StateError(f"{w}.flags: str items required")
    try:                                # the Snapshot rules, again, on this side
        panels = m.validate({"v": 1, "status": "ok", "summary": "",
                             "panels": d.get("panels", []), "events": []})["panels"]
    except m.InvalidSnapshot as e:
        raise StateError(f"{w}: {e}") from None
    return {"name": _name(d, "name", w), "status": status,
            "summary": _text(d, "summary", w), "flags": [truncate(f, m.MAX_STR) for f in flags],
            "panels": panels, "stale": _bool(d, "stale", w), "waiting": _bool(d, "waiting", w),
            "engine": _bool(d, "engine", w)}


def _event(x, i: int) -> dict:
    w = f"feed[{i}]"
    d = _dict(x, w)
    try:
        ev = m._event(d, i)
    except m.InvalidSnapshot as e:
        raise StateError(f"{w}: {e}") from None
    return {**ev, "src": _name(d, "src", w)}


def _alert(x, i: int) -> dict:
    w = f"alerts[{i}]"
    d = _dict(x, w)
    module = _name(d, "module", w)
    key = d.get("key")
    if not isinstance(key, str) or not key.startswith(module + "/") \
            or not m.KEY_RE.fullmatch(key[len(module) + 1:]):
        raise StateError(f"{w}.key: <module>/<check key> required")
    sev = d.get("sev")
    if sev not in m.CHECK_SEVS:
        raise StateError(f"{w}.sev: one of {', '.join(m.CHECK_SEVS)} required")
    count = d.get("count")
    if type(count) is not int or not 1 <= count <= MAX_COUNT:
        raise StateError(f"{w}.count: int 1..{MAX_COUNT} required")
    if d.get("state") not in ALERT_STATES:
        raise StateError(f"{w}.state: open or held required")
    noise = d.get("noise")
    if noise is not None and not isinstance(noise, str):
        raise StateError(f"{w}.noise: str or null required")
    hold = _num(d, "hold", w)
    if hold > m.MAX_HOLD:
        raise StateError(f"{w}.hold: max {m.MAX_HOLD:g}")
    return {"key": key, "module": module, "sev": sev, "title": _text(d, "title", w),
            "detail": _text(d, "detail", w, ""), "count": count,
            "first": _num(d, "first", w), "since": _num(d, "since", w),
            "last": _num(d, "last", w), "hold": hold, "true": _bool(d, "true", w),
            "state": d["state"], "noise": None if noise is None else truncate(noise, m.MAX_STR)}


def check_state(doc) -> dict:
    """Validated, normalized copy of a state.json document. Anything wrong -> StateError."""
    d = _dict(doc, "state")
    if type(d.get("v")) is not int or d["v"] != VERSION:
        raise StateError(f"state.v: {VERSION} required")
    return {
        "v": VERSION,
        "ts": _num(d, "ts", "state"),
        "interval": _num(d, "interval", "state", m.MIN_INTERVAL),
        "modules": [_module(x, i) for i, x in
                    enumerate(_list(d, "modules", "state", MAX_MODULES))],
        "feed": [_event(x, i) for i, x in enumerate(_list(d, "feed", "state", MAX_FEED))],
        "alerts": [_alert(x, i) for i, x in
                   enumerate(_list(d, "alerts", "state", alertsmod.MAX_RECORDS))],
    }
