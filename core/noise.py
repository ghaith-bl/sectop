"""Noise list: /etc/sectop/noise.toml (docs/architecture.md, Alerts).

Alerts I know and accept, kept out of the alert bar. Like an Alertmanager
silence: matcher, reason, end. A noise alert is still tracked by the engine
(count, last seen) and shown as noise, never dropped.

Same file checks as config.toml (core/config.py, read_file). Missing file ->
no entries. Anything wrong -> ConfigError, sectop refuses to start.

    [[noise]]
    match = "firewall/new:out_disco"   # glob on the alert key
    reason = "Steam LAN discovery, blocked by hostfw anyway"
    expires = 2026-12-31            # last day it applies (local date)

- match: fnmatch glob, case-sensitive, on "<module>/<check key>". The module
  part is literal, so one entry never covers all modules.
- expires: required TOML local date. After that day the entry stops matching
  and the alert shows again (forces a review).
"""

import datetime
import fnmatch
import re
import tomllib
from dataclasses import dataclass

from core.config import ConfigError, read_file
from core.module import NAME_RE

DEFAULT_PATH = "/etc/sectop/noise.toml"
MAX_ENTRIES = 200
MAX_REASON = 200
KEYS = {"match", "reason", "expires"}
GLOB_RE = re.compile(r"[A-Za-z0-9_.:/@%+*?\[\]!-]{1,128}")   # key chars + glob


@dataclass(frozen=True)
class Entry:
    match: str
    reason: str
    expires: datetime.date


def reason(entries, key: str, now: float) -> str | None:
    """Reason of the first entry that matches `key` at `now` (epoch s), else None."""
    today = datetime.date.fromtimestamp(now)
    for e in entries:
        if today <= e.expires and fnmatch.fnmatchcase(key, e.match):
            return e.reason
    return None


def _entry(t, i: int, path: str) -> Entry:
    w = f"{path}: noise[{i}]"
    if not isinstance(t, dict):
        raise ConfigError(f"{w}: table required ([[noise]])")
    unknown = set(t) - KEYS
    if unknown:
        raise ConfigError(f"{w}: unknown key(s): {', '.join(sorted(unknown))}")
    match = t.get("match")
    if not isinstance(match, str) or not GLOB_RE.fullmatch(match):
        raise ConfigError(f"{w}.match: 1..128 of alert key chars and * ? [ ] ! required")
    mod, sep, rest = match.partition("/")
    if not sep or not rest or not NAME_RE.fullmatch(mod):
        raise ConfigError(f"{w}.match: <module>/<key glob> required, module part literal")
    why = t.get("reason")
    if not isinstance(why, str) or not why.strip() or len(why) > MAX_REASON:
        raise ConfigError(f"{w}.reason: text of 1..{MAX_REASON} chars required")
    exp = t.get("expires")
    if type(exp) is not datetime.date:            # a datetime is a date subclass: refused
        raise ConfigError(f"{w}.expires: date required (expires = 2026-12-31)")
    return Entry(match, why, exp)


def parse(data: bytes, path: str = DEFAULT_PATH) -> tuple:
    try:
        doc = tomllib.loads(data.decode("utf-8"))
    except UnicodeDecodeError:
        raise ConfigError(f"{path}: not UTF-8") from None
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: {e}") from None
    unknown = set(doc) - {"noise"}
    if unknown:
        raise ConfigError(f"{path}: unknown key(s): {', '.join(sorted(unknown))}")
    items = doc.get("noise", [])
    if not isinstance(items, list):
        raise ConfigError(f"{path}: noise: array of tables required ([[noise]])")
    if len(items) > MAX_ENTRIES:
        raise ConfigError(f"{path}: more than {MAX_ENTRIES} entries")
    return tuple(_entry(t, i, path) for i, t in enumerate(items))


def load(path: str = DEFAULT_PATH, owner_uid: int = 0) -> tuple:
    """owner_uid is 0 in production; tests pass their own uid."""
    data = read_file(path, owner_uid)
    return () if data is None else parse(data, path)
