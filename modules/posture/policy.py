"""Posture policy: /etc/sectop/posture.toml (docs/modules/posture.md, Policy).

What to check and the value my baseline wants. The file never holds a command: each
kind is fixed code (checks.py), the file picks the kind, its file / unit / values and
the severity. Same file checks as config.toml (core/config.py, read_file): root-owned,
not group / other writable, no symlink. Missing -> None (no checks). Anything wrong ->
ConfigError: init fails, the module is off and its header says why. Read once at start
(restart sectop.service after a change). Defaults: deploy/posture.toml.

    [[check]]
    id = "selinux-enforcing"        # [a-z0-9-], 1..32, unique: alert key, noise match
    kind = "file"                   # see KINDS
    sev = "crit"                    # crit | warn | info: when it fails
    why = "SELinux enforcing now"
    path = "/sys/fs/selinux/enforce"
    want = "1"
    # ref = "..."                   # accepted deviation: shown dim, no alert
"""

import re
import tomllib
from dataclasses import dataclass

from core.config import ConfigError, read_file
from core.netd import IFACE_RE

DEFAULT_PATH = "/etc/sectop/posture.toml"
SEVS = ("info", "warn", "crit")
OPS = ("=", "!=", ">=", "<=", "in")
UNIT_STATES = ("active", "inactive", "failed", "masked", "enabled", "disabled", "static")
COMMON = {"id", "kind", "sev", "why", "ref"}
# kind -> (required keys, optional keys)
KINDS = {
    "file": ({"path", "want"}, {"key", "op"}),
    "lines": ({"path", "want"}, set()),
    "sysctl": ({"values"}, set()),
    "cmdline": ({"want"}, set()),
    "units": ({"units"}, set()),
    "failed-units": (set(), set()),
    "listeners": ({"allow"}, {"wireguard"}),
    "taint": ({"want"}, set()),
    "luks": ({"path"}, set()),
    "secureboot": (set(), set()),
    "lockdown": ({"want"}, set()),
    "audit-rules": ({"want"}, set()),
    "audit-enabled": (set(), set()),
    "uid0": ({"want"}, set()),
    "group": ({"group", "want"}, set()),
    "perms": ({"path", "mode", "owner"}, set()),
    "ostree-unlocked": (set(), set()),
    "ostree-staged": (set(), set()),
    "ostree-age": ({"max_days"}, set()),
    "ostree-gpg": (set(), set()),
    "firewalld-zone": ({"want"}, set()),
    "wifi-ipv6": ({"want"}, set()),
}
MAX_CHECKS = 100
MAX_ITEMS = 64                      # values / units / lines / allow / want lists
ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
TEXT_RE = re.compile(r"[\x20-\x7e]+")         # printable ASCII
PATH_RE = re.compile(r"/[A-Za-z0-9_.@%+:/-]{0,200}")
NAME_RE = re.compile(r"[A-Za-z0-9_.@:-]{1,128}")
SYSCTL_RE = re.compile(r"[a-z0-9_]+(?:\.[A-Za-z0-9_-]+)+")
MODE_RE = re.compile(r"0?[0-7]{1,4}")
OWNER_RE = re.compile(r"[a-z_][a-z0-9_-]*:[a-z_][a-z0-9_-]*")
MAX_TEXT = 200


@dataclass(frozen=True)
class Check:
    id: str
    kind: str
    sev: str
    why: str
    ref: str = ""
    path: str = ""
    key: str = ""
    op: str = "="
    want: object = None             # str, int or tuple of str (per kind)
    values: tuple = ()              # sysctl: ((key, want), ...)
    units: tuple = ()               # units: ((unit, state), ...)
    allow: tuple = ()               # listeners: "proto addr:port" globs
    group: str = ""
    mode: int = 0
    owner: str = ""
    max_days: int = 0
    wireguard: str = ""             # listeners: tunnel whose listen-port is allowed


def _text(v, w: str, most: int = MAX_TEXT, empty: bool = False) -> str:
    if not isinstance(v, str) or len(v) > most or (v and not TEXT_RE.fullmatch(v)) \
            or (not empty and not v.strip()):
        raise ConfigError(f"{w}: text of 1..{most} printable ASCII chars required")
    return v


def _texts(v, w: str, empty: bool = True) -> tuple:
    if not isinstance(v, list) or len(v) > MAX_ITEMS or (not empty and not v):
        raise ConfigError(f"{w}: list of 0..{MAX_ITEMS} strings required")
    return tuple(_text(x, f"{w}[{i}]") for i, x in enumerate(v))


def _table(v, w: str) -> dict:
    if not isinstance(v, dict) or not 1 <= len(v) <= MAX_ITEMS:
        raise ConfigError(f"{w}: table of 1..{MAX_ITEMS} entries required")
    return v


def _check(t, i: int, path: str, seen: set) -> Check:
    w = f"{path}: check[{i}]"
    if not isinstance(t, dict):
        raise ConfigError(f"{w}: table required ([[check]])")
    cid = t.get("id")
    if not isinstance(cid, str) or not ID_RE.fullmatch(cid):
        raise ConfigError(f"{w}.id: 1..32 of a-z 0-9 - required (first not -)")
    if cid in seen:
        raise ConfigError(f"{w}.id: duplicate {cid!r}")
    seen.add(cid)
    w = f"{path}: check {cid}"
    kind = t.get("kind")
    if kind not in KINDS:
        raise ConfigError(f"{w}.kind: one of {', '.join(KINDS)} required")
    need, may = KINDS[kind]
    unknown = set(t) - COMMON - need - may
    if unknown:
        raise ConfigError(f"{w}: unknown key(s) for kind {kind}: {', '.join(sorted(unknown))}")
    missing = need - set(t)
    if missing:
        raise ConfigError(f"{w}: kind {kind} needs {', '.join(sorted(missing))}")
    sev = t.get("sev")
    if sev not in SEVS:
        raise ConfigError(f"{w}.sev: one of {', '.join(SEVS)} required")
    args = {"id": cid, "kind": kind, "sev": sev, "why": _text(t.get("why"), f"{w}.why", 120),
            "ref": _text(t.get("ref", ""), f"{w}.ref", 120, empty=True)}
    if "path" in t:
        p = t["path"]
        if not isinstance(p, str) or not PATH_RE.fullmatch(p) or "/../" in p + "/":
            raise ConfigError(f"{w}.path: absolute path, A-Z a-z 0-9 _ . @ % + : / -")
        args["path"] = p
    if "key" in t:
        args["key"] = _text(t["key"], f"{w}.key", 64)
    if "op" in t:
        if t["op"] not in OPS:
            raise ConfigError(f"{w}.op: one of {' '.join(OPS)} required")
        args["op"] = t["op"]
    if kind in ("file", "taint", "lockdown", "firewalld-zone", "wifi-ipv6"):
        args["want"] = _text(t["want"], f"{w}.want", 120, empty=kind == "taint")
        if args.get("op") in (">=", "<=") and not re.fullmatch(r"-?\d+", args["want"]):
            raise ConfigError(f"{w}.want: a whole number required with op {args['op']}")
    elif kind in ("lines", "cmdline", "uid0", "group"):
        args["want"] = _texts(t["want"], f"{w}.want", empty=kind == "group")
    elif kind == "audit-rules":
        n = t["want"]
        if type(n) is not int or not 0 <= n <= 100000:
            raise ConfigError(f"{w}.want: whole number 0..100000 required")
        args["want"] = n
    if kind == "sysctl":
        vals = []
        for k, v in _table(t["values"], f"{w}.values").items():
            if not SYSCTL_RE.fullmatch(k) or not isinstance(v, str) or not TEXT_RE.fullmatch(v):
                raise ConfigError(f"{w}.values.{k}: sysctl name = \"value\" required")
            vals.append((k, v))
        args["values"] = tuple(vals)
    if kind == "units":
        us = []
        for k, v in _table(t["units"], f"{w}.units").items():
            if not NAME_RE.fullmatch(k) or k.startswith("-") or v not in UNIT_STATES:
                raise ConfigError(f"{w}.units.{k}: unit = one of {', '.join(UNIT_STATES)}")
            us.append((k, v))
        args["units"] = tuple(us)
    if kind == "listeners":
        allow = _texts(t["allow"], f"{w}.allow")
        for a in allow:
            if not re.fullmatch(r"(tcp|udp) \S+:\S+", a):
                raise ConfigError(f"{w}.allow: \"tcp|udp <addr>:<port>\" required, got {a!r}")
        args["allow"] = allow
        wgi = t.get("wireguard", "")
        if not isinstance(wgi, str) or (wgi and not IFACE_RE.fullmatch(wgi)):
            raise ConfigError(f"{w}.wireguard: interface name required")
        args["wireguard"] = wgi
    if kind == "group":
        g = t["group"]
        if not isinstance(g, str) or not NAME_RE.fullmatch(g):
            raise ConfigError(f"{w}.group: group name required")
        args["group"] = g
    if kind == "perms":
        m, o = t["mode"], t["owner"]
        if not isinstance(m, str) or not MODE_RE.fullmatch(m):
            raise ConfigError(f"{w}.mode: octal string (\"644\", \"0\") required")
        if not isinstance(o, str) or not OWNER_RE.fullmatch(o):
            raise ConfigError(f"{w}.owner: \"user:group\" required")
        args["mode"], args["owner"] = int(m, 8), o
    if kind == "ostree-age":
        d = t["max_days"]
        if type(d) is not int or not 1 <= d <= 3650:
            raise ConfigError(f"{w}.max_days: whole number 1..3650 required")
        args["max_days"] = d
    return Check(**args)


def parse(data: bytes, path: str = DEFAULT_PATH) -> tuple:
    try:
        doc = tomllib.loads(data.decode("utf-8"))
    except UnicodeDecodeError:
        raise ConfigError(f"{path}: not UTF-8") from None
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: {e}") from None
    unknown = set(doc) - {"check"}
    if unknown:
        raise ConfigError(f"{path}: unknown key(s): {', '.join(sorted(unknown))}")
    items = doc.get("check", [])
    if not isinstance(items, list):
        raise ConfigError(f"{path}: check: array of tables required ([[check]])")
    if len(items) > MAX_CHECKS:
        raise ConfigError(f"{path}: more than {MAX_CHECKS} checks")
    seen: set = set()
    return tuple(_check(t, i, path, seen) for i, t in enumerate(items))


def load(path: str = DEFAULT_PATH, owner_uid: int = 0) -> tuple | None:
    """-> checks, None when the file is missing. owner_uid is 0 in production."""
    data = read_file(path, owner_uid)
    return None if data is None else parse(data, path)
