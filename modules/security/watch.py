"""Watch list: /etc/sectop/watch.toml (docs/modules/security.md, Watch list).

Rates the root commands of the commands box: crit / warn / info, no rule = ok. Same
file checks as config.toml (core/config.py, read_file): root-owned, not group / other
writable, no symlink. Missing file -> None (no rules, every row ok). Anything wrong ->
ConfigError: init fails, the security module is off and its header says why. Read once
at start (restart sectop.service after a change). Defaults: deploy/watch.toml.

    [[rule]]
    id = "selinux-permissive"           # [a-z0-9-], 1..32, unique: alert key, noise match
    sev = "crit"                        # crit | warn | info
    cmd = "setenforce 0|[Pp]ermissive"  # program, then words
    why = "SELinux to permissive"

- cmd: words split on spaces. The first word is the program: the exe name, the argv[0]
  name, or the script an interpreter runs (`bash /usr/local/sbin/hostfw observe` ->
  hostfw). Every other word must match one argument, in any order; `!word`: no
  argument may match. In a word `a|b` = either, each a glob (fnmatch, case-sensitive:
  `*` `?` `[...]`).
- The highest sev wins, then the first rule in the file.
"""

import fnmatch
import os
import re
import tomllib
from dataclasses import dataclass

from core.config import ConfigError, read_file

DEFAULT_PATH = "/etc/sectop/watch.toml"
SEVS = ("info", "warn", "crit")
RANK = {s: i for i, s in enumerate(SEVS)}
MAX_RULES = 200
MAX_WORDS = 16
MAX_CMD = 200
MAX_WHY = 120
KEYS = {"id", "sev", "cmd", "why"}
ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
CMD_RE = re.compile(r"[\x20-\x7e]+")           # printable ASCII
WHY_RE = re.compile(r"[\x20-\x7e]+")
# A script run by one of these: its name is the program too.
INTERPRETERS = frozenset({"env", "sh", "bash", "dash", "zsh", "python3", "python", "perl"})


@dataclass(frozen=True)
class Rule:
    id: str
    sev: str
    cmd: str
    why: str
    prog: tuple            # globs, either
    need: tuple            # per word: globs, either; each word must match an argument
    deny: tuple            # per !word: globs, either; none may match an argument


def _walk(exe: str, argv: list) -> tuple:
    """-> (program names, index of the program in argv: the script after interpreters)."""
    names = {os.path.basename(exe)} if exe else set()
    if argv:
        names.add(os.path.basename(argv[0]))
    start = 0
    if names & INTERPRETERS:
        for i in range(1, len(argv)):
            a = argv[i]
            if a.startswith("-") or "=" in a.split("/", 1)[0]:
                continue                       # options, env VAR=value
            b = os.path.basename(a)
            names.add(b)
            if b not in INTERPRETERS:          # env bash script: go on to the script
                start = i
                break
    names.discard("")
    return names, start


def programs(exe: str, argv: list) -> set:
    """Names a rule's program word is matched against."""
    return _walk(exe, argv)[0]


def command(exe: str, argv: list) -> list:
    """argv from the program on: `env bash /usr/local/sbin/hostfw observe` ->
    `/usr/local/sbin/hostfw observe` (one alert for the env and the bash exec)."""
    return argv[_walk(exe, argv)[1]:]


def _hit(args: list, globs: tuple) -> bool:
    return any(fnmatch.fnmatchcase(a, g) for g in globs for a in args)


def matches(rule: Rule, names: set, args: list) -> bool:
    if not any(fnmatch.fnmatchcase(n, g) for g in rule.prog for n in names):
        return False
    return all(_hit(args, w) for w in rule.need) and not any(_hit(args, w) for w in rule.deny)


def rate(rules: tuple, exe: str, argv: list) -> Rule | None:
    """The rule for this command: highest sev, then first in the file. None = ok."""
    if not rules:
        return None
    names, args, best = programs(exe, argv), argv[1:], None
    for r in rules:
        if best is not None and RANK[r.sev] <= RANK[best.sev]:
            continue
        if matches(r, names, args):
            best = r
    return best


def _globs(word: str, w: str) -> tuple:
    alts = tuple(word.split("|"))
    if not all(alts):
        raise ConfigError(f"{w}: empty alternative in {word!r}")
    return alts


def _rule(t, i: int, path: str, seen: set) -> Rule:
    w = f"{path}: rule[{i}]"
    if not isinstance(t, dict):
        raise ConfigError(f"{w}: table required ([[rule]])")
    unknown = set(t) - KEYS
    if unknown:
        raise ConfigError(f"{w}: unknown key(s): {', '.join(sorted(unknown))}")
    rid = t.get("id")
    if not isinstance(rid, str) or not ID_RE.fullmatch(rid):
        raise ConfigError(f"{w}.id: 1..32 of a-z 0-9 - required (first not -)")
    if rid in seen:
        raise ConfigError(f"{w}.id: duplicate {rid!r}")
    seen.add(rid)
    w = f"{path}: rule {rid}"
    sev = t.get("sev")
    if sev not in SEVS:
        raise ConfigError(f"{w}.sev: one of {', '.join(SEVS)} required")
    cmd = t.get("cmd")
    if not isinstance(cmd, str) or not CMD_RE.fullmatch(cmd) or len(cmd) > MAX_CMD \
            or not cmd.split():
        raise ConfigError(f"{w}.cmd: program and words, printable ASCII, max {MAX_CMD}")
    words = cmd.split()
    if len(words) > MAX_WORDS:
        raise ConfigError(f"{w}.cmd: more than {MAX_WORDS} words")
    if words[0].startswith("!"):
        raise ConfigError(f"{w}.cmd: the first word is the program, not !word")
    need, deny = [], []
    for word in words[1:]:
        if word.startswith("!"):
            if len(word) == 1:
                raise ConfigError(f"{w}.cmd: ! without a word")
            deny.append(_globs(word[1:], f"{w}.cmd"))
        else:
            need.append(_globs(word, f"{w}.cmd"))
    why = t.get("why")
    if not isinstance(why, str) or not WHY_RE.fullmatch(why) or not why.strip() \
            or len(why) > MAX_WHY:
        raise ConfigError(f"{w}.why: text of 1..{MAX_WHY} printable ASCII chars required")
    return Rule(rid, sev, cmd, why, _globs(words[0], f"{w}.cmd"), tuple(need), tuple(deny))


def parse(data: bytes, path: str = DEFAULT_PATH) -> tuple:
    try:
        doc = tomllib.loads(data.decode("utf-8"))
    except UnicodeDecodeError:
        raise ConfigError(f"{path}: not UTF-8") from None
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: {e}") from None
    unknown = set(doc) - {"rule"}
    if unknown:
        raise ConfigError(f"{path}: unknown key(s): {', '.join(sorted(unknown))}")
    items = doc.get("rule", [])
    if not isinstance(items, list):
        raise ConfigError(f"{path}: rule: array of tables required ([[rule]])")
    if len(items) > MAX_RULES:
        raise ConfigError(f"{path}: more than {MAX_RULES} rules")
    seen: set = set()
    return tuple(_rule(t, i, path, seen) for i, t in enumerate(items))


def load(path: str = DEFAULT_PATH, owner_uid: int = 0) -> tuple | None:
    """-> rules, None when the file is missing. owner_uid is 0 in production."""
    data = read_file(path, owner_uid)
    return None if data is None else parse(data, path)
