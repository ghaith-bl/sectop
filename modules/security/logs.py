"""security: logs box (docs/modules/security.md, Logs box).

What the rest of the system logged that the other boxes do not show:
- journal PRIORITY 0..4 of every unit and user unit, not kernel (kernel box), not
  sudo's PRIORITY 1 alerts (auth box). Grouped by identifier + priority + normalized
  message (session-c5.scope and session-c6.scope: the same sudo line).
- audit file watches and exec rules of the hardening rules that no other box reads
  (identity, scope, MAC-policy, sudo_log_file, logins, session, system-locale,
  time-change, perm_chng, usermod, privileged; volume keys mounts, delete, perm_mod,
  access). Grouped by key + exe + file.
- audit SELINUX_ERR (1401): SELinux errors that are not denials (invalid context).

Severity (red = dangerous or suspicious, worth following up; decided 2026-10-25):
- journal: PRIORITY 0-2 crit (alert), 3 warn, 4 info.
- audit keys: a file watch written by the program that owns the file is routine (sudo
  writes the sudo log, NetworkManager its profiles, pam the faillock / lastlog files):
  info. The same file written by any other program: warn. scope (sudoers) and
  MAC-policy (SELinux policy) changes: warn whoever writes. Exec rules and volume
  keys: info. Fixture 2h 2026-10-26: 20 sudo_log_file, 14 logins, 40 session, 12
  system-locale events, all from their owners.
- Own entries (sectop units): tagged own in the from cell, never dropped.
- Noise list (/etc/sectop/noise.toml, core/noise.py): an entry matching
  `security/log:<id>` marks the row noise (dim, reason in the detail) and keeps a crit
  row out of the alert bar (the engine applies the same list). Rows stay, counted.
"""

import collections
import hashlib
import os
import re

from core import audit, noise
from core.journal import values
from core.sanitize import _ADDR

PRIORITIES = {"0": "emerg", "1": "alert", "2": "crit", "3": "err", "4": "warning"}
LOG_SEV = {"0": "crit", "1": "crit", "2": "crit", "3": "warn", "4": "info"}
SELINUX_ERR = 1401
OWN_UNITS = re.compile(r"sectop(-net|-whois@.*)?\.service")
OWN_IDS = ("sectop", "sectop-collector", "sectop-net")
# file watch key -> programs that own those files (exe names); others writing: warn
OWNERS = {
    "sudo_log_file": {"sudo"},
    "logins": {"sudo", "su", "gdm-session-worker", "polkit-agent-helper-1", "pkexec",
               "login", "sshd", "sshd-session", "faillock", "unix_chkpwd"},
    "session": {"sudo", "su", "gdm-session-worker", "gdm", "login", "sshd", "sshd-session",
                "systemd-update-utmp", "systemd-logind"},
    "system-locale": {"NetworkManager", "systemd-hostnamed"},
    "time-change": {"systemd-timedated"},
    "identity": {"systemd-sysusers", "useradd", "usermod", "userdel", "groupadd", "groupmod",
                 "groupdel", "passwd", "chpasswd", "chage", "gpasswd", "newusers", "pwconv",
                 "grpconv"},
}
ALWAYS_WARN = {"scope": "sudoers changed", "MAC-policy": "SELinux policy files changed"}
INFO_KEYS = {"perm_chng", "usermod", "privileged", "mounts", "delete", "perm_mod", "access"}
HANDLED = {"root_cmds", "user_emulation", "kernel_modules"}     # other boxes
MAX_ROWS = 200
MAX_MSGS = 3
MAX_CHECKS = 50
COLUMNS = ["last", "n", "from", "what"]
TYPES = ["age", "num", "text", "text"]

UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
HEX_RE = re.compile(r"\b0x[0-9a-f]+\b|\b[0-9a-f]{12,}\b", re.I)
NUM_RE = re.compile(r"\d+")
SPACE_RE = re.compile(r"\s+")
SCOPE_RE = re.compile(r"session-c?\d+\.scope")
QUOTE_RE = re.compile(r"'[^']*'|\"[^\"]*\"")
TMP_RE = re.compile(r"\.[A-Za-z0-9]{6}$")              # mkstemp suffix: profile.nmconnection.KWXMX3


def normalize(msg: str) -> str:
    """Log line for grouping only: quoted names, UUIDs, IPs, hex, numbers -> placeholders
    (fixture 2026-10-26: 9 appstreamcli lines that differ in the quoted app id = 1 group)."""
    s = QUOTE_RE.sub("<q>", msg)
    s = UUID_RE.sub("<uuid>", s)
    s = _ADDR.sub("<ip>", s)
    s = HEX_RE.sub("<hex>", s)
    s = NUM_RE.sub("#", s)
    return SPACE_RE.sub(" ", s).strip()


class Row:
    def __init__(self, src: str, what: str, sev: str, why: str, ts: float):
        self.src, self.what, self.sev, self.why = src, what, sev, why
        self.n, self.first, self.last = 0, ts, ts
        self.msgs = collections.deque(maxlen=MAX_MSGS)
        self.detail = {}
        self.label = ""                  # check title: priority name or audit key
        self.reported = 0


class Logs:
    def __init__(self, noise=()):
        self.rows = collections.OrderedDict()       # key -> Row, least recent first
        self.noise = tuple(noise)                   # core/noise.py entries
        self.lines = 0                              # journal lines + audit events taken


def _first(v) -> str:
    vs = values(v)
    return vs[0] if vs else ""


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "backslashreplace")).hexdigest()[:12]


def _add(lg: Logs, gkey: str, src: str, what: str, sev: str, why: str, ts: float) -> Row:
    key = "log:" + _digest(gkey)
    r = lg.rows.pop(key, None) or Row(src, what, sev, why, ts)
    lg.rows[key] = r
    while len(lg.rows) > MAX_ROWS:
        lg.rows.popitem(last=False)
    r.n += 1
    r.first, r.last = min(r.first, ts), max(r.last, ts)
    r.what, r.sev, r.why = what, sev, why
    lg.lines += 1
    return r


def _own(e: dict) -> bool:
    unit = _first(e.get("_SYSTEMD_UNIT"))
    return bool(OWN_UNITS.fullmatch(unit)) or _first(e.get("SYSLOG_IDENTIFIER")) in OWN_IDS


def wanted(e: dict) -> bool:
    """Journal entries of this box (not kernel, not audit, not sudo's alerts)."""
    return (e.get("_TRANSPORT") not in ("kernel", "audit") and e.get("PRIORITY") in PRIORITIES
            and not (e.get("SYSLOG_IDENTIFIER") == "sudo" and e.get("PRIORITY") == "1"))


def journal_entry(lg: Logs, e: dict, ts: float) -> None:
    if not wanted(e):
        return
    msg = _first(e.get("MESSAGE"))
    norm = normalize(msg)
    if not norm:
        return
    prio = e["PRIORITY"]
    ident = (_first(e.get("SYSLOG_IDENTIFIER")) or _first(e.get("_COMM"))
             or _first(e.get("_SYSTEMD_UNIT")) or "?")
    own = _own(e)
    src = ident + (" (own)" if own else "")
    r = _add(lg, "\x1f".join(("j", ident, prio, norm)), src, msg, LOG_SEV[prio],
             f"journal {PRIORITIES[prio]} (PRIORITY {prio})", ts)
    if msg in r.msgs:
        r.msgs.remove(msg)
    r.msgs.appendleft(msg)
    r.label = PRIORITIES[prio]
    unit = _first(e.get("_SYSTEMD_UNIT")) or _first(e.get("_SYSTEMD_USER_UNIT")) or "-"
    r.detail = {"priority": f"{prio} {PRIORITIES[prio]}",
                "unit": SCOPE_RE.sub("session-#.scope", unit) if unit != "-" else "-"}
    if _first(e.get("_SYSTEMD_USER_UNIT")):
        r.detail["user unit"] = _first(e.get("_SYSTEMD_USER_UNIT"))
    if own:
        r.detail["own"] = "sectop's own entry: shown, never dropped"


def _path(ev) -> str:
    """The file an audit watch saw: first PATH record that is not the parent dir."""
    best = ""
    for rec in ev.all("PATH"):
        name = audit.text(rec.raw, "name") or ""
        if rec.raw.get("nametype") == "PARENT":
            best = best or name
            continue
        if name:
            return name
    return best or "-"


def _rate(key: str, exe: str) -> tuple:
    base = os.path.basename(exe)
    if key in ALWAYS_WARN:
        return "warn", f"{ALWAYS_WARN[key]} (audit key {key})"
    if key in OWNERS:
        if base in OWNERS[key]:
            return "info", f"audit key {key}: written by its owner {base}"
        return "warn", f"audit key {key}: written by {base or '?'}, not by its owners " \
                       f"({', '.join(sorted(OWNERS[key]))})"
    return "info", f"audit key {key}"


def audit_event(lg: Logs, ev, ts: float, name) -> None:
    """One audit event: a keyed SYSCALL no other box takes, or SELINUX_ERR."""
    for rec in ev.records:
        if rec.type == SELINUX_ERR:
            _selinux_err(lg, rec, ts)
    if ev.kind == "SYSCALL":
        keys = [k for k in ev.keys if k not in HANDLED]
        if not keys or set(ev.keys) & HANDLED:
            return
        key, exe = keys[0], ev.get("exe") or "?"
        path = _path(ev)
        sev, why = _rate(key, exe)
        who = name(ev.get("auid"))
        r = _add(lg, "\x1f".join(("a", key, exe, TMP_RE.sub(".<tmp>", path))), f"audit {key}",
                 f"{os.path.basename(exe)} {path}", sev, why, ts)
        r.label = key
        ok = "ok" if ev.get("success") != "no" else "failed"
        r.detail = {"exe": exe, "file": path, "login": who,
                    "syscall": f"{ev.get('syscall') or '?'} {ok}",
                    "pid": ev.get("pid") or "-", "cmdline": ev.proctitle or "-"}


def _selinux_err(lg: Logs, rec, ts: float) -> None:
    op = rec.raw.get("op") or "?"
    ctx = audit.text(rec.raw, "invalid_context") or ""
    ctype = ctx.split(":")[2] if ctx.count(":") >= 2 else ctx or "?"
    r = _add(lg, "\x1f".join(("s", op, ctype)), "selinux", f"{op} invalid context {ctype}",
             "info", "SELinux error, not a denial (SELINUX_ERR)", ts)
    r.label = "SELINUX_ERR"
    r.detail = {"record": rec.message[:300]}


def _noise(lg: Logs, key: str, now: float):
    return noise.reason(lg.noise, f"security/{key}", now) if lg.noise else None


def rows(lg: Logs, stamp, now: float) -> list:
    out = []
    for key, r in sorted(lg.rows.items(), key=lambda kv: -kv[1].last):
        why_noise = _noise(lg, key, now)
        detail = [("why", r.why), ("first", stamp(r.first))]
        detail += [("line", m) for m in r.msgs]
        detail += list(r.detail.items())
        detail.append(("noise key", f"security/{key}"))
        if why_noise:
            detail.append(("noise", why_noise))
        row = {"cells": [f"{r.last:.3f}", str(r.n), r.src, r.what], "sev": r.sev, "id": key,
               "detail": [{"k": a, "v": b} for a, b in detail]}
        if why_noise:
            row["tone"] = "dim"
        out.append(row)
    return out


def noise_count(lg: Logs, now: float) -> int:
    return sum(1 for k in lg.rows if _noise(lg, k, now))


def checks(lg: Logs, now: float, window: float, stamp) -> list:
    """crit rows whose last one is under `window` old -> one check each (noise: the
    alert engine marks it, the bar leaves it out)."""
    hot = sorted(((k, r) for k, r in lg.rows.items()
                  if r.sev == "crit" and now - r.last <= window),
                 key=lambda kr: -kr[1].last)[:MAX_CHECKS]
    out = []
    for key, r in hot:
        out.append({"key": key, "sev": "crit",
                    "title": " ".join(f"{r.src} {r.label}: {r.what}".split())[:160],
                    "detail": f"last {stamp(r.last)}, {r.why}", "n": max(0, r.n - r.reported)})
        r.reported = r.n
    return out
