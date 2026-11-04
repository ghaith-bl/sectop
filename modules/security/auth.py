"""security: auth box (docs/modules/security.md, Auth box).

Who tried to get in, from the same journal entries as the commands box:
- audit USER_AUTH (1100): one PAM authentication. acct = the account whose password
  was checked, exe = the program (sudo, su, gdm-session-worker, polkit agent helper),
  uid = who ran it, auid = the login it came from, res = success / failed.
- audit RESP_ACCT_LOCK (2207, pam_faillock): the account hit deny and is locked.
  ANOM_LOGIN_FAILURES (2100) comes with it (same pid, same moment): not a row.
- audit USER_MGMT (1102) op=faillock-reset: a lock reset (`faillock --reset`).
- sudo syslog PRIORITY 1 (alert): the policy said no (user NOT in sudoers, command not
  allowed, user NOT authorized on host). Login from journald's _AUDIT_LOGINUID.
  `N incorrect password attempts` is left out: its USER_AUTH failures are rows already.

Host fixtures 2026-10-25 (tests/fixtures/security: unlock-fail, su-fail, not-sudoers,
faillock): a locked account still prompts (pam_faillock preauth silent) and every try
is a USER_AUTH failure; sudo logs `user NOT in sudoers` also after wrong passwords.

Severity (decided 2026-10-25: red = dangerous or suspicious, worth following up, not
everything): crit = account locked, sudo refused by policy, su by a non-root user (su
is closed on my host: pam_wheel, empty group sugroup); warn = failed authentication;
info = authentication ok, lock reset. A crit row is also a check (alert) while its last
one is under the window (the same 1 h as the watch list).
"""

import collections
import hashlib
import os
import re

from core import proc as procmod

USER_AUTH = 1100
USER_MGMT = 1102
ACCT_LOCK = 2207
SERVICES = {"sudo": "sudo", "su": "su", "gdm-session-worker": "gdm",
            "polkit-agent-helper-1": "polkit", "pkexec": "pkexec", "login": "login",
            "sshd": "sshd"}
POLICY = {"user NOT in sudoers": "not in sudoers", "command not allowed": "not allowed",
          "user NOT authorized on host": "not on host"}
TRIES_RE = re.compile(r"\d+ incorrect password attempts?")
SAFE_RE = re.compile(r"[^A-Za-z0-9_.@%+-]")
MAX_ROWS = 200
MAX_CHECKS = 50
COLUMNS = ["last", "n", "login>user", "service", "result", "tty"]
TYPES = ["age", "num", "text", "text", "text", "text"]


class Row:
    def __init__(self, login: str, user: str, service: str, result: str, ts: float):
        self.login, self.user, self.service, self.result = login, user, service, result
        self.n, self.first, self.last = 0, ts, ts
        self.sev, self.why = "info", ""
        self.tty = self.exe = self.pid = self.by = ""
        self.ttys = collections.deque(maxlen=5)        # distinct, newest first
        self.reported = 0                               # n at the last check
        self.progs = procmod.names()                    # c = program card


class Auth:
    def __init__(self):
        self.rows = collections.OrderedDict()           # key -> Row, least recent first
        self.fails = 0                                  # failed authentications since start


def _tty(terminal: str | None) -> str:
    t = (terminal or "").removeprefix("/dev/")
    return t if t and t != "?" else "-"


def service(exe: str | None) -> str:
    base = os.path.basename(exe or "") or "?"
    return SERVICES.get(base, base)


def _add(a: Auth, login: str, user: str, svc: str, result: str, ts: float, sev: str,
         why: str, tty: str = "-", exe: str = "", pid: str = "", by: str = "",
         prog: str | None = None) -> Row:
    key = "\x1f".join((login, user, svc, result))
    r = a.rows.pop(key, None) or Row(login, user, svc, result, ts)
    a.rows[key] = r                                     # most recent last
    while len(a.rows) > MAX_ROWS:
        a.rows.popitem(last=False)
    r.n += 1
    r.first, r.last = min(r.first, ts), max(r.last, ts)
    r.sev, r.why = sev, why
    r.tty, r.exe, r.pid, r.by = tty, exe or r.exe, pid or r.pid, by or r.by
    if tty in r.ttys:
        r.ttys.remove(tty)
    r.ttys.appendleft(tty)
    procmod.add(r.progs, prog)
    return r


def _none(pid, ts):
    return None


def audit_event(a: Auth, ev, ts: float, name, prog=_none) -> None:
    """One audit event (core/audit.py Event). name(uid) -> user name, prog(pid, ts) ->
    program (core/proc.py)."""
    if not ev.records:
        return
    p = prog(ev.get("pid"), ts)
    t = ev.records[0].type
    login = name(ev.get("auid"))
    if t == USER_AUTH:
        user, exe, uid = ev.get("acct") or "?", ev.get("exe") or "", ev.get("uid") or ""
        svc, ok = service(exe), ev.get("res") == "success"
        if not ok:
            a.fails += 1
        if svc == "su" and uid not in ("0", ""):
            sev, why = "crit", "su by a non-root user (su is closed: I use sudo)"
        elif ok:
            sev, why = "info", "authentication ok"
        else:
            sev, why = "warn", "authentication failed (wrong password, or a locked account)"
        _add(a, login, user, svc, "ok" if ok else "failed", ts, sev, why,
             _tty(ev.get("terminal")), exe, ev.get("pid") or "", name(uid), p)
    elif t == ACCT_LOCK:
        exe = ev.get("exe") or ""
        _add(a, login, name(ev.get("suid")), service(exe), "locked", ts, "crit",
             "account locked by pam_faillock (deny reached)", _tty(ev.get("terminal")),
             exe, ev.get("pid") or "", prog=p)
    elif t == USER_MGMT and ev.get("op") == "faillock-reset":
        exe = ev.get("exe") or ""
        _add(a, login, name(ev.get("id")), "faillock", "lock reset", ts, "info",
             "faillock --reset", _tty(ev.get("terminal")), exe, ev.get("pid") or "",
             name(ev.get("uid")), p)


def sudo_alert(a: Auth, entry: dict, ts: float, name, prog=_none) -> None:
    """sudo syslog line with PRIORITY 1: `<user> : <reason> ; TTY=.. ; PWD=.. ; ...`."""
    msg = entry.get("MESSAGE")
    if not isinstance(msg, str):
        return
    head, *rest = msg.strip().split(" ; ")
    user, sep, reason = head.partition(" : ")
    if not sep or TRIES_RE.fullmatch(reason.strip()):
        return
    reason = reason.strip()
    kv = dict(p.partition("=")[::2] for p in rest)
    result = POLICY.get(reason)
    sev = "crit" if result else "warn"
    _add(a, name(entry.get("_AUDIT_LOGINUID")), user.strip() or "?", "sudo",
         result or reason[:40], ts, sev, f"sudo: {reason}", _tty(kv.get("TTY")),
         "/usr/bin/sudo", str(entry.get("_PID") or ""),
         prog=prog(str(entry.get("_PID") or ""), ts))


def rows(a: Auth, stamp) -> list:
    out = []
    for key, r in sorted(a.rows.items(), key=lambda kv: -kv[1].last):
        detail = [("why", r.why), ("first", stamp(r.first)), ("exe", r.exe or "-"),
                  ("ran as", r.by or "-"), ("pid", r.pid or "-")]
        if len(r.ttys) > 1:
            detail.append(("tty seen", ", ".join(r.ttys)))
        row = {"cells": [f"{r.last:.3f}", str(r.n), f"{r.login}>{r.user}", r.service,
                         r.result, r.tty],
               "sev": r.sev, "id": key, "detail": [{"k": k, "v": v} for k, v in detail]}
        if r.progs:
            row["progs"] = list(r.progs)
        out.append(row)
    return out


def _safe(s: str) -> str:
    return SAFE_RE.sub("_", s)[:32] or "_"


def checks(a: Auth, now: float, window: float, stamp) -> list:
    """crit rows with new lines since the last report, last one under `window` old ->
    one event check each, at = the newest line."""
    out = []
    hot = sorted((r for r in a.rows.values()
                  if r.sev == "crit" and r.n > r.reported and now - r.last <= window),
                 key=lambda r: -r.last)[:MAX_CHECKS]
    for r in hot:
        key = "auth:" + ":".join(_safe(x) for x in (r.service, r.result, r.login, r.user))
        if len(key) > 128:
            key = "auth:" + hashlib.sha256(key.encode()).hexdigest()[:12]
        if r.result == "locked":
            title = f"account locked: {r.user} ({r.service})"
        elif r.service == "su":
            title = f"su by {r.login} to {r.user}: {r.result}"
        else:
            title = f"{r.service} refused: {r.user} {r.result}"
        out.append({"key": key, "sev": "crit", "title": title[:160],
                    "detail": f"{r.login}>{r.user} tty {r.tty}, last {stamp(r.last)}, "
                              f"{r.why}", "n": r.n - r.reported, "at": r.last})
        r.reported = r.n
    return out
