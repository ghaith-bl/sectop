"""whois for a public IP: RDAP (core/rdap.py) in a child process, unprivileged.

sectop runs as root. A lookup talks to the network and parses what comes
back, so the child runs as user nobody: setpriv sets uid / gid, drops all
groups and sets no_new_privs. It goes out via the tunnel like any program
(audit shows it). Only on key press, one lookup per address per session
(cache in core/ui.py). Blocks the UI up to TIMEOUT (core/app.py).
"""

import ipaddress
import json
import os
import pwd

from core.run import _unsafe
from core.run import run as _run

SETPRIV = "/usr/bin/setpriv"
PYTHON = "/usr/bin/python3"
USER = "nobody"
FALLBACK_ID = 65534      # overflow uid / gid if there is no nobody entry
TIMEOUT = 12.0
MAX_FIELDS = 20
MAX_VALUE = 200
MAX_CHILD = 65536
CHILD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rdap.py")


def public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def ids(user: str = USER) -> tuple:
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        return FALLBACK_ID, FALLBACK_ID
    return pw.pw_uid, pw.pw_gid


def argv(ip: str, uid: int, gid: int, source: str, python: str = PYTHON) -> list:
    return [SETPRIV, f"--reuid={uid}", f"--regid={gid}", "--clear-groups", "--no-new-privs",
            "--", python, "-I", "-c", source, ip]


def _child(path: str) -> str:
    with open(path, "rb") as f:
        data = f.read(MAX_CHILD + 1)
    if len(data) > MAX_CHILD or not data.isascii():
        raise ValueError("not a small ASCII file")
    return data.decode("ascii")


def _err(text: str) -> list:
    return [("whois", text[:MAX_VALUE])]


def _fields(out: str) -> list:
    lines = [ln for ln in out.splitlines() if ln.strip()]
    doc = json.loads(lines[-1]) if lines else None
    if not isinstance(doc, dict):
        raise ValueError("no JSON object")
    if not doc.get("ok"):
        err = doc.get("error")
        return _err(err if isinstance(err, str) else "lookup failed")
    fields = doc.get("fields")
    if not isinstance(fields, list):
        raise ValueError("fields: list required")
    pairs = []
    for f in fields[:MAX_FIELDS]:
        if not (isinstance(f, list) and len(f) == 2 and all(isinstance(x, str) for x in f)):
            raise ValueError("fields: [str, str] pairs required")
        pairs.append((f[0][:40], f[1][:MAX_VALUE]))
    return pairs


def lookup(ip: str, run=_run, user_ids=ids, child: str = CHILD, python: str = PYTHON) -> list:
    """-> [(key, value)] for the detail view. A problem comes back as one 'whois' pair."""
    if not public(ip):
        return _err("not a public address: no whois")
    try:
        bad = _unsafe(python)
    except FileNotFoundError:
        bad = "not found"
    if bad:
        return _err(f"{python}: {bad}")
    try:
        source = _child(child)
    except (OSError, ValueError) as e:
        return _err(f"rdap.py: {e}")
    uid, gid = user_ids()
    if uid == 0 or gid == 0:
        return _err(f"user {USER} maps to root: refused")
    res = run(argv(ip, uid, gid, source, python), timeout=TIMEOUT)
    if res.timed_out:
        return _err(f"timeout after {TIMEOUT:g} s")
    if res.rc == 127:
        return _err(f"{SETPRIV} not found")
    if res.rc == 126:
        return _err(f"{SETPRIV} not trusted")
    if res.rc != 0:
        last = [ln for ln in res.err.splitlines() if ln.strip()]
        return _err(f"rc {res.rc}: {last[-1] if last else 'no output'}")
    try:
        pairs = _fields(res.out)
    except ValueError as e:                       # JSONDecodeError too
        return _err(f"bad child output: {e}")
    return pairs + [("via", f"RDAP as {USER} (uid {uid}), timeout {TIMEOUT:g} s")]
