"""sectop net unit: the system service sectop-net.service, user sectop-net,
CAP_NET_ADMIN only (docs/architecture.md, Privilege split).

nft and wg need CAP_NET_ADMIN even to read. The process that holds it stays
minimal: fixed argv (commands() below, the only firewall knowledge here),
no input from anyone (only the root-owned config: tunnel name, interval),
no parsing of what the commands print. Each result goes as is to
/run/sectop-net/<name>.json (core/statefile.py, group sectop).

The collector side is Reader: the firewall module asks for an nft / wg
command and gets the last result from its file, like core.run.run() would
return it. Fast commands run every half firewall interval, slow ones every
half SLOW, so every collector tick finds a fresh sample.

systemd: /usr/bin/python3 -I -B /usr/local/lib/sectop/bin/sectop-net
"""

import os
import pwd
import re
import signal
import sys
import time

from core import config as configmod
from core import statefile
from core.module import _is_num
from core.run import Result
from core.run import run as _run
from core.sanitize import display

NET_DIR = "/run/sectop-net"
NET_USER = "sectop-net"
NET_BINS = ("nft", "wg")     # what the firewall module gets from here, not from run()

# firewall module defaults (modules/firewall uses these)
TABLE = ("inet", "hostfw")
DEFAULT_TUNNEL = "proton0"
IFACE_RE = re.compile(r"[A-Za-z0-9_.-]{1,15}")
FW_INTERVAL = 2.0
FW_SLOW = 30.0
TIMEOUT = 1.0            # per command, like the module's own commands

FAST, SLOW = "fast", "slow"
FAST_MAX_AGE = 30.0      # older fast result -> error (net unit stuck or stopped)
SLOW_MAX_AGE = 3 * FW_SLOW
SLEEP_MIN, SLEEP_MAX = 0.05, 1.0


class Quit(BaseException):
    """Raised by the SIGTERM handler."""


def bin_path(name: str) -> str:
    for d in ("/usr/bin", "/usr/sbin"):
        p = f"{d}/{name}"
        if os.path.isfile(p):
            return p
    return f"/usr/bin/{name}"         # run() reports rc 127


def commands(tunnel: str, binary=bin_path) -> dict:
    """name -> (argv, FAST or SLOW). Exactly what modules/firewall asks for."""
    if not isinstance(tunnel, str) or not IFACE_RE.fullmatch(tunnel):
        raise ValueError("tunnel: interface name required")
    nft, wg = binary("nft"), binary("wg")
    return {
        "table": ((nft, "-j", "-t", "list", "table", *TABLE), FAST),
        "handshakes": ((wg, "show", tunnel, "latest-handshakes"), FAST),
        "transfer": ((wg, "show", tunnel, "transfer"), FAST),
        "endpoints": ((wg, "show", tunnel, "endpoints"), SLOW),
        "fwmark": ((wg, "show", tunnel, "fwmark"), SLOW),
        "fwmark_set": ((nft, "-j", "list", "set", *TABLE, "wg_fwmark"), SLOW),
    }


def path(name: str, base: str = NET_DIR) -> str:
    return os.path.join(base, f"{name}.json")


def result_doc(name: str, argv, res: Result, ts: float) -> dict:
    return {"v": 1, "name": name, "argv": list(argv), "rc": res.rc, "out": res.out,
            "err": res.err, "timed_out": res.timed_out, "truncated": res.truncated, "ts": ts}


# --- net unit -------------------------------------------------------------

def plan(cfg) -> dict:
    """Config -> name -> (argv, seconds between runs). Firewall disabled -> {}."""
    fw = cfg.module("firewall")
    if not fw.enabled:
        return {}
    interval = fw.interval if fw.interval is not None else FW_INTERVAL
    every = {FAST: max(1.0, interval / 2), SLOW: FW_SLOW / 2}
    cmds = commands(fw.options.get("tunnel", DEFAULT_TUNNEL))
    return {name: (argv, every[kind]) for name, (argv, kind) in cmds.items()}


def _log(msg: str) -> None:
    print(f"sectop-net: {display(msg)}", file=sys.stderr, flush=True)


def loop(cmds: dict, base: str = NET_DIR, run=_run, write=statefile.write,
         clock=time.monotonic, wall=time.time, sleep=time.sleep, log=_log,
         stop=lambda: False) -> None:
    """Run each command when due, write its result. A write problem is logged
    once until it changes."""
    due = {name: 0.0 for name in cmds}
    problem = None
    while not stop():
        for name, (argv, every) in cmds.items():
            if clock() < due[name]:
                continue
            res = run(list(argv), timeout=TIMEOUT)
            try:
                write(path(name, base), result_doc(name, argv, res, wall()))
                err = None
            except (OSError, statefile.StateError) as e:
                err = f"{path(name, base)}: {type(e).__name__}: {e}"
            if err != problem:
                log(err or "writing again")
                problem = err
            due[name] = clock() + every
        left = min(due.values(), default=clock() + SLEEP_MAX) - clock()
        sleep(max(SLEEP_MIN, min(left, SLEEP_MAX)))


def _term(signum, frame):
    raise Quit


def main(argv: list | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        print("usage: sectop-net   (no arguments; run by sectop-net.service)", file=sys.stderr)
        return 2
    if os.geteuid() == 0:
        _log("refusing to run as root: runs as user sectop-net with CAP_NET_ADMIN "
             "(sectop-net.service, docs/install.md)")
        return 2
    try:
        cmds = plan(configmod.load())
    except (configmod.ConfigError, ValueError) as e:
        _log(f"config: {e}")
        return 2
    if not cmds:
        _log("firewall module disabled: nothing to run")
        return 0
    signal.signal(signal.SIGTERM, _term)
    try:
        loop(cmds)
    except (KeyboardInterrupt, Quit):
        pass
    return 0


# --- collector side -------------------------------------------------------

def owner_uid(user: str = NET_USER) -> int | None:
    try:
        return pwd.getpwnam(user).pw_uid
    except KeyError:
        return None


def _fail(msg: str) -> Result:
    return Result(1, "", msg)


class Reader:
    """run()-like: argv of an nft / wg command -> its last result from the net
    unit's file. Missing, old, unsafe or wrong file -> a failed Result that says
    why, so the module shows it like any command error."""

    def __init__(self, tunnel: str, base: str = NET_DIR, owner=owner_uid, wall=time.time,
                 binary=bin_path):
        self.names = {tuple(argv): (name, kind)
                      for name, (argv, kind) in commands(tunnel, binary).items()}
        self.base, self._owner, self.wall = base, owner, wall

    def __call__(self, argv, timeout: float = TIMEOUT) -> Result:
        hit = self.names.get(tuple(argv))
        if hit is None:
            raise ValueError(f"not a net unit command: {argv!r}")      # bug in the module
        name, kind = hit
        uid = self._owner()
        if uid is None:
            return _fail(f"user {NET_USER} missing: sectop not installed? (docs/install.md)")
        p = path(name, self.base)
        try:
            doc = statefile.load(p, uid)
        except statefile.StateError as e:
            return _fail(f"net file: {e}")
        if doc is None:
            return _fail(f"{p} missing: is sectop-net.service running?")
        try:
            res, ts = _check(doc, argv)
        except ValueError as e:
            return _fail(f"{p}: {e}")
        age = self.wall() - ts
        if age > (FAST_MAX_AGE if kind == FAST else SLOW_MAX_AGE):
            return _fail(f"{p}: {int(age)} s old: is sectop-net.service stuck?")
        return res


def _check(doc, argv) -> tuple:
    """Net file -> (Result, ts). Wrong shape or another command -> ValueError."""
    if not isinstance(doc, dict) or doc.get("v") != 1 or type(doc.get("v")) is not int:
        raise ValueError("v: 1 required")
    if doc.get("argv") != list(argv):
        raise ValueError("written for another command (config changed? restart "
                         "sectop-net.service)")
    rc = doc.get("rc")
    if type(rc) is not int:
        raise ValueError("rc: int required")
    out, err = doc.get("out"), doc.get("err")
    if not isinstance(out, str) or not isinstance(err, str):
        raise ValueError("out / err: str required")
    flags = doc.get("timed_out"), doc.get("truncated")
    if not all(isinstance(f, bool) for f in flags):
        raise ValueError("timed_out / truncated: true or false required")
    ts = doc.get("ts")
    if not _is_num(ts) or ts < 0:
        raise ValueError("ts: epoch seconds required")
    return Result(rc, out, err, *flags), float(ts)


if __name__ == "__main__":
    sys.exit(main())
