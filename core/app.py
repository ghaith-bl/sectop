"""sectop UI: draws what the collector wrote and handles keys.

Runs as my user, never as root, never collects. Reads
/run/sectop/state.json (core/collector.py writes it, core/statefile.py
checks it) when the file changed. One-way: the UI never writes to the
collector; ack stays here (core/ui.py). No update for a while or a bad
file -> a crit alert "collector: ..." on top of the last good data.

v1: single thread. Each loop: read the state file if it changed, draw,
wait for a key (TICK_MS). whois: core/lookup.py (socket service). Log card: core/logs.py
(one journal query on enter, after the frame that says 'reading').

Run: sectop [SCREEN]   (launcher /usr/local/bin/sectop, docs/install.md)
SCREEN = name or number from core/screens.py, default 1.
"""

import curses
import locale
import os
import pwd
import signal
import sys
import time

from core import config as configmod
from core import logs as logsmod
from core import lookup as lookupmod
from core import render, statefile
from core.sanitize import display
from core.screens import SCREENS, find, names
from core.ui import UI

STATE_PATH = "/run/sectop/state.json"
COLLECTOR_USER = "sectop"
TICK_MS = 250
STALE_MIN = 15.0         # seconds without a new state -> collector alert
STALE_FACTOR = 3         # ... or 3 x the state's interval (write period), if longer
ALERT_KEY = "core/collector"


class Quit(BaseException):
    """Raised by the SIGTERM handler."""


def owner_uid(user: str = COLLECTOR_USER) -> int | None:
    try:
        return pwd.getpwnam(user).pw_uid
    except KeyError:
        return None


def collector_alert(problem: str, now: float) -> dict:
    """An alert like core/alerts.py active() makes, for the alert bar. The title
    says why: the bar shows only titles (first install 2026-10-20: "no data" alone
    did not say that user sectop was missing)."""
    return {"key": ALERT_KEY, "module": "core", "sev": "crit",
            "title": f"collector: {problem}", "detail": problem, "count": 1,
            "first": now, "since": now, "last": now, "hold": 0.0, "true": True,
            "state": "open", "noise": None}


class Reader:
    """Last good state.json. poll() reads it again when the file changed
    (inode, mtime, size). A bad file is refused whole; the last good stays.
    owner: uid of user sectop, or a function that looks it up (asked again on
    every poll while it is missing: the install may create it while the UI runs)."""

    def __init__(self, path: str = STATE_PATH, owner=None, load=statefile.load, stat=os.stat):
        self.path = path
        self._owner = owner if callable(owner) else (lambda: owner)
        self._uid = None
        self._load, self._stat = load, stat
        self.state = None            # checked state (core/statefile.py check_state)
        self.error = None            # last read problem
        self.sig = None

    @property
    def owner(self) -> int | None:
        if self._uid is None:
            self._uid = self._owner()
        return self._uid

    def poll(self) -> bool:
        """True if something changed (new state or new problem)."""
        if self.owner is None:
            return self._problem(f"user {COLLECTOR_USER} missing: sectop not installed? "
                                 "(docs/install.md)")
        try:
            st = self._stat(self.path)
        except FileNotFoundError:
            self.sig = None
            return self._problem(f"{self.path} missing: is sectop.service running?")
        except PermissionError:
            self.sig = None
            return self._problem(f"{self.path}: permission denied: my user in group "
                                 f"{COLLECTOR_USER}? (log out and in after install)")
        except OSError as e:
            self.sig = None
            return self._problem(f"{self.path}: {e.strerror}")
        sig = (st.st_ino, st.st_mtime_ns, st.st_size)
        if sig == self.sig:
            return False
        self.sig = sig
        try:
            doc = self._load(self.path, self.owner)
            if doc is None:
                raise statefile.StateError(f"{self.path} missing")
            self.state, self.error = statefile.check_state(doc), None
        except statefile.StateError as e:
            self._problem(str(e))
        return True

    def _problem(self, text: str) -> bool:
        changed = text != self.error
        self.error = text
        return changed

    def limit(self) -> float:
        s = self.state
        return STALE_MIN if s is None else max(STALE_MIN, STALE_FACTOR * s["interval"])

    def stale(self, now: float) -> bool:
        return self.state is None or now - self.state["ts"] > self.limit()

    def current(self, now: float) -> tuple:
        """-> (view, feed, alerts) to draw. Old or no data: collector alert first,
        modules marked stale (status unknown)."""
        s = self.state
        problem = self.error
        if s is None:
            view, feed, alerts = [], [], []
        else:
            view, feed, alerts = s["modules"], s["feed"], s["alerts"]
            if self.stale(now):
                when = time.strftime("%H:%M:%S", time.localtime(s["ts"]))
                problem = problem or f"no update since {when} (limit {self.limit():g} s)"
                view = [{**m, "stale": True, "flags": m["flags"] + ["stale"],
                         "status": m["status"] if m["status"] == "off" else "unknown"}
                        for m in view]
        if problem:
            alerts = [collector_alert(problem, now)] + list(alerts)
        return view, feed, alerts


def source(reader: Reader, ui: UI, frozen, now: float):
    """What to draw: live data, or the copy taken when pause started (with that
    moment, so ages do not move while paused). Reading goes on while paused.
    -> (view, feed, alerts, frozen)."""
    if not ui.paused:
        view, feed, alerts = reader.current(now)
        return view, feed, alerts, None
    if frozen is None:
        frozen = (*reader.current(now), now)
    return frozen[0], frozen[1], frozen[2], frozen


def step_lookup(ui: UI, lookup=lookupmod.lookup) -> bool:
    """Run a whois the UI asked for (blocks up to lookup.TIMEOUT). True if one ran."""
    ip = ui.lookup
    if ip is None:
        return False
    ui.done(ip, lookup(ip))
    return True


def step_logs(ui: UI, view: list, load=logsmod.load) -> bool:
    """Read the log card the UI asked for (blocks up to the query timeout). True if one ran."""
    req = ui.logreq
    if req is None:
        return False
    ui.logs_done(req, load(req, view))
    return True


def _ui(stdscr, reader: Reader, ui: UI) -> None:
    """Full redraw only after a new state or a stale flip (not while paused) or
    a key (incl. resize); otherwise just the clock once a second. A whois runs
    after the frame that says 'looking up' is on screen."""
    render.setup(stdscr)
    stdscr.timeout(TICK_MS)
    frozen, dirty, shown, stale = None, True, None, None
    while True:
        changed = reader.poll()
        now = time.time()
        if reader.stale(now) != stale:
            stale, changed = reader.stale(now), True
        if changed and not ui.paused:
            dirty = True
        if dirty:
            view, feed, alerts, frozen = source(reader, ui, frozen, now)
            ref = frozen[3] if frozen else now          # ages: paused -> the pause moment
            ui.update(render.draw(stdscr, SCREENS, view, feed, ui, now, alerts, ref))
            dirty, shown = False, int(now)
        elif int(now) != shown:
            render.draw_top(stdscr, SCREENS, ui, now)
            shown = int(now)
        if step_lookup(ui):
            dirty = True
            continue
        if ui.logreq is not None:
            step_logs(ui, frozen[0] if frozen else reader.current(time.time())[0])
            dirty = True
            continue
        key = stdscr.getch()
        if key != -1:
            dirty = True
            if not ui.key(key):
                return


def _term(signum, frame):
    raise Quit


USAGE = f"usage: sectop [SCREEN]   SCREEN: {' | '.join(names())} or 1-{len(SCREENS)}"


def main(argv: list | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] in (["-h"], ["--help"]):
        print(USAGE)
        return 0
    try:
        if len(argv) > 1:
            raise ValueError("one SCREEN at most")
        start = find(argv[0]) if argv else 0
    except ValueError as e:
        print(f"sectop: {display(e)}\n{USAGE}", file=sys.stderr)
        return 2
    if os.geteuid() == 0:
        print("sectop: refusing to run as root: run it as your user, no sudo "
              "(docs/install.md)", file=sys.stderr)
        return 2
    try:
        cfg = configmod.load()
    except configmod.ConfigError as e:
        print(f"sectop: config: {display(e)}", file=sys.stderr)
        return 2
    locale.setlocale(locale.LC_ALL, "")
    signal.signal(signal.SIGTERM, _term)
    palette = cfg.console_palette and linux_console()
    if palette:
        _put(render.console_palette(True))
    try:
        curses.wrapper(_ui, Reader(owner=owner_uid),
                       UI(len(SCREENS), screen=start, mask=cfg.mask_public_ips))
    except (KeyboardInterrupt, Quit):
        pass
    finally:
        if palette:
            _put(render.console_palette(False))
    return 0


def linux_console() -> bool:
    """The Linux text console (soft palette there, core/render.py CONSOLE_PALETTE)."""
    return os.environ.get("TERM") == "linux" and sys.stdout.isatty()


def _put(s: str) -> None:
    sys.stdout.write(s)
    sys.stdout.flush()


if __name__ == "__main__":
    sys.exit(main())
