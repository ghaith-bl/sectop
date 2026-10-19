"""sectop main loop.

v1: single thread. Each loop: collect modules that are due, draw,
wait for a key (TICK_MS). Error / backoff / stale / slow rules are
in docs/module-interface.md (Errors). Core is pure logic with an
injected clock so the rules can be tested without a terminal.

Dev run (from repo root): sudo python3 -B -m core.app [SCREEN]
SCREEN = name or number from core/screens.py, default 1.
"""

import collections
import curses
import locale
import signal
import sys
import time
from dataclasses import dataclass

from core import config as configmod
from core import registry, render
from core.module import validate
from core.sanitize import display
from core.screens import SCREENS, find, names
from core.ui import UI

FEED_MAX = 500
STALE_FACTOR = 3         # last good older than 3 x interval -> unknown
BACKOFF_AFTER = 3        # errors in a row before the interval grows
BACKOFF_MAX = 60.0
TICK_MS = 250


class Quit(BaseException):
    """Raised by the SIGTERM handler. BaseException so module error
    handling (Exception, SystemExit) cannot swallow it."""


@dataclass
class Run:
    """Runtime state of one module."""
    loaded: registry.Loaded
    base: float                 # configured interval
    interval: float             # current, grows with backoff
    due: float = 0.0            # monotonic time of next collect
    errors: int = 0             # errors in a row
    error: str | None = None    # last error, None after a success
    snap: dict | None = None    # last good (validated) Snapshot
    good_at: float | None = None
    slow: bool = False


def _err(e: BaseException) -> str:
    msg = str(e)
    return f"{type(e).__name__}: {msg}" if msg else type(e).__name__


def backoff(base: float, errors: int) -> float:
    """Interval after `errors` errors in a row."""
    if errors < BACKOFF_AFTER:
        return base
    grown = base * 2 ** (errors - BACKOFF_AFTER + 1)
    return max(base, min(BACKOFF_MAX, grown))


class Core:
    def __init__(self, loaded: list, clock=time.monotonic):
        self.clock = clock
        self.runs = [Run(ld, ld.interval, ld.interval) for ld in loaded]
        self.feed = collections.deque(maxlen=FEED_MAX)   # newest first

    def tick(self) -> None:
        for r in self.runs:
            if r.loaded.active and self.clock() >= r.due:
                self._collect(r)

    def _collect(self, r: Run) -> None:
        start = self.clock()
        try:
            snap = validate(r.loaded.mod.collect(r.loaded.state))
        except (Exception, SystemExit) as e:
            end = self.clock()
            r.errors += 1
            r.error = _err(e)
            r.interval = backoff(r.base, r.errors)
        else:
            end = self.clock()
            r.errors, r.error, r.interval = 0, None, r.base
            r.snap, r.good_at = snap, end
            for ev in snap["events"]:
                self.feed.appendleft({**ev, "src": r.loaded.name})
        r.slow = end - start > r.base
        # A slow module waits a full interval after it ended,
        # so it cannot take every tick.
        nxt = start + r.interval
        r.due = nxt if nxt > end else end + r.interval

    def view(self) -> list:
        """One dict per module, for render.layout()."""
        now = self.clock()
        out = []
        for r in self.runs:
            ld = r.loaded
            m = {"name": ld.name, "flags": [], "panels": [], "stale": False, "waiting": False}
            if not ld.enabled:
                m.update(status="off", summary="disabled")
            elif ld.error:
                m.update(status="unknown", summary="not loaded", flags=["failed: " + ld.error])
            else:
                old = r.good_at is None or now - r.good_at > STALE_FACTOR * r.base
                m["status"] = "unknown" if old else r.snap["status"]
                m["summary"] = r.snap["summary"] if r.snap else "waiting"
                m["waiting"] = r.snap is None and r.error is None
                if r.error:
                    m["flags"].append("error: " + r.error)
                if r.interval != r.base:
                    m["flags"].append(f"backoff {r.interval:g}s")
                if r.slow:
                    m["flags"].append("slow")
                if r.snap is not None:
                    m["panels"] = r.snap["panels"]
                    m["stale"] = r.error is not None or old
                    if m["stale"]:
                        m["flags"].append("stale")
            out.append(m)
        return out


def _ui(stdscr, core: Core, ui: UI) -> None:
    render.setup(stdscr)
    stdscr.timeout(TICK_MS)
    while True:
        core.tick()
        frame = render.draw(stdscr, SCREENS, core.view(), list(core.feed), ui, time.time())
        ui.boxes = frame.boxes
        key = stdscr.getch()
        if key != -1 and not ui.key(key):
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
    try:
        cfg = configmod.load()
        loaded = registry.load(cfg)
    except configmod.ConfigError as e:
        print(f"sectop: config: {display(e)}", file=sys.stderr)
        return 2
    locale.setlocale(locale.LC_ALL, "")
    signal.signal(signal.SIGTERM, _term)
    try:
        curses.wrapper(_ui, Core(loaded), UI(len(SCREENS), screen=start,
                                             mask=cfg.mask_public_ips))
    except (KeyboardInterrupt, Quit):
        pass
    finally:
        for name, err in registry.close(loaded):
            print(f"sectop: {display(name)}: {display(err)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
