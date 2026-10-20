"""sectop collector: the system service sectop.service, user sectop.

Runs the modules on their intervals, steps the alert engine and writes
/run/sectop/state.json for the UI (core/statefile.py): after every collect
and every HEARTBEAT seconds. Never draws, never reads keys, takes nothing
from the UI (one-way). Refuses to run as root (docs/architecture.md,
Privilege split).

Single thread. Error / backoff / stale / slow rules are in
docs/module-interface.md (Errors). Core is pure logic with an injected
clock, so the rules can be tested without a service. After each good
collect the module's checks go to the alert engine (core/alerts.py,
wall clock).

systemd: /usr/bin/python3 -I -B /usr/local/lib/sectop/bin/sectop-collector
"""

import collections
import os
import signal
import sys
import time
from dataclasses import dataclass

from core import alerts as alertsmod
from core import config as configmod
from core import noise as noisemod
from core import registry, statefile
from core.module import MIN_INTERVAL, validate, worst
from core.sanitize import display

STATE_PATH = "/run/sectop/state.json"
FEED_MAX = statefile.MAX_FEED
STALE_FACTOR = 3         # last good older than 3 x interval -> unknown
BACKOFF_AFTER = 3        # errors in a row before the interval grows
BACKOFF_MAX = 60.0
HEARTBEAT = 5.0          # state written at least this often
SLEEP_MIN = 0.05
SLEEP_MAX = 1.0


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
    def __init__(self, loaded: list, clock=time.monotonic, wall=time.time, noise=()):
        self.clock, self.wall = clock, wall
        self.runs = [Run(ld, ld.interval, ld.interval) for ld in loaded]
        self.feed = collections.deque(maxlen=FEED_MAX)   # newest first
        self.alerts = alertsmod.empty()                  # alert engine state
        self.noise = tuple(noise)                        # core/noise.py entries

    def tick(self) -> bool:
        """Collect modules that are due. True if any was collected."""
        done = False
        for r in self.runs:
            if r.loaded.active and self.clock() >= r.due:
                self._collect(r)
                done = True
        return done

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
            self.alerts = alertsmod.step(self.alerts, r.loaded.name, snap["checks"], self.wall())
        r.slow = end - start > r.base
        # A slow module waits a full interval after it ended,
        # so it cannot take every tick.
        nxt = start + r.interval
        r.due = nxt if nxt > end else end + r.interval

    def wait(self, limit: float = SLEEP_MAX) -> float:
        """Seconds to sleep: until the next module is due, SLEEP_MIN..min(limit, SLEEP_MAX)."""
        dues = [r.due for r in self.runs if r.loaded.active]
        left = min(dues) - self.clock() if dues else SLEEP_MAX
        return max(SLEEP_MIN, min(left, limit, SLEEP_MAX))

    def longest(self) -> float:
        """Longest configured interval of the active modules (UI: stale limit)."""
        return max((r.base for r in self.runs if r.loaded.active), default=MIN_INTERVAL)

    def active(self) -> list:
        """Open and held alerts (core/alerts.py, wall clock, noise list)."""
        return alertsmod.active(self.alerts, self.wall(), self.noise)

    def view(self, alerts: list | None = None) -> list:
        """One dict per module, for render.layout(). A v2 module's status is the
        worst of its open / held alerts (not noise), so header and alert bar agree."""
        now = self.clock()
        alerts = self.active() if alerts is None else alerts
        sev = {}
        for a in alerts:
            if a["noise"] is None:
                sev[a["module"]] = worst(sev.get(a["module"], "ok"), a["sev"])
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
                m["engine"] = r.snap is not None and r.snap["v"] == 2
                if old:
                    m["status"] = "unknown"
                else:
                    m["status"] = sev.get(ld.name, "ok") if m["engine"] else r.snap["status"]
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

    def state(self) -> dict:
        """state.json document (core/statefile.py)."""
        alerts = self.active()
        return statefile.state(self.wall(), self.longest(), self.view(alerts),
                               list(self.feed), alerts)


def _log(msg: str) -> None:
    print(f"sectop-collector: {display(msg)}", file=sys.stderr, flush=True)


def run(core: Core, path: str = STATE_PATH, write=statefile.write, sleep=time.sleep,
        log=_log, stop=lambda: False) -> None:
    """Collect, write the state, sleep. Until stop() (tests) or Quit / Ctrl-C.
    A write problem is logged once until it changes (no log flood every tick)."""
    last, problem = None, None
    while not stop():
        collected = core.tick()
        now = core.clock()
        if collected or last is None or now - last >= HEARTBEAT:
            try:
                write(path, core.state())
                err = None
            except (OSError, statefile.StateError) as e:
                err = f"{path}: {_err(e)}"
            if err != problem:
                log(err or f"{path}: written again")
                problem = err
            last = now
        sleep(core.wait(HEARTBEAT - (core.clock() - last)))


def _term(signum, frame):
    raise Quit


def main(argv: list | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        print("usage: sectop-collector   (no arguments; run by sectop.service)",
              file=sys.stderr)
        return 2
    if os.geteuid() == 0:
        _log("refusing to run as root: runs as user sectop (sectop.service, docs/install.md)")
        return 2
    try:
        cfg = configmod.load()
        noise = noisemod.load()            # before modules load: nothing to close on error
        loaded = registry.load(cfg)
    except configmod.ConfigError as e:
        _log(f"config: {e}")
        return 2
    signal.signal(signal.SIGTERM, _term)
    try:
        run(Core(loaded, noise=noise))
    except (KeyboardInterrupt, Quit):
        pass
    finally:
        for name, err in registry.close(loaded):
            _log(f"{name}: {err}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
