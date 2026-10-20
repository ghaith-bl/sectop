import datetime
import json
import types
import unittest
from unittest import mock

from core import collector, statefile
from core.collector import Core, Quit, backoff
from core.config import ConfigError
from core.noise import Entry
from core.registry import Loaded


class Clock:
    def __init__(self, t=100.0):
        self.t = t

    def __call__(self):
        return self.t


def snap(status="ok", events=(), summary="s"):
    return {"v": 1, "status": status, "summary": summary,
            "panels": [{"id": "p", "title": "t", "type": "kv", "items": []}],
            "events": list(events)}


def ev(ts, msg="m", sev="warn"):
    return {"ts": ts, "sev": sev, "code": "C", "msg": msg}


def loaded(name="a", collect=None, interval=2.0, **over):
    mod = types.SimpleNamespace(collect=collect or (lambda st: snap()))
    kw = {"name": name, "import_name": f"modules.{name}", "enabled": True,
          "mod": mod, "interval": interval, "state": {"st": name}}
    kw.update(over)
    return Loaded(**kw)


class Script:
    """collect() that plays a list of results: dict = Snapshot, exception = raise."""
    def __init__(self, *results, clock=None, takes=0.0):
        self.results = list(results)
        self.calls = []
        self.clock, self.takes = clock, takes

    def __call__(self, state):
        self.calls.append(state)
        if self.clock:
            self.clock.t += self.takes
        r = self.results.pop(0) if len(self.results) > 1 else self.results[0]
        if isinstance(r, BaseException):
            raise r
        return r


class TestBackoff(unittest.TestCase):
    def test_backoff(self):
        self.assertEqual([backoff(2.0, n) for n in range(7)],
                         [2.0, 2.0, 2.0, 4.0, 8.0, 16.0, 32.0])
        self.assertEqual(backoff(2.0, 20), 60.0)
        self.assertEqual(backoff(90.0, 5), 90.0)         # never below interval


class TestCore(unittest.TestCase):
    def core(self, *lds):
        self.clock = Clock()
        return Core(list(lds), clock=self.clock)

    def test_schedule(self):
        s = Script(snap())
        c = self.core(loaded(collect=s))
        self.assertTrue(c.tick())                         # collected
        self.assertEqual(s.calls, [{"st": "a"}])
        self.clock.t += 1.9
        self.assertFalse(c.tick())                        # nothing due: no redraw needed
        self.assertEqual(len(s.calls), 1)
        self.clock.t += 0.1
        self.assertTrue(c.tick())
        self.assertEqual(len(s.calls), 2)

    def test_view_ok(self):
        c = self.core(loaded(collect=Script(snap("warn", summary="hi"))))
        self.assertEqual(c.view()[0]["summary"], "waiting")
        self.assertEqual(c.view()[0]["status"], "unknown")
        self.assertTrue(c.view()[0]["waiting"])
        c.tick()
        [m] = c.view()
        self.assertEqual((m["name"], m["status"], m["summary"], m["flags"], m["stale"],
                          m["waiting"]), ("a", "warn", "hi", [], False, False))
        self.assertEqual(m["panels"][0]["id"], "p")

    def test_events_feed(self):
        s = Script(snap(events=[ev(1, "x1"), ev(2, "x2")]), snap(events=[ev(3, "x3")]))
        b = Script(snap(events=[ev(5, "b")]), snap())
        c = self.core(loaded(collect=s), loaded("b", collect=b))
        c.tick()
        self.clock.t += 2
        c.tick()
        self.assertEqual([(e["src"], e["msg"]) for e in c.feed],
                         [("a", "x3"), ("b", "b"), ("a", "x2"), ("a", "x1")])
        self.assertEqual(c.feed[0]["ts"], 3.0)

    def test_feed_limit(self):
        many = snap(events=[ev(i) for i in range(100)])
        c = self.core(loaded(collect=Script(many), interval=1.0))
        for _ in range(7):
            c.tick()
            self.clock.t += 1
        self.assertEqual(len(c.feed), collector.FEED_MAX)
        self.assertEqual(c.feed[0]["ts"], 99.0)

    def test_waiting_vs_first_error(self):
        c = self.core(loaded(collect=Script(RuntimeError("boom"))))
        c.tick()
        [m] = c.view()
        self.assertFalse(m["waiting"])                   # an error is not "waiting"
        self.assertEqual(m["status"], "unknown")

    def test_error_keeps_last_good(self):
        s = Script(snap("crit"), RuntimeError("boom"))
        c = self.core(loaded(collect=s))
        c.tick()
        self.clock.t += 2
        c.tick()
        [m] = c.view()
        self.assertEqual(m["status"], "crit")            # recent good data
        self.assertEqual(m["flags"], ["error: RuntimeError: boom", "stale"])
        self.assertTrue(m["stale"])
        self.assertEqual(len(m["panels"]), 1)

    def test_checks_go_to_alert_engine(self):
        wall = Clock(1760950000.0)
        v2 = {**snap(), "v": 2, "checks": [{"key": "k", "sev": "crit", "title": "t"}]}
        c = Core([loaded(collect=Script(v2, {**snap(), "v": 2, "checks": []},
                                        RuntimeError("boom")))],
                 clock=Clock(), wall=wall)
        c.tick()
        self.assertEqual(c.alerts["alerts"]["a/k"]["last"], 1760950000.0)
        self.assertTrue(c.alerts["alerts"]["a/k"]["true"])
        c.clock.t += 2
        wall.t += 2
        c.tick()                                          # check gone -> held
        self.assertFalse(c.alerts["alerts"]["a/k"]["true"])
        kept = c.alerts
        c.clock.t += 2
        wall.t += 2
        c.tick()                                          # error: not stepped
        self.assertIs(c.alerts, kept)
        self.assertEqual(Core([]).alerts, {"alerts": {}})

    def test_v2_status_from_engine(self):
        wall = Clock(1760950000.0)
        checks = [{"key": "a", "sev": "warn", "title": "t"}, {"key": "b", "sev": "crit",
                                                             "title": "u"}]
        v2 = {**snap(status="ok"), "v": 2, "checks": checks}
        c = Core([loaded(collect=Script(v2, {**v2, "checks": []}))], clock=Clock(), wall=wall,
                 noise=(Entry("a/b", "known", datetime.date(2999, 1, 1)),))
        c.tick()
        [m] = c.view()
        self.assertEqual((m["status"], m["engine"]), ("warn", True))   # b is noise
        c.clock.t += 2
        wall.t += 2
        c.tick()                                         # checks gone: held, still warn
        self.assertEqual(c.view()[0]["status"], "warn")
        wall.t += 60
        self.assertEqual(c.view()[0]["status"], "ok")    # hold over
        c.clock.t += 7
        self.assertEqual(c.view()[0]["status"], "unknown")   # stale beats the engine

    def test_v1_status_from_snapshot(self):
        c = self.core(loaded(collect=Script(snap("crit"))))
        c.tick()
        [m] = c.view()
        self.assertEqual((m["status"], m["engine"]), ("crit", False))

    def test_v1_checks_ignored(self):
        c = self.core(loaded(collect=Script({**snap(), "checks": [1]})))
        c.tick()
        self.assertEqual(c.alerts, {"alerts": {}})
        self.assertIsNone(c.runs[0].error)

    def test_invalid_snapshot_is_error(self):
        c = self.core(loaded(collect=Script({"v": 3})))
        c.tick()
        [m] = c.view()
        self.assertEqual(m["flags"], ["error: InvalidSnapshot: v: 1 or 2 required"])
        self.assertEqual(m["panels"], [])

    def test_backoff_and_reset(self):
        boom = RuntimeError("x")
        c = self.core(loaded(collect=Script(boom, boom, boom, boom, snap())))
        waits = []
        for _ in range(5):
            self.clock.t = max(self.clock.t, c.runs[0].due)
            c.tick()
            waits.append(c.runs[0].due - self.clock.t)
        self.assertEqual(waits, [2.0, 2.0, 4.0, 8.0, 2.0])
        self.assertEqual(c.runs[0].errors, 0)
        self.assertEqual(c.view()[0]["flags"], [])

    def test_backoff_flag(self):
        c = self.core(loaded(collect=Script(RuntimeError())))
        for _ in range(3):
            self.clock.t = max(self.clock.t, c.runs[0].due)
            c.tick()
        self.assertIn("backoff 4s", c.view()[0]["flags"])
        self.assertIn("error: RuntimeError", c.view()[0]["flags"])

    def test_stale_unknown(self):
        s = Script(snap("ok"), RuntimeError("x"))
        c = self.core(loaded(collect=s))
        c.tick()
        self.clock.t += 6.0                               # 3 x 2.0, not older yet
        self.assertEqual(c.view()[0]["status"], "ok")
        self.clock.t += 0.1
        [m] = c.view()
        self.assertEqual(m["status"], "unknown")
        self.assertTrue(m["stale"])                        # old even without error

    def test_slow(self):
        clock = Clock()
        s = Script(snap(), clock=clock, takes=3.0)
        c = Core([loaded(collect=s)], clock=clock)
        c.tick()
        self.assertTrue(c.runs[0].slow)
        self.assertIn("slow", c.view()[0]["flags"])
        self.assertEqual(c.runs[0].due, clock.t + 2.0)     # full interval after end
        s.takes = 0.5
        clock.t = c.runs[0].due
        c.tick()
        self.assertFalse(c.runs[0].slow)

    def test_isolation(self):
        def boom(st):
            raise ValueError("bad")

        def bye(st):
            raise SystemExit(1)

        good = Script(snap("info"))
        c = self.core(loaded("a", collect=boom), loaded("b", collect=bye),
                      loaded("c", collect=good))
        c.tick()
        v = c.view()
        self.assertEqual(v[0]["flags"], ["error: ValueError: bad"])
        self.assertEqual(v[1]["flags"], ["error: SystemExit: 1"])
        self.assertEqual(v[2]["status"], "info")

    def test_quit_and_interrupt_propagate(self):
        for exc in (Quit, KeyboardInterrupt):
            def f(st, exc=exc):
                raise exc
            c = self.core(loaded(collect=f))
            with self.assertRaises(exc):
                c.tick()

    def test_disabled_and_failed(self):
        never = Script(snap())
        c = self.core(loaded("a", enabled=False, mod=None, interval=0.0),
                      loaded("b", collect=never, error="init: OSError: nope"))
        c.tick()
        a, b = c.view()
        self.assertEqual((a["status"], a["summary"], a["flags"]), ("off", "disabled", []))
        self.assertEqual((b["status"], b["summary"], b["flags"]),
                         ("unknown", "not loaded", ["failed: init: OSError: nope"]))
        self.assertEqual(never.calls, [])


class TestState(unittest.TestCase):
    def test_wait_and_longest(self):
        clock = Clock()
        c = Core([loaded("a", interval=6.0), loaded("b", interval=2.0),
                  loaded("c", enabled=False, mod=None, interval=0.0)], clock=clock)
        self.assertEqual(c.longest(), 6.0)
        self.assertEqual(c.wait(), collector.SLEEP_MIN)          # all due now
        c.tick()
        self.assertEqual(c.wait(), 1.0)                          # next in 2 s, max 1 s
        clock.t += 1.7
        self.assertAlmostEqual(c.wait(), 0.3)
        self.assertAlmostEqual(c.wait(0.1), 0.1)                 # heartbeat sooner
        self.assertEqual(Core([], clock=clock).longest(), 1.0)

    def test_state_passes_ui_check(self):
        clock, wall = Clock(), Clock(1760950000.0)
        crit = {**snap(events=[ev(1760949999.0)]), "v": 2,
                "checks": [{"key": "k", "sev": "crit", "title": "t", "n": 3}]}
        c = Core([loaded(collect=Script(crit))], clock=clock, wall=wall)
        c.tick()
        doc = c.state()
        self.assertEqual((doc["ts"], doc["interval"]), (1760950000.0, 2.0))
        checked = statefile.check_state(json.loads(statefile.encode(doc)))
        self.assertEqual(checked["alerts"][0]["key"], "a/k")
        self.assertEqual(checked["modules"][0]["status"], "crit")
        self.assertEqual(checked["feed"][0]["src"], "a")


class TestRun(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.writes, self.logs, self.sleeps = [], [], []

    def go(self, core, steps, write=None):
        n = iter(range(steps))

        def sleep(sec):
            self.sleeps.append(sec)
            self.clock.t += sec

        collector.run(core, "/x/state.json", write=write or self.write, sleep=sleep,
                      log=self.logs.append, stop=lambda: next(n, None) is None)

    def write(self, path, doc):
        self.writes.append((self.clock.t, doc))

    def test_writes_after_collect_and_heartbeat(self):
        core = Core([loaded(interval=20.0)], clock=self.clock)
        self.go(core, 30)
        times = [t for t, _ in self.writes]
        self.assertEqual(times[0], 100.0)                        # first collect
        gaps = [b - a for a, b in zip(times, times[1:])]
        self.assertTrue(gaps and all(g <= collector.HEARTBEAT + 1e-9 for g in gaps), gaps)
        self.assertTrue(all(s <= collector.SLEEP_MAX for s in self.sleeps))
        self.assertEqual(self.logs, [])

    def test_write_problem_logged_once(self):
        calls = []

        def write(path, doc):
            calls.append(path)
            if len(calls) <= 3:
                raise PermissionError(13, "Permission denied")

        core = Core([loaded(interval=1.0)], clock=self.clock)
        self.go(core, 20, write=write)
        self.assertGreater(len(calls), 4)
        self.assertEqual(len(self.logs), 2)
        self.assertIn("PermissionError", self.logs[0])
        self.assertIn("written again", self.logs[1])

    def test_quit_stops(self):
        def f(st):
            raise Quit
        with self.assertRaises(Quit):
            self.go(Core([loaded(collect=f)], clock=self.clock), 5)


class TestMain(unittest.TestCase):
    def main(self, argv=(), euid=1000, cfg_err=None, noise_err=None, close=()):
        logs = []
        with mock.patch.object(collector.os, "geteuid", return_value=euid), \
             mock.patch.object(collector.configmod, "load",
                               side_effect=cfg_err, return_value=object()), \
             mock.patch.object(collector.noisemod, "load", side_effect=noise_err,
                               return_value=("entry",)), \
             mock.patch.object(collector.registry, "load", return_value=[]) as reg, \
             mock.patch.object(collector.registry, "close", return_value=list(close)), \
             mock.patch.object(collector.signal, "signal"), \
             mock.patch.object(collector, "_log", logs.append), \
             mock.patch("sys.stderr"), \
             mock.patch.object(collector, "run") as run:
            rc = collector.main(list(argv))
        return rc, run, reg, logs

    def test_refuses_root(self):
        rc, run, reg, logs = self.main(euid=0)
        self.assertEqual(rc, 2)
        run.assert_not_called()
        reg.assert_not_called()
        self.assertIn("refusing to run as root", logs[0])

    def test_no_arguments(self):
        rc, run, _, _ = self.main(argv=["x"])
        self.assertEqual(rc, 2)
        run.assert_not_called()

    def test_config_and_noise_errors(self):
        for kw in ({"cfg_err": ConfigError("bad")}, {"noise_err": ConfigError("noise.toml: x")}):
            rc, run, reg, logs = self.main(**kw)
            self.assertEqual(rc, 2, kw)
            run.assert_not_called()
            reg.assert_not_called()                          # no module loaded
            self.assertTrue(logs[0].startswith("config: "), logs)

    def test_runs_and_closes(self):
        rc, run, reg, logs = self.main(close=[("firewall", "close: OSError: x")])
        self.assertEqual(rc, 0)
        core = run.call_args.args[0]
        self.assertEqual(core.noise, ("entry",))
        self.assertEqual(logs, ["firewall: close: OSError: x"])


if __name__ == "__main__":
    unittest.main()
