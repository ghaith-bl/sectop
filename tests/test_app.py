import types
import unittest
from unittest import mock

from core import app
from core.app import Core, Quit, backoff
from core.config import ConfigError
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
        c.tick()
        self.assertEqual(s.calls, [{"st": "a"}])
        self.clock.t += 1.9
        c.tick()
        self.assertEqual(len(s.calls), 1)
        self.clock.t += 0.1
        c.tick()
        self.assertEqual(len(s.calls), 2)

    def test_view_ok(self):
        c = self.core(loaded(collect=Script(snap("warn", summary="hi"))))
        self.assertEqual(c.view()[0]["summary"], "waiting")
        self.assertEqual(c.view()[0]["status"], "unknown")
        c.tick()
        [m] = c.view()
        self.assertEqual((m["name"], m["status"], m["summary"], m["flags"], m["stale"]),
                         ("a", "warn", "hi", [], False))
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
        self.assertEqual(len(c.feed), app.FEED_MAX)
        self.assertEqual(c.feed[0]["ts"], 99.0)

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

    def test_invalid_snapshot_is_error(self):
        c = self.core(loaded(collect=Script({"v": 2})))
        c.tick()
        [m] = c.view()
        self.assertEqual(m["flags"], ["error: InvalidSnapshot: v: 1 required"])
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


class TestMain(unittest.TestCase):
    def test_config_error(self):
        with mock.patch.object(app.configmod, "load", side_effect=ConfigError("bad \x1b")), \
             mock.patch("sys.stderr") as err, \
             mock.patch.object(app.curses, "wrapper") as wrapper:
            self.assertEqual(app.main(), 2)
        wrapper.assert_not_called()
        written = "".join(c.args[0] for c in err.write.call_args_list)
        self.assertIn("sectop: config: bad ?", written)


if __name__ == "__main__":
    unittest.main()
