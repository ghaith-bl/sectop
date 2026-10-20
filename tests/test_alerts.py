import copy
import datetime
import json
import unittest
from unittest import mock

from core import alerts as al
from core.noise import Entry

T0 = 1760950000.0


def chk(key, sev="warn", n=0, **over):
    c = {"key": key, "sev": sev, "title": f"title {key}", "detail": "", "n": n}
    c.update(over)
    return c


class Engine:
    """Steps one state with a fake clock (test helper)."""

    def __init__(self):
        self.state, self.now = al.empty(), T0

    def step(self, module, *checks, dt=6.0):
        self.now += dt
        self.state = al.step(self.state, module, list(checks), self.now)
        return self

    def rec(self, key):
        return self.state["alerts"][key]

    def st(self, key):
        return al.status(self.rec(key), self.now)

    def active(self, dt=0.0):
        return [(a["key"], a["state"]) for a in al.active(self.state, self.now + dt)]


class TestStep(unittest.TestCase):
    def test_new_check_opens(self):
        e = Engine().step("firewall", chk("tunnel_down:proton0", "crit"))
        r = e.rec("firewall/tunnel_down:proton0")
        self.assertEqual(e.st("firewall/tunnel_down:proton0"), "open")
        self.assertEqual((r["first"], r["since"], r["last"]), (e.now,) * 3)
        self.assertEqual((r["count"], r["sev"], r["module"], r["hold"]),
                         (1, "crit", "firewall", al.DEFAULT_HOLD))
        self.assertEqual(r["title"], "title tunnel_down:proton0")

    def test_no_repeat_while_true(self):
        e = Engine().step("fw", chk("a"))
        since = e.rec("fw/a")["since"]
        for _ in range(5):
            e.step("fw", chk("a"))
        r = e.rec("fw/a")
        self.assertEqual((r["count"], r["since"], r["last"]), (1, since, e.now))
        self.assertEqual(len(e.state["alerts"]), 1)

    def test_count_uses_n(self):
        e = Engine().step("fw", chk("leak", n=5))
        self.assertEqual(e.rec("fw/leak")["count"], 5)
        e.step("fw", chk("leak", n=3)).step("fw", chk("leak", n=0))
        self.assertEqual(e.rec("fw/leak")["count"], 8)

    def test_turning_true_counts_at_least_one(self):
        e = Engine().step("fw", chk("a", n=0))
        self.assertEqual(e.rec("fw/a")["count"], 1)
        e.step("fw").step("fw", chk("a", n=0))          # gone, back within hold
        self.assertEqual(e.rec("fw/a")["count"], 2)
        e.step("fw").step("fw", chk("a", n=4))
        self.assertEqual(e.rec("fw/a")["count"], 6)

    def test_held_then_closed(self):
        e = Engine().step("fw", chk("a"))
        last = e.rec("fw/a")["last"]
        e.step("fw")
        self.assertEqual(e.st("fw/a"), "held")
        self.assertEqual(e.active(), [("fw/a", "held")])
        self.assertEqual(al.status(e.rec("fw/a"), last + al.DEFAULT_HOLD - 0.001), "held")
        self.assertEqual(al.status(e.rec("fw/a"), last + al.DEFAULT_HOLD), "closed")
        e.step("fw", dt=al.DEFAULT_HOLD)
        self.assertEqual(e.st("fw/a"), "closed")
        self.assertEqual(e.active(), [])
        self.assertIn("fw/a", e.state["alerts"])        # record kept

    def test_back_within_hold_is_same_alert(self):
        e = Engine().step("fw", chk("a"))
        since = e.rec("fw/a")["since"]
        e.step("fw").step("fw").step("fw", chk("a"))
        self.assertEqual(e.st("fw/a"), "open")
        self.assertEqual(e.rec("fw/a")["since"], since)

    def test_back_after_hold_is_new_period(self):
        e = Engine().step("fw", chk("a"))
        first = e.rec("fw/a")["first"]
        e.step("fw").step("fw", dt=al.DEFAULT_HOLD).step("fw", chk("a"))
        r = e.rec("fw/a")
        self.assertEqual((r["first"], r["since"], r["count"]), (first, e.now, 2))

    def test_hold_from_check(self):
        e = Engine().step("fw", chk("a", hold=0.0), chk("b", hold=600.0))
        e.step("fw", dt=1.0)
        self.assertEqual(e.st("fw/a"), "closed")        # hold 0: closes at once
        self.assertEqual(e.st("fw/b"), "held")
        e.step("fw", dt=598.0)
        self.assertEqual(e.st("fw/b"), "held")
        e.step("fw", dt=2.0)
        self.assertEqual(e.st("fw/b"), "closed")

    def test_latest_values_kept(self):
        e = Engine().step("fw", chk("a", "info", title="pre-connect"))
        e.step("fw", chk("a", "crit", title="after connect", detail="d"))
        r = e.rec("fw/a")
        self.assertEqual((r["sev"], r["title"], r["detail"]), ("crit", "after connect", "d"))
        e.step("fw")
        self.assertEqual(e.rec("fw/a")["sev"], "crit")   # held keeps the last values

    def test_other_modules_untouched(self):
        e = Engine().step("fw", chk("a")).step("sys", chk("a"))
        self.assertEqual(e.st("fw/a"), "open")           # sys step does not clear fw
        e.step("fw")
        self.assertEqual((e.st("fw/a"), e.st("sys/a")), ("held", "open"))

    def test_module_not_stepped_keeps_state(self):
        e = Engine().step("fw", chk("a"))
        e.now += 3600                                    # e.g. collect failing for 1 h
        self.assertEqual(e.st("fw/a"), "open")

    def test_input_not_changed(self):
        e = Engine().step("fw", chk("a", n=2), chk("b"))
        before = copy.deepcopy(e.state)
        checks = [chk("a", n=1), chk("c")]
        kept = copy.deepcopy(checks)
        new = al.step(e.state, "fw", checks, e.now + 6)
        self.assertEqual(e.state, before)
        self.assertEqual(checks, kept)
        self.assertNotEqual(new, before)

    def test_json_data(self):
        e = Engine().step("fw", chk("a", n=3, hold=30), chk("b", "crit")).step("fw", chk("b"))
        text = json.dumps(e.state, allow_nan=False)
        self.assertEqual(json.loads(text), e.state)
        self.assertEqual(al.empty(), {"alerts": {}})


class TestActive(unittest.TestCase):
    def test_order(self):
        e = Engine().step("fw", chk("w1", "warn"), chk("i1", "info"), chk("c1", "crit"))
        e.step("fw", chk("w1", "warn"), chk("i1", "info"), chk("c1", "crit"),
               chk("w2", "warn"))
        # worst first; same severity: newest since first
        self.assertEqual(e.active(), [("fw/c1", "open"), ("fw/w2", "open"),
                                      ("fw/w1", "open"), ("fw/i1", "open")])
        e.step("fw", chk("w1", "warn"), chk("c1", "crit"))
        # same severity: open before held
        self.assertEqual(e.active(), [("fw/c1", "open"), ("fw/w1", "open"),
                                      ("fw/w2", "held"), ("fw/i1", "held")])

    def test_tie_by_key(self):
        e = Engine().step("fw", chk("b"), chk("a"))
        self.assertEqual(e.active(), [("fw/a", "open"), ("fw/b", "open")])

    def test_noise(self):
        e = Engine().step("fw", chk("ks:a", "warn"), chk("leak", "info"), chk("ks:b", "crit"))
        far = datetime.date.fromtimestamp(e.now) + datetime.timedelta(days=30)
        past = datetime.date.fromtimestamp(e.now) - datetime.timedelta(days=30)
        noise = (Entry("fw/ks:*", "proton ndp", far), Entry("fw/leak", "old", past))
        got = [(a["key"], a["noise"]) for a in al.active(e.state, e.now, noise)]
        # noise last; an expired entry does not match
        self.assertEqual(got, [("fw/leak", None), ("fw/ks:b", "proton ndp"),
                               ("fw/ks:a", "proton ndp")])
        self.assertEqual([a["noise"] for a in al.active(e.state, e.now)], [None] * 3)
        e.step("fw", chk("ks:a", "warn", n=2))                # still tracked while noise
        self.assertEqual(e.rec("fw/ks:a")["count"], 3)
        self.assertNotIn("noise", e.rec("fw/ks:a"))

    def test_copies(self):
        e = Engine().step("fw", chk("a"))
        a = al.active(e.state, e.now)[0]
        a["count"] = 99
        self.assertEqual(e.rec("fw/a")["count"], 1)
        self.assertNotIn("state", e.rec("fw/a"))


class TestTrim(unittest.TestCase):
    def test_closed_out_first_then_held_open_never(self):
        with mock.patch.object(al, "MAX_RECORDS", 4):
            e = Engine().step("fw", chk("old"), chk("held", hold=600.0))
            e.step("fw", chk("held", hold=600.0), dt=1.0)
            e.step("fw", dt=al.DEFAULT_HOLD)             # old: closed, held: held
            self.assertEqual((e.st("fw/old"), e.st("fw/held")), ("closed", "held"))
            e.step("fw", chk("o1"), chk("o2"), dt=1.0)
            self.assertEqual(set(e.state["alerts"]), {"fw/old", "fw/held", "fw/o1", "fw/o2"})
            e.step("fw", chk("o1"), chk("o2"), chk("o3"), dt=1.0)
            self.assertEqual(set(e.state["alerts"]), {"fw/held", "fw/o1", "fw/o2", "fw/o3"})
            e.step("fw", chk("o1"), chk("o2"), chk("o3"), chk("o4"), chk("o5"), dt=1.0)
            self.assertEqual(set(e.state["alerts"]),
                             {"fw/o1", "fw/o2", "fw/o3", "fw/o4", "fw/o5"})   # open kept

    def test_oldest_last_seen_out_first(self):
        with mock.patch.object(al, "MAX_RECORDS", 2):
            e = Engine().step("fw", chk("a")).step("fw", chk("b")).step("fw", chk("c"))
            self.assertEqual(set(e.state["alerts"]), {"fw/b", "fw/c"})


if __name__ == "__main__":
    unittest.main()
