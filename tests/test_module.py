import copy
import types
import unittest

from core import module as m
from core.module import InvalidSnapshot, check_module, validate, worst

GOOD = {
    "v": 1,
    "status": "warn",
    "summary": "enforce | proton0 up | leak 0",
    "panels": [
        {"id": "mode", "title": "hostfw", "type": "kv",
         "items": [{"k": "mode", "v": "enforce", "sev": "ok"}, {"k": "rollback", "v": "-"}]},
        {"id": "conns", "title": "Connections", "type": "table", "sev": "info",
         "columns": ["proc", "dst"], "rows": [{"cells": ["firefox", "10.2.0.1"]}]},
        {"id": "rate", "title": "out_leak / tick", "type": "spark", "values": [0, 1, 0.5]},
    ],
    "events": [{"ts": 1760870780.123, "sev": "crit", "code": "HFW-OUT-LEAK", "msg": "x"}],
}


def snap(**over):
    s = copy.deepcopy(GOOD)
    s.update(over)
    return s


class TestValidate(unittest.TestCase):
    def assertInvalid(self, s):
        with self.assertRaises(InvalidSnapshot):
            validate(s)

    def test_good(self):
        out = validate(snap())
        self.assertEqual(out["status"], "warn")
        self.assertEqual(out["panels"][0]["items"][1]["sev"], "ok")   # default
        self.assertEqual(out["panels"][0]["sev"], "ok")               # default
        self.assertEqual(out["panels"][1]["rows"][0]["sev"], "ok")
        self.assertEqual(out["panels"][2]["unit"], "")
        self.assertEqual(out["events"][0]["code"], "HFW-OUT-LEAK")

    def test_input_not_changed(self):
        s = snap()
        validate(s)
        self.assertEqual(s, GOOD)

    def test_unknown_keys_dropped(self):
        s = snap(extra=1)
        s["panels"][0]["color"] = "red"
        s["events"][0]["src"] = "spoofed"
        out = validate(s)
        self.assertNotIn("extra", out)
        self.assertNotIn("color", out["panels"][0])
        self.assertNotIn("src", out["events"][0])

    def test_empty_lists_ok(self):
        out = validate(snap(panels=[], events=[]))
        self.assertEqual((out["panels"], out["events"]), ([], []))

    def test_not_json(self):
        self.assertInvalid(snap(summary=b"bytes"))
        self.assertInvalid(snap(panels=[{1, 2}]))
        s = snap()
        s["panels"][2]["values"] = [float("nan")]
        self.assertInvalid(s)

    def test_top_level(self):
        self.assertInvalid([])
        self.assertInvalid(snap(v=2))
        self.assertInvalid(snap(v=True))
        self.assertInvalid(snap(v=1.0))
        self.assertInvalid(snap(status="error"))
        self.assertInvalid(snap(summary=None))
        self.assertInvalid(snap(panels={}))
        s = snap()
        del s["events"]
        self.assertInvalid(s)

    def test_panel_errors(self):
        for change in (
            lambda p: p.update(type="pie"),
            lambda p: p.update(sev="error"),
            lambda p: p.pop("title"),
            lambda p: p.update(items="x"),
            lambda p: p["items"].append({"k": "a", "v": 1}),
            lambda p: p["items"].append("x"),
        ):
            s = snap()
            change(s["panels"][0])
            self.assertInvalid(s)

    def test_duplicate_panel_id(self):
        s = snap()
        s["panels"][1]["id"] = "mode"
        self.assertInvalid(s)

    def test_table_errors(self):
        for change in (
            lambda p: p.update(columns=[]),
            lambda p: p.update(columns=["c"] * (m.MAX_COLUMNS + 1)),
            lambda p: p.update(columns=["a", 1]),
            lambda p: p["rows"].append({"cells": ["only one"]}),
            lambda p: p["rows"].append({"cells": ["a", 2]}),
        ):
            s = snap()
            change(s["panels"][1])
            self.assertInvalid(s)

    def test_spark_errors(self):
        for vals in (["1"], [True], [None]):
            s = snap()
            s["panels"][2]["values"] = vals
            self.assertInvalid(s)

    def test_event_errors(self):
        for change in (
            lambda e: e.update(sev="ok"),        # ok is not an event severity
            lambda e: e.update(ts="now"),
            lambda e: e.update(ts=True),
            lambda e: e.update(ts=-1),
            lambda e: e.pop("msg"),
        ):
            s = snap()
            change(s["events"][0])
            self.assertInvalid(s)

    def test_limits(self):
        s = snap(summary="s" * 1000)
        s["panels"] = [{"id": f"p{i}", "title": "t", "type": "kv", "items": []} for i in range(20)]
        s["events"] = [{"ts": i, "sev": "info", "code": "c", "msg": "m"} for i in range(300)]
        out = validate(s)
        self.assertEqual(len(out["summary"]), m.MAX_STR)
        self.assertTrue(out["summary"].endswith("~"))
        self.assertEqual(len(out["panels"]), m.MAX_PANELS)
        self.assertEqual(len(out["events"]), m.MAX_EVENTS)
        self.assertEqual(out["events"][0]["ts"], 200.0)       # newest kept

    def test_spark_keeps_newest(self):
        s = snap()
        s["panels"][2]["values"] = list(range(500))
        vals = validate(s)["panels"][2]["values"]
        self.assertEqual(len(vals), m.MAX_SPARK)
        self.assertEqual(vals[-1], 499)

    def test_row_detail(self):
        s = snap()
        s["panels"][1]["rows"][0]["detail"] = [{"k": "TTL", "v": "64", "x": 1},
                                               {"k": "msg", "v": "v" * 1000}]
        s["panels"][1]["rows"].append({"cells": ["a", "b"], "detail": []})
        rows = validate(s)["panels"][1]["rows"]
        self.assertEqual(rows[0]["detail"][0], {"k": "TTL", "v": "64"})   # unknown key dropped
        self.assertEqual(len(rows[0]["detail"][1]["v"]), m.MAX_STR)
        self.assertEqual(rows[1]["detail"], [])
        self.assertNotIn("detail", validate(snap())["panels"][1]["rows"][0])   # optional
        s["panels"][1]["rows"][0]["detail"] = [{"k": str(i), "v": ""} for i in range(100)]
        self.assertEqual(len(validate(s)["panels"][1]["rows"][0]["detail"]), m.MAX_DETAIL)
        for bad in ("x", [1], [{"k": "a"}], [{"k": 1, "v": "b"}], None):
            s2 = snap()
            s2["panels"][1]["rows"][0]["detail"] = bad
            self.assertInvalid(s2)

    def test_row_id(self):
        s = snap()
        s["panels"][1]["rows"][0]["id"] = "k" * 1000
        row = validate(s)["panels"][1]["rows"][0]
        self.assertEqual(len(row["id"]), m.MAX_STR)
        self.assertNotIn("id", validate(snap())["panels"][1]["rows"][0])
        s["panels"][1]["rows"][0]["id"] = 5
        self.assertInvalid(s)

    def test_ip(self):
        s = snap()
        s["panels"][1]["rows"][0]["ip"] = "2607:6bc0:0000::0010"
        s["panels"][0]["items"][0]["ip"] = "8.8.8.8"
        out = validate(s)
        self.assertEqual(out["panels"][1]["rows"][0]["ip"], "2607:6bc0::10")   # normalized
        self.assertEqual(out["panels"][0]["items"][0]["ip"], "8.8.8.8")
        self.assertNotIn("ip", out["panels"][0]["items"][1])
        for bad in ("8.8.8.8:443", "x", "", 1, None):
            s2 = snap()
            s2["panels"][1]["rows"][0]["ip"] = bad
            self.assertInvalid(s2)

    def test_tone(self):
        s = snap()
        s["panels"][0]["items"][0]["tone"] = "green"
        s["panels"][1]["rows"][0]["tone"] = "red"
        out = validate(s)
        self.assertEqual(out["panels"][0]["items"][0]["tone"], "green")
        self.assertEqual(out["panels"][1]["rows"][0]["tone"], "red")
        self.assertNotIn("tone", out["panels"][0]["items"][1])               # optional
        for bad in ("pink", "", 1, None):
            s2 = snap()
            s2["panels"][1]["rows"][0]["tone"] = bad
            self.assertInvalid(s2)
            s3 = snap()
            s3["panels"][0]["items"][0]["tone"] = bad
            self.assertInvalid(s3)

    def test_rows_cut(self):
        s = snap()
        s["panels"][1]["rows"] = [{"cells": ["a", "b"]}] * 1000
        self.assertEqual(len(validate(s)["panels"][1]["rows"]), m.MAX_ROWS)


class TestCheckModule(unittest.TestCase):
    def mod(self, **over):
        attrs = {"NAME": "firewall", "INTERVAL": 2.0,
                 "init": lambda cfg: None, "collect": lambda st: GOOD}
        attrs.update(over)
        return types.SimpleNamespace(**attrs)

    def test_good(self):
        check_module(self.mod())
        check_module(self.mod(close=lambda st: None))

    def test_bad(self):
        for over in ({"NAME": "Fire-Wall"}, {"NAME": ""}, {"NAME": None},
                     {"INTERVAL": 0.5}, {"INTERVAL": True}, {"INTERVAL": "2"},
                     {"INTERVAL": float("inf")}, {"init": None}, {"collect": 1},
                     {"close": "x"}):
            with self.assertRaises(ValueError, msg=repr(over)):
                check_module(self.mod(**over))


class TestWorst(unittest.TestCase):
    def test_worst(self):
        self.assertEqual(worst(), "ok")
        self.assertEqual(worst("ok", "crit", "info"), "crit")
        self.assertEqual(worst("info", "warn"), "warn")


if __name__ == "__main__":
    unittest.main()
