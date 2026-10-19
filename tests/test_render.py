import unittest

from core import render
from core.render import SPARK, cols, fit, layout, pad

W = 80


def mod(**over):
    m = {"name": "firewall", "status": "warn", "summary": "enforce | leak 0",
         "flags": [], "stale": False,
         "panels": [
             {"id": "mode", "title": "hostfw", "type": "kv", "sev": "ok",
              "items": [{"k": "mode", "v": "enforce", "sev": "ok"},
                        {"k": "rollback", "v": "-", "sev": "warn"}]},
             {"id": "conns", "title": "Connections", "type": "table", "sev": "ok",
              "columns": ["proc", "dst"],
              "rows": [{"cells": ["firefox", "10.2.0.1"], "sev": "ok"},
                       {"cells": ["x", "149.112.112.11"], "sev": "crit"}]},
             {"id": "rate", "title": "out_leak / tick", "type": "spark", "sev": "warn",
              "values": [0, 1, 2, 3], "unit": "pkt"},
         ]}
    m.update(over)
    return m


def ev(i=0, **over):
    e = {"ts": 1760870780.0 + i, "sev": "crit", "src": "firewall",
         "code": "HFW-OUT-LEAK", "msg": f"dst 8.8.8.8 n{i}"}
    e.update(over)
    return e


def text(line):
    return "".join(t for t, _ in line)


def lay(view=None, feed=(), mask=True, width=W, height=100):
    view = [mod()] if view is None else view
    return layout(view, list(feed), mask, width, height, tsfmt=lambda ts: "12:00:00")


def find(lines, needle):
    return [text(line) for line in lines if needle in text(line)]


class TestCells(unittest.TestCase):
    def test_cols(self):
        self.assertEqual(cols("abc"), 3)
        self.assertEqual(cols("\u4e2d\u6587"), 4)          # wide
        self.assertEqual(cols("e\u0301"), 1)               # combining

    def test_fit(self):
        self.assertEqual(fit("abcdef", 6), "abcdef")
        self.assertEqual(fit("abcdef", 4), "abc~")
        self.assertEqual(fit("abc", 0), "")
        self.assertEqual(fit("\u4e2d\u6587\u5b57", 4), "\u4e2d~")   # 2 + 1 cells
        self.assertLessEqual(cols(fit("\u4e2d\u6587\u5b57", 5)), 5)

    def test_pad(self):
        self.assertEqual(pad("ab", 4), "ab  ")
        self.assertEqual(pad("\u4e2d", 4), "\u4e2d  ")
        self.assertEqual(pad("abcdef", 3), "ab~")


class TestLayout(unittest.TestCase):
    def test_header_and_panels(self):
        lines = lay()
        self.assertTrue(text(lines[0]).startswith("sectop  mask on"))
        self.assertEqual(text(lines[1]), "[WARN] firewall  enforce | leak 0")
        self.assertEqual(lines[1][0], ("[WARN]", "warn"))
        self.assertEqual(find(lines, "rollback"), ["    rollback  -"])
        self.assertEqual(find(lines, "firefox"), ["    firefox  10.2.0.1"])

    def test_styles(self):
        lines = lay()
        [mode] = [line for line in lines if "enforce" in text(line) and "mode" in text(line)]
        self.assertEqual(mode[-1], ("enforce", "plain"))           # ok -> plain
        [rb] = [line for line in lines if "rollback" in text(line)]
        self.assertEqual(rb[-1][1], "warn")
        [row] = [line for line in lines if text(line).strip().startswith("x ")]
        self.assertEqual(row[0][1], "crit")

    def test_mask(self):
        lines = lay(feed=[ev()])
        self.assertEqual(find(lines, "149.112."), ["    x        149.112.x.x"])
        self.assertTrue(find(lines, "dst 8.8.x.x n0"))
        self.assertFalse(find(lines, "8.8.8.8"))
        self.assertTrue(text(lay(mask=False)[0]).startswith("sectop  mask off"))
        lines = lay(feed=[ev()], mask=False)
        self.assertTrue(find(lines, "149.112.112.11"))
        self.assertTrue(find(lines, "dst 8.8.8.8 n0"))

    def test_mask_column_width(self):
        # Width is measured on the masked text: no extra gap.
        lines = lay()
        self.assertEqual(find(lines, "proc"), ["    proc     dst"])

    def test_clean(self):
        m = mod(name="fw", summary="a\x1b[2Jb\nc", panels=[])
        lines = lay([m], feed=[ev(msg="\x1b]0;x\x07")])
        self.assertEqual(text(lines[1]), "[WARN] fw  a?[2Jb?c")
        self.assertTrue(find(lines, "?]0;x?"))
        for line in lines:
            for t, _ in line:
                self.assertTrue(t.isprintable(), repr(t))

    def test_width_never_exceeded(self):
        wide = mod(summary="\u4e2d" * 50, flags=["error: " + "e" * 100, "stale"])
        wide["panels"][1]["rows"].append({"cells": ["\u6587" * 30, "y" * 90], "sev": "ok"})
        for width in (1, 2, 5, 10, 17, 40, 79):
            for line in lay([wide], feed=[ev(msg="m" * 200)], width=width):
                self.assertLessEqual(cols(text(line)), width, (width, text(line)))

    def test_flags_and_stale(self):
        m = mod(flags=["error: RuntimeError: x", "stale"], stale=True)
        lines = lay([m])
        self.assertTrue(text(lines[1]).endswith("  | error: RuntimeError: x  | stale"))
        self.assertEqual(lines[1][-2][1], "warn")
        self.assertEqual(lines[1][-1][1], "dim")
        self.assertEqual(len(find(lines, "(stale)")), 3)

    def test_unknown_status(self):
        lines = lay([mod(status="unknown"), mod(name="x", status="off", panels=[])])
        self.assertTrue(text(lines[1]).startswith("[??]   firewall"))
        self.assertTrue(find(lines, "[OFF]  x"))

    def test_spark(self):
        [line] = find(lay(), "\u2581")
        self.assertEqual(line, "    " + SPARK[0] + SPARK[2] + SPARK[5] + SPARK[7] + "  3 pkt")

    def test_spark_flat_and_empty(self):
        m = mod()
        m["panels"][2].update(values=[2.5, 2.5], unit="")
        self.assertEqual(find(lay([m]), SPARK[0]), ["    " + SPARK[0] * 2 + "  2.5"])
        m["panels"][2]["values"] = []
        lines = lay([m])
        i = [text(line) for line in lines].index("  out_leak / tick")
        self.assertEqual(text(lines[i + 1]), "    -")

    def test_spark_keeps_newest(self):
        m = mod()
        m["panels"][2]["values"] = list(range(100))
        [line] = find(lay([m], width=30), SPARK[7])
        self.assertTrue(line.endswith(SPARK[7] + "  99 pkt"))
        self.assertLessEqual(cols(line), 30)

    def test_events_newest_first_as_given(self):
        lines = lay(feed=[ev(2), ev(1)])
        got = find(lines, "HFW-OUT-LEAK")
        self.assertEqual(got[0], "12:00:00 CRIT firewall HFW-OUT-LEAK dst 8.8.x.x n2")
        self.assertTrue(got[1].endswith("n1"))

    def test_no_events(self):
        lines = lay()
        self.assertEqual(text(lines[-2]), "events  0")
        self.assertEqual(text(lines[-1]), "  -")

    def test_height_events_kept(self):
        view = [mod(name=f"m{i}") for i in range(10)]
        feed = [ev(i) for i in range(50)]
        lines = lay(view, feed, height=30)
        self.assertEqual(len(lines), 30)
        self.assertTrue(find(lines, "more lines"))
        self.assertEqual(len(find(lines, "HFW-OUT-LEAK")), render.EVENTS_MIN - 1)

    def test_height_body_fits_feed_cut(self):
        lines = lay(feed=[ev(i) for i in range(50)], height=30)
        self.assertEqual(len(lines), 30)
        self.assertFalse(find(lines, "more lines"))
        self.assertTrue(find(lines, "Connections"))

    def test_tiny_screen(self):
        for h in (0, 1, 2, 3, 7):
            self.assertLessEqual(len(lay(feed=[ev()], height=h)), h)
        self.assertEqual(lay(width=0), [])


if __name__ == "__main__":
    unittest.main()
