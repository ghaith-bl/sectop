import unittest

from core import render
from core.render import BH, BV, CROSS, SPARK, TD, TU, cols, fit, layout, pad
from core.screens import Screen
from core.ui import UI

SCR = (Screen("one", ("firewall",), feed=True), Screen("two", (), note="soon"))


def mod(**over):
    m = {"name": "firewall", "status": "warn", "summary": "enforce | leak 0",
         "flags": [], "stale": False, "waiting": False,
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


def frame(view=None, feed=(), ui=None, width=100, height=40, now=None):
    view = [mod()] if view is None else view
    ui = ui or UI(len(SCR))
    return layout(SCR, view, list(feed), ui, width, height, now=now, tsfmt=lambda ts: "12:00:00")


def lay(*a, **kw):
    return frame(*a, **kw).lines


def find(lines, needle):
    return [text(line) for line in lines if needle in text(line)]


def part(lines, needle):
    """(text, style) part that contains needle."""
    for line in lines:
        for t, s in line:
            if needle in t:
                return t, s
    raise AssertionError(needle)


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


class TestTop(unittest.TestCase):
    def test_tabs(self):
        lines = lay(now=1.0)
        self.assertTrue(text(lines[0]).startswith(" [1 one]  2 two"))
        self.assertTrue(text(lines[0]).endswith("mask on  12:00:00 "))
        self.assertEqual(lines[0][1], ("[1 one]", "focus"))
        ui = UI(2, screen=1, mask=False)
        line = lay(ui=ui)[0]
        self.assertTrue(text(line).startswith(" 1 one  [2 two]"))
        self.assertTrue(text(line).endswith("mask off "))

    def test_alert_bar(self):
        lines = lay()
        self.assertTrue(text(lines[1]).startswith(" WARN firewall"))
        self.assertTrue(text(lines[1]).endswith("1 alert "))
        self.assertEqual(lines[1][1], ("WARN", "warn"))

    def test_alert_order_and_filter(self):
        view = [mod(name="a", status="unknown", panels=[]), mod(name="b", status="ok"),
                mod(name="c", status="crit"), mod(name="d", status="off"),
                mod(name="e", status="warn"), mod(name="f", status="unknown", waiting=True)]
        bar = text(lay(view)[1])
        self.assertTrue(bar.startswith(" CRIT c    WARN e    ?? a"))
        self.assertTrue(bar.endswith("3 alerts "))
        self.assertEqual(text(lay([mod(status="ok")])[1]), " no alerts")

    def test_header(self):
        lines = lay()
        self.assertEqual(text(lines[2]), "[WARN] firewall  enforce | leak 0")
        self.assertEqual(lines[2][0], ("[WARN]", "warn"))
        m = mod(flags=["error: RuntimeError: x", "stale"], stale=True)
        line = lay([m])[2]
        self.assertTrue(text(line).endswith("  | error: RuntimeError: x  | stale"))
        self.assertEqual(line[-2][1], "warn")
        self.assertEqual(line[-1][1], "dim")

    def test_unknown_and_off(self):
        lines = lay([mod(status="unknown"), mod(name="x", status="off", panels=[])])
        self.assertTrue(text(lines[2]).startswith("[??]   firewall"))

    def test_footer(self):
        lines = lay()
        self.assertTrue(text(lines[-1]).startswith(" 1-2 screen  tab <- -> box"))


class TestBoxes(unittest.TestCase):
    def test_content(self):
        lines = lay()
        self.assertTrue(find(lines, f"{BV} mode      enforce"))
        self.assertTrue(find(lines, f"{BV} rollback  -"))
        self.assertTrue(find(lines, f"{BV} firefox  10.2.0.1"))
        self.assertTrue(find(lines, f"{BV} proc     dst"))         # header, masked widths

    def test_styles(self):
        lines = [line for line in lay() if text(line).startswith(BV)]
        self.assertEqual(part(lines, "enforce"), ("enforce", "plain"))     # ok -> plain
        lines = lay()
        self.assertEqual(part(lines, "rollback")[1], "dim")                # kv key
        [rb] = [line for line in lines if "rollback" in text(line)]
        self.assertIn(("-", "warn"), rb)
        self.assertEqual(part(lines, "x        149")[1], "crit")
        self.assertEqual(part(lines, " out_leak / tick ")[1], "warn")    # title sev

    def test_mask(self):
        lines = lay(feed=[ev()])
        self.assertTrue(find(lines, "x        149.112.x.x"))
        self.assertTrue(find(lines, "dst 8.8.x.x n0"))
        self.assertFalse(find(lines, "8.8.8.8"))
        lines = lay(feed=[ev()], ui=UI(2, mask=False))
        self.assertTrue(find(lines, "149.112.112.11"))
        self.assertTrue(find(lines, "dst 8.8.8.8 n0"))

    def test_clean(self):
        m = mod(name="firewall", summary="a\x1b[2Jb\nc")
        m["panels"][0]["title"] = "t\x1b]0;x\x07"
        lines = lay([m], feed=[ev(msg="\x1b]0;x\x07")])
        self.assertEqual(text(lines[2]), "[WARN] firewall  a?[2Jb?c")
        self.assertTrue(find(lines, "t?]0;x?"))
        self.assertTrue(find(lines, "HFW-OUT-LEAK ?]0;x?"))
        for line in lines:
            for t, _ in line:
                self.assertTrue(t.isprintable(), repr(t))

    def test_grid_width_exact(self):
        wide = mod(summary="\u4e2d" * 50, flags=["error: " + "e" * 100, "stale"], stale=True)
        wide["panels"][1]["rows"].append({"cells": ["\u6587" * 30, "y" * 90], "sev": "ok"})
        wide["panels"][0]["title"] = "\u4e2d" * 40
        for width in (1, 2, 3, 4, 5, 10, 17, 40, 79, 120, 173):
            for line in lay([wide], feed=[ev(msg="m" * 200)], width=width):
                n = cols(text(line))
                self.assertLessEqual(n, width, (width, text(line)))
                if text(line)[:1] in (BV,) or text(line)[:1] in "\u250c\u251c\u2514":
                    self.assertEqual(n, width, (width, text(line)))

    def test_pack_side_by_side(self):
        lines = lay(width=120)
        top = lines[3]
        self.assertTrue(text(top).startswith("\u250c\u2500 hostfw "))
        self.assertIn("[Connections]", text(top))                  # same row, focused
        self.assertNotIn("out_leak", text(top))                    # spark: own row
        self.assertTrue(find(lines, " out_leak / tick "))

    def test_narrow_stacks(self):
        lines = lay(width=30)
        tops = [text(line) for line in lines if text(line)[:1] in "\u250c\u251c"]
        self.assertEqual(len(tops), 4)                             # 4 rows: kv, table, spark, events
        self.assertNotIn(TD, "".join(tops))                        # no box side by side

    def test_border_junctions(self):
        lines = lay(width=120)
        seps = [text(line) for line in lines if text(line).startswith("\u251c")]
        self.assertIn(TU, seps[0])                                 # kv | table row ends above
        self.assertEqual(text(lines[-2])[0], "\u2514")              # bottom border
        self.assertTrue(set(text(lines[-2])[1:-1]) <= {BH, TU})

    def test_height_grow_events(self):
        f = frame(feed=[ev(1), ev(2)], height=40)
        self.assertEqual(len(f.lines), 40)
        info = {b.key: b for b in f.boxes}
        self.assertEqual(list(info), ["firewall/mode", "firewall/conns", "firewall/rate",
                                      "one/events"])
        self.assertGreater(info["one/events"].page, 2)              # leftover lines go here
        self.assertEqual(info["firewall/mode"].lines, 2)
        self.assertEqual(info["firewall/mode"].page, 3)                 # row height = table

    def test_height_shrink_tallest(self):
        m = mod()
        m["panels"][1]["rows"] = [{"cells": [f"p{i}", "10.0.0.1"], "sev": "ok"}
                                  for i in range(30)]
        f = frame([m], feed=[ev()], height=20)
        self.assertEqual(len(f.lines), 20)
        info = {b.key: b for b in f.boxes}
        self.assertEqual(info["firewall/conns"].lines, 30)
        self.assertLess(info["firewall/conns"].page, 30)
        page = info["firewall/conns"].page
        self.assertTrue(find(f.lines, f"[Connections]  1-{page}/30 "))

    def rows30(self):
        m = mod()
        m["panels"][1]["rows"] = [{"cells": [f"p{i}", "10.0.0.1"], "sev": "ok"}
                                  for i in range(30)]
        return m

    def test_cursor_scrolls_header_pinned(self):
        m = self.rows30()
        f = frame([m], height=20)
        page = {b.key: b for b in f.boxes}["firewall/conns"].page
        ui = UI(2, sel={"firewall/conns": 20})
        f = frame([m], ui=ui, height=20)
        b = {b.key: b for b in f.boxes}["firewall/conns"]
        self.assertEqual((b.sel, b.off), (20, 20 - page + 1))
        self.assertTrue(b.ident.startswith("p20 ") and b.ident.endswith("10.0.0.1"))
        self.assertTrue(find(f.lines, f"{BV} proc  dst"))          # header stays
        self.assertFalse(find(f.lines, f"p{20 - page} "))
        self.assertTrue(find(f.lines, "p20 "))
        ui = UI(2, sel={"firewall/conns": 999})                     # clamped
        f = frame([m], ui=ui, height=20)
        self.assertEqual({b.key: b for b in f.boxes}["firewall/conns"].sel, 29)
        self.assertTrue(find(f.lines, f"{30 - page + 1}-30/30"))
        ui = UI(2, sel={"firewall/conns": 3}, scroll={"firewall/conns": 2})
        b = {b.key: b for b in frame([m], ui=ui, height=20).boxes}["firewall/conns"]
        self.assertEqual((b.sel, b.off), (3, 2))                    # visible: offset kept

    def test_cursor_highlight(self):
        ui = UI(2, sel={"firewall/conns": 1})
        lines = lay(ui=ui)
        [row] = [line for line in lines if "149.112" in text(line)]
        i = row.index(("x        149.112.x.x", render.SEL + "crit"))
        self.assertEqual(row[i - 1][1], render.SEL + "plain")             # pad before
        self.assertEqual(row[i + 1][1], render.SEL + "plain")             # fill after
        self.assertEqual(row[i + 2], (BV, "dim"))
        [kv] = [line for line in lines if "enforce" in text(line) and "mode" in text(line)]
        self.assertFalse(any(s.startswith(render.SEL) for _, s in kv))   # not focused

    def test_cursor_anchor(self):
        m = self.rows30()
        ui = UI(2, sel={"firewall/conns": 5})
        ui.update(frame([m], ui=ui))
        ident = ui.anchor["firewall/conns"]
        self.assertTrue(ident.startswith("p5 "))
        m["panels"][1]["rows"][:0] = [{"cells": ["new", "10.0.0.9"], "sev": "ok"}] * 2
        b = {b.key: b for b in frame([m], ui=ui).boxes}["firewall/conns"]
        self.assertEqual((b.sel, b.ident), (7, ident))              # same line, 2 rows down
        ui = UI(2, sel={"firewall/conns": 0}, anchor={"firewall/conns": ident})
        b = {b.key: b for b in frame([m], ui=ui).boxes}["firewall/conns"]
        self.assertEqual(b.sel, 0)                                  # line 0 follows newest
        ui = UI(2, sel={"firewall/conns": 5}, anchor={"firewall/conns": "gone"})
        b = {b.key: b for b in frame([m], ui=ui).boxes}["firewall/conns"]
        self.assertEqual(b.sel, 5)                                  # not found: same index

    def test_focus(self):
        f = frame()
        self.assertEqual(f.focus, "firewall/conns")                # default: first table
        self.assertEqual(part(f.lines, "[Connections]"), ("[Connections]", "focus"))
        ui = UI(2, focus={0: "firewall/mode"})
        f = frame(ui=ui)
        self.assertEqual((f.focus, part(f.lines, "[hostfw]")[1]), ("firewall/mode", "focus"))
        self.assertEqual(part(f.lines, " Connections ")[1], "title")
        ui = UI(2, focus={0: "gone"})
        self.assertEqual(frame(ui=ui).focus, "firewall/conns")      # gone -> default
        scr = (Screen("one", ("firewall",), focus="firewall/rate"),)
        f = layout(scr, [mod()], [], UI(1), 100, 40)
        self.assertEqual(f.focus, "firewall/rate")                  # screen preference
        self.assertTrue(find(f.lines, "[out_leak / tick]"))

    def test_stale(self):
        lines = lay([mod(stale=True)])
        self.assertEqual(sum(text(line).count("(stale)") for line in lines), 3)

    def test_spark(self):
        [line] = find(lay(), SPARK[0])
        self.assertIn(f"{BV} " + SPARK[0] + SPARK[2] + SPARK[5] + SPARK[7] + "  3 pkt ", line)

    def test_spark_flat_and_empty(self):
        m = mod()
        m["panels"][2].update(values=[2.5, 2.5], unit="")
        self.assertTrue(find(lay([m]), f"{BV} " + SPARK[0] * 2 + "  2.5 "))
        m["panels"][2]["values"] = []
        lines = lay([m])
        i = next(i for i, line in enumerate(lines) if "out_leak / tick" in text(line))
        self.assertTrue(text(lines[i + 1]).startswith(f"{BV} - "))

    def test_spark_keeps_newest(self):
        m = mod()
        m["panels"][2]["values"] = list(range(100))
        [line] = find(lay([m], width=30), SPARK[7])
        self.assertIn(SPARK[7] + "  99 pkt", line)
        self.assertEqual(cols(line), 30)


class TestFeedAndScreens(unittest.TestCase):
    def test_events_this_screen_only(self):
        lines = lay(feed=[ev(2), ev(1, src="other", msg="hidden")])
        self.assertTrue(find(lines, " events  1 "))
        got = find(lines, "HFW-OUT-LEAK")
        self.assertEqual(len(got), 1)
        self.assertIn("12:00:00 CRIT firewall HFW-OUT-LEAK dst 8.8.x.x n2", got[0])

    def test_no_events(self):
        lines = lay()
        i = next(i for i, line in enumerate(lines) if " events  0 " in text(line))
        self.assertTrue(text(lines[i + 1]).startswith(f"{BV} - "))

    def test_empty_screen_note(self):
        f = frame(ui=UI(2, screen=1))
        self.assertEqual([b.key for b in f.boxes], ["two/note"])
        self.assertTrue(find(f.lines, f"{BV} soon "))
        self.assertTrue(text(f.lines[1]).startswith(" WARN firewall"))  # alerts from all screens

    def test_no_data_yet(self):
        f = frame([mod(panels=[])])
        self.assertEqual([b.key for b in f.boxes], ["one/events"])      # feed box only
        scr = (Screen("x", ("firewall",)),)
        f = layout(scr, [mod(panels=[])], [], UI(1), 100, 40)
        self.assertEqual([b.key for b in f.boxes], ["x/note"])
        self.assertTrue(find(f.lines, f"{BV} no data yet "))

    def test_module_not_on_screen(self):
        f = frame([mod(name="other")])
        self.assertEqual([b.key for b in f.boxes], ["one/note"])
        self.assertTrue(find(f.lines, f"{BV} - "))
        self.assertTrue(text(f.lines[1]).startswith(" WARN other"))

    def test_help(self):
        f = frame(ui=UI(2, help=True))
        self.assertEqual([b.key for b in f.boxes], ["help"])
        self.assertEqual(f.focus, "help")
        self.assertFalse(f.boxes[0].cursor)
        self.assertTrue(find(f.lines, "enter                 detail of the selected line"))
        self.assertTrue(find(f.lines, "q                     quit"))

    def test_paused(self):
        line = lay(ui=UI(2, paused=True), now=1.0)[0]
        self.assertTrue(text(line).endswith("PAUSED  mask on  12:00:00 "))
        self.assertIn(("PAUSED", "warn"), line)
        self.assertNotIn("PAUSED", text(lay()[0]))

    def test_detail_table_row(self):
        m = mod()
        m["panels"][1]["rows"][1]["detail"] = [{"k": "TTL", "v": "64"},
                                               {"k": "SRC", "v": "149.112.112.11"}]
        ui = UI(2, detail="firewall/conns", sel={"firewall/conns": 1})
        f = frame([m], ui=ui)
        self.assertEqual([b.key for b in f.boxes], ["detail"])
        self.assertTrue(find(f.lines, " detail: Connections   Esc close "))
        body = [text(line) for line in f.lines if text(line).startswith(BV)]
        self.assertEqual([t[1:].rstrip(BV).rstrip() for t in body[:6]],
                         [" proc      x", " dst       149.112.x.x", " severity  crit", "",
                          " TTL       64", " SRC       149.112.x.x"])    # masked
        f = frame([m], ui=UI(2, detail="firewall/conns", sel={"firewall/conns": 1}, mask=False))
        self.assertTrue(find(f.lines, "149.112.112.11"))

    def test_detail_other_kinds(self):
        def body(key, sel=0, feed=()):
            f = frame(feed=list(feed), ui=UI(2, detail=key, sel={key: sel}))
            return [text(line)[1:].rstrip(BV).rstrip() for line in f.lines
                    if text(line).startswith(BV)]
        self.assertEqual(body("firewall/mode", 1)[:2], [" rollback  -", " severity  warn"])
        self.assertEqual(body("firewall/rate")[:5],
                         [" last    3 pkt", " min     0 pkt", " max     3 pkt", " points  4",
                          " values  0 1 2 3"])
        self.assertEqual(body("one/events", 0, [ev()])[:5],
                         [" time      12:00:00", " severity  crit", " source    firewall",
                          " code      HFW-OUT-LEAK", " message   dst 8.8.x.x n0"])
        self.assertEqual(body("nope")[0].strip(), "line gone")

    def test_detail_wraps_long_values(self):
        m = mod()
        m["panels"][1]["rows"][0]["detail"] = [{"k": "msg", "v": "a" * 150 + "\u4e2d" * 10}]
        f = frame([m], ui=UI(2, detail="firewall/conns"), width=60)
        lines = [text(line) for line in f.lines if text(line).startswith(BV)]
        wrapped = [t for t in lines if "aaa" in t or "\u4e2d" in t]
        self.assertGreater(len(wrapped), 2)
        indent = 1 + len("severity") + 2                                  # pad + key column
        self.assertTrue(wrapped[1].startswith(BV + " " * indent + "a"))   # under the value
        for t in lines:
            self.assertEqual(cols(t), 60)

    def test_wrap(self):
        self.assertEqual(render.wrap("abcde", 2), ["ab", "cd", "e"])
        self.assertEqual(render.wrap("", 3), [""])
        self.assertEqual(render.wrap("\u4e2d\u4e2d\u4e2d", 3), ["\u4e2d", "\u4e2d", "\u4e2d"])
        self.assertEqual(render.wrap("abc", 0), [""])

    def test_tiny_screen(self):
        for h in range(0, 9):
            self.assertLessEqual(len(lay(feed=[ev()], height=h)), h)
        self.assertEqual(lay(width=0), [])
        f = frame(height=6)                                        # top 3 + grid 3
        self.assertEqual(len(f.lines), 6)
        self.assertEqual([b.key for b in f.boxes], ["firewall/mode", "firewall/conns"])


if __name__ == "__main__":
    unittest.main()
