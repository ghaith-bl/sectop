import curses
import unittest

from core import module, render
import re

from core.render import BH, BV, CROSS, RT, SPARK, TD, TR, TU, cols, fit, layout, pad
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


def frame(view=None, feed=(), ui=None, width=100, height=40, now=None, alerts=(), ref=None):
    view = [mod()] if view is None else view
    ui = ui or UI(len(SCR))
    return layout(SCR, view, list(feed), ui, width, height, now=now, tsfmt=lambda ts: "12:00:00",
                  alerts=alerts, ref=ref, stampfmt=lambda ts: "2026-10-25 12:00:00")


def alert(key, sev, title, count=1, state="open", noise=None):
    """Shape of core/alerts.py active() items (only what the bar reads)."""
    return {"key": key, "module": key.split("/")[0], "sev": sev, "title": title,
            "count": count, "state": state, "noise": noise}


def lay(*a, **kw):
    return frame(*a, **kw).lines


def find(lines, needle):
    return [text(line) for line in lines if needle in text(line)]


def border(lines, title, state):
    """A top border with title on the left and state flush right: one dash, then the
    box's corner or junction."""
    pat = re.escape(title) + ".*" + re.escape(f" {state} ") + f"{BH}[{TR}{RT}{TD}{TU}{CROSS}]"
    return [text(line) for line in lines if re.search(pat, text(line))]


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
        self.assertEqual(lines[0][1], ("[1 one]", "tabon"))
        self.assertEqual(lines[0][3], ("2 two", "note"))
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
        self.assertTrue(bar.startswith(" CRIT c   WARN e   ?? a"))
        self.assertTrue(bar.endswith("3 alerts "))
        self.assertEqual(text(lay([mod(status="ok")])[1]), " no alerts")

    def test_engine_alerts(self):
        al = [alert("fw/h", "crit", "handshake stale"),
              alert("fw/in", "warn", "new in_vpn", count=3),
              alert("fw/lan", "info", "new out_lan"),
              alert("fw/x", "crit", "silenced", noise="steam disc"),
              alert("fw/old", "warn", "new out_dns", state="held")]
        view = [mod(engine=True, status="crit"), mod(name="sys", status="unknown")]
        f = frame(view, alerts=al)
        bar = text(f.lines[1])
        self.assertTrue(bar.startswith(" CRIT handshake stale   WARN new in_vpn x3   "
                                       "WARN new out_dns   ?? sys"))
        self.assertTrue(bar.endswith("4 alerts  1 info  1 noise "))
        self.assertNotIn("CRIT firewall", bar)          # engine module: alerts, not its name
        self.assertEqual(part(f.lines[1:2], "new out_dns"), (" new out_dns", "dim"))   # held
        self.assertEqual(part(f.lines[1:2], "new in_vpn"), (" new in_vpn x3", "plain"))
        self.assertEqual(f.alerts, (("fw/h", 1, "crit"), ("fw/in", 3, "warn"),
                                    ("fw/old", 1, "warn")))

    def test_acked_alerts(self):
        al = [alert("fw/h", "crit", "handshake stale"), alert("fw/in", "warn", "new in_vpn")]
        ui = UI(len(SCR))
        ui.acks = {"fw/h": (1, "crit")}
        f = frame([mod(engine=True)], ui=ui, alerts=al)
        bar = text(f.lines[1])
        self.assertTrue(bar.startswith(" WARN new in_vpn   CRIT handshake stale"))  # acked last
        self.assertTrue(bar.endswith("2 alerts  1 acked "))
        self.assertEqual(part(f.lines[1:2], "CRIT"), ("CRIT", "dim"))
        al[0]["count"] = 2                               # new count: shows again
        self.assertTrue(text(lay([mod(engine=True)], ui=ui, alerts=al)[1]).startswith(" CRIT"))

    def test_acked(self):
        a = alert("k", "warn", "t", count=2)
        self.assertTrue(render.acked(a, {"k": (2, "warn")}))
        self.assertTrue(render.acked(a, {"k": (5, "crit")}))
        self.assertFalse(render.acked(a, {"k": (1, "warn")}))     # count rose
        self.assertFalse(render.acked(a, {"k": (2, "info")}))     # severity rose
        self.assertFalse(render.acked(a, {}))

    def test_bar_counts_stay_when_long(self):
        al = [alert(f"fw/{i}", "warn", f"problem number {i}") for i in range(20)]
        bar = text(frame([mod(engine=True)], alerts=al, width=80).lines[1])
        self.assertEqual(cols(bar), 80)
        self.assertTrue(bar.endswith(" 20 alerts "))
        self.assertIn("~", bar)                          # alerts cut, counts kept

    def test_no_alerts_but_info(self):
        bar = text(lay([mod(engine=True, status="ok")], alerts=[alert("k", "info", "t")])[1])
        self.assertTrue(bar.startswith(" no alerts"))
        self.assertTrue(bar.endswith("1 info "))

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
        self.assertIn("  a ack  ", text(lines[-1]))


class TestBoxes(unittest.TestCase):
    def test_content(self):
        lines = lay()
        self.assertTrue(find(lines, f"{BV}    mode      enforce"))  # glyph column: ok = blank
        self.assertTrue(find(lines, f"{BV} !  rollback  -"))         # warn
        self.assertTrue(find(lines, f"{BV}    firefox  10.2.0.1"))
        self.assertTrue(find(lines, f"{BV} !! x        149.112.x.x"))   # crit
        self.assertTrue(find(lines, f"{BV}    proc     dst"))       # header, masked widths

    def test_styles(self):
        lines = [line for line in lay() if text(line).startswith(BV)]
        self.assertEqual(part(lines, "enforce"), ("enforce", "text"))      # ok -> text color
        lines = lay()
        self.assertEqual(part(lines, "rollback")[1], "name")               # kv key
        [rb] = [line for line in lines if "rollback" in text(line)]
        self.assertIn(("-", "warn"), rb)
        self.assertEqual(part(lines, "x        149")[1], "crit")
        self.assertEqual(part(lines, " out_leak / tick ")[1], "warn")    # title sev

    def filtered(self, filt, mask=True, typing=None):
        m = mod()
        m["panels"][1]["rows"][0]["detail"] = [{"k": "rule", "v": "out_lan"}]
        ui = UI(2, filters={"firewall/conns": filt}, mask=mask, typing=typing)
        return frame([m], ui=ui)

    def test_filter_rows(self):
        f = self.filtered("fire")
        self.assertTrue(border(f.lines, "[Connections]", "/ fire  1 of 2"))   # state right
        self.assertTrue(find(f.lines, "firefox  10.2.0.1"))
        self.assertFalse(find(f.lines, "149.112"))
        self.assertEqual({b.key: b for b in f.boxes}["firewall/conns"].lines, 1)
        for filt, want in (("out_lan", 1), ("OUT_LAN", 1), ("!fire", 1), ("x 149.112.x.x", 1),
                           ("149.112.112", 1), ("!fire !x", 0), ("nothing", 0), ("!", 2)):
            f = self.filtered(filt)
            self.assertEqual({b.key: b for b in f.boxes}["firewall/conns"].lines,
                             want if want else 1, filt)              # 0 rows -> one "-" line
            if not want:
                self.assertTrue(find(f.lines, f"/ {filt}  0 of 2"))

    def test_filter_detail_uses_shown_rows(self):
        m = mod()
        ui = UI(2, filters={"firewall/conns": "149"}, detail="firewall/conns",
                sel={"firewall/conns": 0})
        f = frame([m], ui=ui)
        self.assertTrue(find(f.lines, " proc      x"))               # row 1 of the data

    def test_filter_feed_and_footer(self):
        f = frame(feed=[ev(1), ev(2, msg="other")],
                  ui=UI(2, filters={"one/events": "n1"}, typing="n1"))
        self.assertEqual(len(find(f.lines, "HFW-OUT-LEAK")), 1)
        self.assertTrue(border(f.lines, " events  2 ", "/ n1  1 of 2"))
        self.assertTrue(text(f.lines[-1]).startswith(" / n1_  enter apply  esc cancel"))
        self.assertTrue(text(frame().lines[-1]).startswith(" 1-2 screen"))
        info = {b.key: b for b in f.boxes}
        self.assertTrue(info["one/events"].filterable and info["firewall/conns"].filterable)
        self.assertFalse(info["firewall/mode"].filterable)

    def test_row_id_anchor(self):
        m = self.rows30()
        for i, r in enumerate(m["panels"][1]["rows"]):
            r["id"] = f"flow{i}"
        ui = UI(2, sel={"firewall/conns": 5})
        ui.update(frame([m], ui=ui))
        self.assertEqual(ui.anchor["firewall/conns"], "flow5")
        row = m["panels"][1]["rows"].pop(5)
        row["cells"] = ["p5", "10.0.0.9"]                            # text changed, moved up
        m["panels"][1]["rows"].insert(1, row)
        b = {b.key: b for b in frame([m], ui=ui).boxes}["firewall/conns"]
        self.assertEqual((b.sel, b.ident), (1, "flow5"))             # cursor followed the id

    def whois_frame(self, ip="149.112.112.11", **kw):
        m = mod()
        m["panels"][1]["rows"][1]["ip"] = ip
        ui = UI(2, detail="firewall/conns", sel={"firewall/conns": 1}, **kw)
        return frame([m], ui=ui)

    def test_whois_in_detail(self):
        f = self.whois_frame()
        self.assertTrue(find(f.lines, " whois     149.112.112.11: press w (RDAP by sectop-whois"))
        self.assertEqual(f.boxes[0].ip, "149.112.112.11")             # detail box carries it
        f = self.whois_frame(lookup="149.112.112.11")
        self.assertTrue(find(f.lines, "149.112.112.11: looking up (RDAP, up to 12 s) ..."))
        f = self.whois_frame(whois={"149.112.112.11": [("name", "QUAD9"), ("country", "CH")]})
        body = [text(line)[1:].rstrip(BV).rstrip() for line in f.lines
                if text(line).startswith(BV)]
        i = body.index(" whois     149.112.112.11")
        self.assertEqual(body[i + 1:i + 3], [" name      QUAD9", " country   CH"])
        f = self.whois_frame(ip="10.2.0.1")
        self.assertTrue(find(f.lines, "10.2.0.1: not a public address, no whois"))

    def test_selected_filter_in_boxinfo(self):
        m = mod()
        m["panels"][1]["rows"][1]["filter"] = "brave"
        ui = UI(len(SCR), focus={0: "firewall/conns"})
        ui.sel["firewall/conns"] = 1
        b = next(b for b in frame([m], ui=ui).boxes if b.key == "firewall/conns")
        self.assertEqual(b.pick, "brave")
        ui.sel["firewall/conns"] = 0
        b = next(b for b in frame([m], ui=ui).boxes if b.key == "firewall/conns")
        self.assertIsNone(b.pick)

    def test_selected_ip_in_boxinfo(self):
        m = mod()
        m["panels"][1]["rows"][1]["ip"] = "149.112.112.11"
        m["panels"][0]["items"][0]["ip"] = "8.8.8.8"
        info = {b.key: b for b in frame([m], ui=UI(2, sel={"firewall/conns": 1})).boxes}
        self.assertEqual((info["firewall/conns"].ip, info["firewall/mode"].ip),
                         ("149.112.112.11", "8.8.8.8"))
        info = {b.key: b for b in frame([m]).boxes}
        self.assertIsNone(info["firewall/conns"].ip)                  # row 0 has no ip
        self.assertTrue(text(frame().lines[-1]).find("w whois") > 0)

    def test_tone_styles(self):
        m = mod()
        rows = m["panels"][1]["rows"]
        rows[:] = [{"cells": [f"r{i}", "10.0.0.1"], "sev": sev, "tone": tone}
                   for i, (sev, tone) in enumerate((("ok", "blue"), ("info", "red"),
                                                    ("warn", "yellow"), ("crit", "red"),
                                                    ("warn", "plain")))]
        rows.append({"cells": ["r5", "10.0.0.1"], "sev": "info"})            # no tone: sev
        m["panels"][0]["items"][0]["tone"] = "green"
        lines = lay([m], ui=UI(2, focus={0: "firewall/mode"}))   # no cursor in the table
        styles = [part(lines, f"r{i}  ")[1] for i in range(6)]
        self.assertEqual(styles, ["blue", "red", "bold yellow", "crit", "bold plain", "info"])
        box = [line for line in lay([m]) if text(line).startswith(BV)]  # table focused
        self.assertEqual(part(box, "enforce")[1], "green")
        ui = UI(2, sel={"firewall/conns": 2})
        self.assertEqual(part(lay([m], ui=ui), "r2  ")[1], render.SEL + "bold yellow")

    def test_attr(self):
        render._ATTR.update(plain=0, red=1 << 20)
        self.assertEqual(render.attr("red"), 1 << 20)
        self.assertEqual(render.attr("sel bold red"),
                         (1 << 20) | render.curses.A_REVERSE | render.curses.A_BOLD)
        self.assertEqual(render.attr("bold plain"), render.curses.A_BOLD)
        self.assertEqual(render.attr("nope"), render.curses.A_NORMAL)

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
        self.assertTrue(text(top).startswith("\u256d\u2500 hostfw "))   # rounded corner
        self.assertIn("[Connections]", text(top))                  # same row, focused
        self.assertNotIn("out_leak", text(top))                    # spark: own row
        self.assertTrue(find(lines, " out_leak / tick "))

    def wide_tables(self):
        m = mod()
        m["panels"] = [
            {"id": "audit", "title": "audit", "type": "table", "sev": "ok",
             "columns": ["time", "src", "dst"],
             "rows": [{"cells": ["12:00:00", "[fdeb:446c:912d:8da::2]:51814", "10.0.0.1:443"],
                       "sev": "ok"}] * 3},
            {"id": "conns", "title": "conns", "type": "table", "sev": "ok",
             "columns": ["peer", "proc"],
             "rows": [{"cells": ["10.2.0.1:53", "systemd-resolve"], "sev": "ok"}]}]
        return m

    def test_shrink(self):
        self.assertEqual(render.shrink([10, 30, 8], [4, 6, 3], 40), [10, 22, 8])   # widest first
        self.assertEqual(render.shrink([10, 12], [4, 6], 10), [4, 6])              # floors hold
        self.assertEqual(render.shrink([5, 5], [3, 3], 20), [5, 5])                # fits: kept
        self.assertEqual(render.shrink([9, 9], [3, 3], 14), [7, 7])                # ties share

    def test_tables_shrink_side_by_side(self):
        # natural: audit 3+8+29+12+4 = 56, conns 3+15+11+2 = 31 (3 = severity column)
        # -> 91 cells; screen 76
        f = frame([self.wide_tables()], width=76, height=20)
        top = next(text(line) for line in f.lines if "audit" in text(line))
        self.assertIn(" conns ", top)                               # same row
        self.assertTrue(find(f.lines, f"{BV}    peer         proc "))
        [row] = find(f.lines, "12:00:00")[:1]
        self.assertIn("~", row)                                     # widest column cut
        self.assertIn("10.0.0.1:443", row)                          # others kept whole
        self.assertIn("systemd-resolve", row)
        for line in f.lines:
            self.assertLessEqual(cols(text(line)), 76)

    def test_tables_stack_below_least(self):
        f = frame([self.wide_tables()], width=50, height=20)
        tops = [text(line) for line in f.lines if text(line)[:1] in "\u256d\u251c"]
        self.assertEqual(len(tops), 3)                              # audit, conns, events rows
        top = next(text(line) for line in f.lines if "audit" in text(line))
        self.assertNotIn("conns", top)                              # conns on its own row

    def test_kv_shrinks_next_to_table(self):
        m = mod()
        m["panels"][0]["items"][1]["v"] = "armed, 2m 05s left -> /usr/sbin/nft flush chain x"
        m["panels"][1]["rows"][0]["cells"][1] = "d" * 60
        f = frame([m], width=100, height=20)
        top = next(text(line) for line in f.lines if " hostfw " in text(line))
        self.assertIn("Connections", top)                           # kv gave cells back
        self.assertTrue(find(f.lines, "rollback  armed, 2m"))
        self.assertTrue(any("~" in t for t in find(f.lines, "rollback")))

    def test_title_fits_natural_width(self):
        m = mod()
        m["panels"][0]["title"] = "hostfw counters  (11 zero hidden)"
        f = frame([m], width=120)
        self.assertTrue(find(f.lines, " hostfw counters  (11 zero hidden) "))

    def test_full_width_hint(self):
        m = mod()
        m["panels"].insert(0, {"id": "k2", "title": "k2", "type": "kv", "sev": "ok",
                               "items": [{"k": "a", "v": "b", "sev": "ok"}]})
        m["panels"][1]["width"] = "full"                 # hostfw kv: a row of its own
        lines = lay([m], width=120)
        top = next(text(line) for line in lines if " k2 " in text(line))
        self.assertNotIn("hostfw", top)                  # k2 does not share hostfw's row
        row = next(text(line) for line in lines if " hostfw " in text(line))
        self.assertNotIn("Connections", row)             # nor the next box
        self.assertEqual(cols(row), 120)

    def test_narrow_stacks(self):
        lines = lay(width=30)
        tops = [text(line) for line in lines if text(line)[:1] in "\u256d\u251c"]
        self.assertEqual(len(tops), 4)                             # 4 rows: kv, table, spark, events
        self.assertNotIn(TD, "".join(tops))                        # no box side by side

    def test_border_junctions(self):
        lines = lay(width=120)
        seps = [text(line) for line in lines if text(line).startswith("\u251c")]
        self.assertIn(TU, seps[0])                                 # kv | table row ends above
        self.assertEqual(text(lines[-2])[0], "\u2570")              # bottom border, rounded
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
        self.assertTrue(border(f.lines, "[Connections]", f"1-{page}/30"))

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
        self.assertTrue(find(f.lines, f"{BV}    proc  dst"))       # header stays
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
        self.assertEqual(row[i - 1], ("!! ", render.SEL + "crit"))        # glyph, selected too
        self.assertEqual(row[i - 2][1], render.SEL + "plain")             # pad before
        self.assertEqual(row[i + 1][1], render.SEL + "plain")             # fill after
        self.assertEqual(row[i + 2], (BV, "frame"))                         # white frame
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
        self.assertIn(f"{BV} !! 12:00:00  firewall HFW-OUT-LEAK dst 8.8.x.x n2", got[0])

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
        self.assertTrue(find(f.lines, " detail: Connections   real IPs shown   Esc close "))
        body = [text(line) for line in f.lines if text(line).startswith(BV)]
        self.assertEqual([t[1:].rstrip(BV).rstrip() for t in body[:6]],
                         [" proc      x", " dst       149.112.112.11", " severity  crit", "",
                          " TTL       64", " SRC       149.112.112.11"])  # opened: not masked
        self.assertTrue(find(f.lines, "mask on"))                          # top line: mask kept
        f = frame([m], ui=UI(2, detail="firewall/conns", sel={"firewall/conns": 1}, mask=False))
        self.assertTrue(find(f.lines, " detail: Connections   Esc close "))   # no note: mask off
        self.assertTrue(find(f.lines, "149.112.112.11"))

    def test_detail_secrets(self):
        """Rows: the module masks secrets. Detail: real IPs, secrets masked while mask is
        on; m (mask off) shows the raw argv."""
        m = mod()
        argv = "mysql --password hunter2 -h 149.112.112.11"
        m["panels"][1]["rows"][0]["detail"] = [{"k": "argv", "v": argv}]

        def body(mask):
            f = frame([m], ui=UI(2, detail="firewall/conns", mask=mask))
            return [text(line) for line in f.lines if "argv" in text(line)]
        [on] = body(True)
        self.assertIn("mysql --password *** -h 149.112.112.11", on)
        [off] = body(False)
        self.assertIn(argv, off)

    def test_cut_column_grows(self):
        """A column cut at COL_MAX takes free room in its box, the last one first."""
        self.assertEqual(render.grow([40, 40], [90, 50], 100), [50, 50])
        self.assertEqual(render.grow([40, 40], [45, 90], 100), [40, 60])
        self.assertEqual(render.grow([5, 40], [5, 40], 100), [5, 40])        # nothing cut
        m = mod()
        long = "x" * 70
        m["panels"][1]["rows"][0]["cells"] = ["firefox", long]
        m["panels"][1]["width"] = "full"
        self.assertTrue(find(lay([m], width=120), long))
        self.assertTrue(find(lay([m], width=60), "x" * 30 + render.TRUNC))  # no room: cut

    def test_dim_tone(self):
        m = mod()
        m["panels"][1]["rows"] = [{"cells": ["sudo -k", "-"], "sev": "ok", "tone": "dim"},
                                  {"cells": ["sudo -l", "-"], "sev": "warn", "tone": "dim"},
                                  {"cells": ["id", "-"], "sev": "ok"}]
        lines = lay([m], ui=UI(2, focus={0: "firewall/mode"}))
        self.assertEqual([part(lines, c)[1] for c in ("sudo -k", "sudo -l", "id  ")],
                         ["dim", "bold dim", "name"])                   # ok: column color

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
                         [" time      2026-10-25 12:00:00", " severity  crit",
                          " source    firewall",
                          " code      HFW-OUT-LEAK", " message   dst 8.8.8.8 n0"])
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


class TestDetailLoop(unittest.TestCase):
    """UI and renderer together, the way core/app.py runs them: key, layout, update.
    2026-10-22: the detail did not scroll at all. Every frame stored the text of the
    first line as the anchor and put the view back to it (found on the host: a program
    with many sockets, no way to reach the lower lines)."""

    HEIGHT = 24                                              # detail body = 18 lines

    def setUp(self):
        self.m = mod()
        self.m["panels"][1]["rows"][0]["detail"] = [
            {"k": f"sock{i}", "v": f"tcp 10.2.0.2:{40000 + i} -> 1.2.3.{i}:443"}
            for i in range(60)]
        self.ui = UI(2)
        self.draw()

    def draw(self, view=None):
        f = frame(view or [self.m], ui=self.ui, height=self.HEIGHT)
        self.ui.update(f)
        return f

    def press(self, *keys):
        for k in keys:
            self.ui.key(k if isinstance(k, int) else ord(k))
            f = self.draw()
        return f

    def type(self, text):
        """/, the old text away, then text, still typing."""
        self.press("/")
        for _ in range(60):
            self.press(127)
        return self.press(*text) if text else self.draw()

    def search(self, text):
        self.type(text)
        return self.press(10)

    def open(self, key="firewall/conns"):
        self.ui.focus[0] = key
        self.ui.key(10)
        return self.draw()

    @staticmethod
    def body(f):
        return [text(line)[1:].rstrip(BV).rstrip() for line in f.lines
                if text(line).startswith(BV)]

    def mark_text(self, f):
        """Text of the lines drawn as the current match."""
        return [text(line)[1:].rstrip(BV).strip() for line in f.lines
                if any(st.startswith("sel ") for _, st in line)]

    def test_scroll_keys(self):
        f = self.open()
        b = f.boxes[0]
        self.assertEqual((b.key, b.lines, b.page, b.off, b.ident), ("detail", 64, 18, 0, None))
        self.assertTrue(self.body(f)[0].startswith(" proc "))
        f = self.press("j", "j")
        self.assertEqual(f.boxes[0].off, 2)
        self.assertTrue(self.body(f)[0].startswith(" severity"))
        self.assertEqual(self.press(curses.KEY_DOWN).boxes[0].off, 3)
        self.assertEqual(self.press("k").boxes[0].off, 2)
        self.assertEqual(self.press(curses.KEY_UP).boxes[0].off, 1)
        self.assertEqual(self.press(curses.KEY_NPAGE).boxes[0].off, 18)      # page - 1 lines
        self.assertEqual(self.press(" ").boxes[0].off, 35)
        f = self.press("G")
        self.assertEqual(f.boxes[0].off, 46)                                 # 64 - 18
        self.assertTrue(self.body(f)[-1].startswith(" sock59"))
        self.assertEqual(self.press(curses.KEY_END).boxes[0].off, 46)
        self.assertEqual(self.press(curses.KEY_PPAGE).boxes[0].off, 29)
        self.assertEqual(self.press("g").boxes[0].off, 0)
        self.assertEqual(self.press("G", curses.KEY_HOME).boxes[0].off, 0)

    def test_help_scrolls_too(self):
        self.HEIGHT = 12                                      # help is longer than the box
        f = self.press("?")
        b = f.boxes[0]
        self.assertEqual(b.key, "help")
        self.assertGreater(b.lines, b.page)
        self.assertFalse(find(f.lines, "quit"))
        f = self.press("G")
        self.assertTrue(find(f.lines, "quit"))
        self.assertEqual(self.press("g").boxes[0].off, 0)

    def test_footer_names_the_keys(self):
        self.assertTrue(text(self.open().lines[-1]).startswith(
            " up down PgUp PgDn scroll  g G Home End top / end  / search  n N match"))
        self.press(27)
        self.assertTrue(text(self.press("?").lines[-1]).startswith(" up down PgUp PgDn scroll"))
        self.press(27)
        self.assertTrue(text(self.draw().lines[-1]).startswith(" 1-2 screen"))

    def test_search_jumps_to_the_match(self):
        self.open()
        f = self.type("1.2.3.54:")
        b = f.boxes[0]
        self.assertEqual(self.mark_text(f), ["sock54    tcp 10.2.0.2:40054 -> 1.2.3.54:443"])
        self.assertEqual((b.mark, b.off), (4 + 54, 46))       # 4 pairs above sock0; end clamps
        self.assertTrue(find(f.lines, "/ 1.2.3.54:  1/1  47-64/64"))
        self.assertTrue(text(f.lines[-1]).startswith(" / 1.2.3.54:_  enter keep  esc cancel"))
        self.assertEqual(self.press(10).boxes[0].mark, 4 + 54)                # enter keeps
        self.assertEqual((self.ui.typing, self.ui.detail), (None, "firewall/conns"))
        self.assertTrue(text(self.draw().lines[-1]).startswith(" up down PgUp"))

    def test_search_marks_every_match_bold(self):
        self.open()
        f = self.type("1.2.3.1")                              # sock1 and sock10 .. sock19
        lit = [text(line) for line in f.lines
               if any(st.endswith("bold text") or st.endswith("bold name") for _, st in line)]
        self.assertEqual(len(lit), 5)                         # 11 matches, 5 in view
        self.assertEqual(len([line for line in f.lines if not any(
            "bold" in st for _, st in line) and "sock1" in text(line)]), 0)
        self.assertTrue(find(f.lines, "/ 1.2.3.1  1/11  1-18/64"))
        self.assertEqual(self.mark_text(f), ["sock1     tcp 10.2.0.2:40001 -> 1.2.3.1:443"])

    def test_next_previous_wrap(self):
        self.open()
        self.search("1.2.3.1")
        seen = []
        for _ in range(11):
            seen.append(self.press("n").boxes[0].mark)
        self.assertEqual(seen, [14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 5])   # wraps to the first
        self.assertEqual(self.press("N").boxes[0].mark, 23)                   # and back
        self.assertEqual(self.press("N").boxes[0].mark, 22)
        f = self.press("n")
        self.assertEqual(f.boxes[0].mark, 23)
        self.assertTrue(find(f.lines, "/ 1.2.3.1  11/11"))
        self.assertEqual(self.mark_text(f), ["sock19    tcp 10.2.0.2:40019 -> 1.2.3.19:443"])

    def test_search_masked_form(self):
        """Mask on: tables show 1.2.x.x, so that is what gets typed; the detail shows real
        IPs. 2026-10-25: the table filter found the row, the detail said no match."""
        self.ui.filters["firewall/conns"] = "1.2.x.x"
        self.draw()
        f = self.open()
        self.assertEqual(f.boxes[0].mark, 4)                  # first socket line
        self.assertTrue(find(f.lines, "/ 1.2.x.x  1/60"))
        f = self.search("40007 -> 1.2.x.x")                   # real port + masked IP
        self.assertEqual(self.mark_text(f), ["sock7     tcp 10.2.0.2:40007 -> 1.2.3.7:443"])
        f = self.search("1.2.3.7:")                           # the real form still works
        self.assertEqual(f.boxes[0].mark, 4 + 7)

    def test_scrolling_drops_the_current_match(self):
        self.open()
        self.search("1.2.3.1")
        f = self.press(curses.KEY_NPAGE)                      # off 17: matches 14 .. 23 in view
        self.assertEqual((f.boxes[0].mark, self.mark_text(f)), (None, []))
        self.assertTrue(find(f.lines, "/ 1.2.3.1  -/11"))
        self.assertEqual(self.press("n").boxes[0].mark, 17)   # first match at / after the top line
        self.press("g")
        self.assertEqual(self.press("N").boxes[0].mark, 23)   # nothing above the top: wraps
        self.press(curses.KEY_NPAGE, curses.KEY_NPAGE)        # off 35: all matches are above
        self.assertEqual(self.press("n").boxes[0].mark, 5)    # nothing below: wraps

    def test_no_match_and_keys_that_do_nothing(self):
        self.open()
        f = self.type("nothing like this")
        self.assertTrue(find(f.lines, "/ nothing like this  no match"))
        self.assertEqual((f.boxes[0].mark, f.boxes[0].off), (None, 0))
        self.press(10, "n", "N")                              # nothing to move to
        self.assertEqual(self.draw().boxes[0].off, 0)
        f = self.search("")                                   # empty search = no search
        self.assertEqual(self.ui.find, "")
        self.assertFalse(find(f.lines, "no match"))

    def test_search_case_and_esc(self):
        self.open()
        f = self.search("SOCK3")
        self.assertEqual(f.boxes[0].mark, 4 + 3)              # sock3 first (case-insensitive)
        f = self.type("sock5")
        self.assertEqual(f.boxes[0].mark, 4 + 5)
        f = self.press(27)                                    # esc: back to the text before
        self.assertEqual((self.ui.find, self.ui.typing), ("SOCK3", None))
        self.assertEqual(f.boxes[0].mark, 4 + 3)              # and to its first match
        self.assertEqual(self.ui.detail, "firewall/conns")    # esc while typing: not closed

    def test_search_key_and_value(self):
        self.open()
        self.assertEqual(self.search("proc firefox").boxes[0].mark, 0)   # key, space, value
        self.assertEqual(self.search("dst").boxes[0].mark, 1)            # the key alone
        self.assertTrue(find(self.search("proc  firefox").lines, "no match"))   # one space

    def test_search_is_not_cut_by_a_wrap(self):
        pairs = [("msg", "a" * 32 + "needle" + "b" * 50), ("x", "y")]
        lines, owner = render._detail_rows(pairs, 40, False)     # value column = 35 cells
        self.assertEqual(owner, [0] * len(lines[:-1]) + [1])
        self.assertGreater(len(lines) - 1, 2)
        self.assertFalse([t for t in map(text, lines) if "needle" in t])   # cut by the wrap
        self.assertEqual(render._found(pairs, owner, "NEEDLE"), ((0, 0, len(lines) - 1),))
        self.assertEqual(render._found(pairs, owner, "zzz"), ())
        self.assertEqual(render._found([("", ""), ("a", "b")], [0, 1], "a b"), ((1, 1, 2),))

    def test_opened_from_a_filtered_table(self):
        self.ui.filters["firewall/conns"] = "1.2.3.54"
        self.draw()
        f = self.open()
        self.assertEqual((self.ui.find, f.boxes[0].mark), ("1.2.3.54", 4 + 54))
        self.assertEqual(self.mark_text(f), ["sock54    tcp 10.2.0.2:40054 -> 1.2.3.54:443"])
        self.press(27)                                        # close: search gone
        self.assertEqual((self.ui.find, self.ui.mark), ("", None))
        for filt in ("1.2.3 firefox", "!curl", ""):           # not exactly one word to look for
            self.ui.filters["firewall/conns"] = filt
            self.draw()
            self.open()
            self.assertEqual((self.ui.find, self.ui.mark), ("", None), filt)
            self.press(27)
        self.ui.filters["firewall/conns"] = "!curl 1.2.3.54"  # !words are not searched for
        self.draw()
        self.open()
        self.assertEqual(self.ui.find, "1.2.3.54")

    def test_whois_opens_the_detail_too(self):
        self.m["panels"][1]["rows"][0]["ip"] = "149.112.112.11"
        self.ui.filters["firewall/conns"] = "1.2.3.54"
        self.draw()
        self.ui.focus[0] = "firewall/conns"
        self.press("w")
        self.assertEqual((self.ui.detail, self.ui.find), ("firewall/conns", "1.2.3.54"))


class TestLook(unittest.TestCase):
    """Look (docs/architecture.md, 2026-10-20): severity glyph column, header bold +
    underline, numbers / ages right, ages from a reference time, state right in the
    border, rounded corners. Colors as before (README.md, Screen legend)."""

    NOW = 1792410745.0

    def table(self, types=None, rows=None, title="T"):
        p = {"id": "t", "title": title, "type": "table", "sev": "ok", "columns": ["name", "n"],
             "rows": rows or [{"cells": ["a", "5"], "sev": "ok"},
                              {"cells": ["bb", "10"], "sev": "warn"},
                              {"cells": ["c", "7"], "sev": "info", "tone": "blue"},
                              {"cells": ["d", "1"], "sev": "crit"}]}
        if types:
            p["types"] = types
        return mod(panels=[p])

    def body(self, f):
        return [text(line)[1:].rstrip(BV).rstrip() for line in f.lines
                if text(line).startswith(BV)]

    def test_glyph_per_severity_colors_as_before(self):
        f = frame([self.table()], ui=UI(2, focus={0: "one/events"}))    # no row selected
        row = {name: next(line for line in f.lines if f" {name} " in text(line)[4:8])
               for name in ("a", "bb", "c", "d")}
        lines = {"   ": row["a"], "!  ": row["bb"], "i  ": row["c"], "!! ": row["d"]}
        self.assertEqual(self.body(f)[1:5], ["    a     5", " !  bb    10", " i  c     7",
                                             " !! d     1"])
        for glyph, sev, row_style in (("!  ", "warn", "warn"), ("i  ", "info", "blue"),
                                      ("!! ", "crit", "crit")):
            line = lines[glyph]
            self.assertEqual(line[1], (" ", "plain"))
            self.assertEqual(line[2], (glyph, sev))              # glyph: severity color
            self.assertEqual(line[3][1], row_style)              # row: same style as before
        self.assertEqual(lines["   "][2], ("   ", "plain"))      # ok: blank, no color

    def test_header_bold_underline_labels_only(self):
        f = frame([self.table(["text", "num"])])
        [head] = [line for line in f.lines if "name" in text(line) and text(line).startswith(BV)]
        self.assertIn(("name", render.HEAD), head)
        self.assertIn(("n", render.HEAD), head)
        self.assertFalse([t for t, st in head if st == render.HEAD and not t.strip()])

    def test_numbers_right(self):
        f = frame([self.table(["text", "num"])])
        self.assertEqual(self.body(f)[:5], ["    name   n", "    a      5", " !  bb    10",
                                            " i  c      7", " !! d      1"])

    def ages(self, now=None, ref=None):
        rows = [{"cells": c, "sev": "ok"} for c in (
            ["x", str(self.NOW - 12)], ["y", str(self.NOW - 300)], ["z", "-"],
            ["v", str(self.NOW - 3 * 3600)], ["w", str(self.NOW - 3 * 86400)],
            ["u", str(self.NOW + 9)])]                                  # clock skew: not negative
        return frame([self.table(["text", "age"], rows)], now=now, ref=ref)

    def test_age_column(self):
        self.assertEqual([b[-4:].strip() for b in self.body(self.ages(self.NOW))[1:7]],
                         ["12s", "5m", "-", "3h", "3d", "0s"])
        self.assertTrue(self.body(self.ages())[1].endswith("12:00:00"))   # no time: clock

    def test_ref_freezes_ages(self):
        f = self.ages(now=self.NOW + 100, ref=self.NOW)             # paused 100 s ago
        self.assertEqual(self.body(f)[1][-4:].strip(), "12s")

    def test_age_detail_and_filter(self):
        rows = [{"cells": ["x", str(self.NOW - 12)], "sev": "ok"}]
        ui = UI(2, detail="firewall/t", sel={"firewall/t": 0})
        f = frame([self.table(["text", "age"], rows)], ui=ui, now=self.NOW)
        self.assertIn(" n         2026-10-25 12:00:00  (12s ago)", self.body(f))
        ui = UI(2, filters={"firewall/t": "2026-10-25"})            # full time is searched
        f = frame([self.table(["text", "age"], rows)], ui=ui, now=self.NOW)
        self.assertEqual({b.key: b for b in f.boxes}["firewall/t"].lines, 1)

    def test_anchor_stable_while_ages_move(self):
        rows = [{"cells": [f"p{i}", str(self.NOW - i)], "sev": "ok"} for i in range(30)]
        m = self.table(["text", "age"], rows)
        ui = UI(2, sel={"firewall/t": 5})
        ui.update(frame([m], ui=ui, now=self.NOW))
        ident = ui.anchor["firewall/t"]
        m["panels"][0]["rows"][:0] = [{"cells": ["new", str(self.NOW)], "sev": "ok"}]
        b = {b.key: b for b in frame([m], ui=ui, now=self.NOW + 7).boxes}["firewall/t"]
        self.assertEqual((b.sel, b.ident), (6, ident))            # same row, ages moved
        self.assertEqual(ident, f"p5  {self.NOW - 5}")            # raw cells, not the text

    def test_events_glyph_and_age(self):
        f = frame(feed=[ev(0, sev="warn")], now=1760870792.0)
        [line] = find(f.lines, "HFW-OUT-LEAK")
        self.assertIn(f"{BV} !   12s  firewall HFW-OUT-LEAK dst 8.8.x.x n0", line)

    def test_state_right_never_over_title(self):
        title = "a long title that takes the room"
        ui = UI(2, filters={"firewall/t": "x" * 50})
        f = frame([self.table(title=title)], ui=ui, width=60)
        [top] = find(f.lines, title)
        self.assertNotIn("xxxx", top)                            # no room: typed text left out
        self.assertTrue(border(f.lines, title, "0 of 4"))        # the counts stay
        f = frame([self.table(title="T")], ui=UI(2, filters={"firewall/t": "bb"}), width=60)
        self.assertTrue(border(f.lines, "[T]", "/ bb  1 of 4"))


if __name__ == "__main__":
    unittest.main()


class TestCard(unittest.TestCase):
    """c = program card: rows of every module (every screen) that name the program."""

    def setUp(self):
        self.fw = mod()
        self.fw["panels"][1]["rows"][0]["progs"] = ["firefox"]
        self.sec = {"name": "security", "status": "ok", "summary": "", "flags": [],
                    "stale": False, "waiting": False,
                    "panels": [{"id": "commands", "title": "commands 2", "type": "table",
                                "sev": "ok", "columns": ["last", "cmd"],
                                "types": ["age", "text"],
                                "rows": [{"cells": ["1760870770.0", "id"], "sev": "warn",
                                          "progs": ["firefox", "bash"]},
                                         {"cells": ["1760870700.0", "ls"], "sev": "ok",
                                          "progs": ["bash"]}]}]}
        self.ui = UI(len(SCR))
        self.ui.focus[0] = "firewall/conns"
        self.draw()

    def draw(self):
        f = frame([self.fw, self.sec], ui=self.ui, now=1760870780.0)
        self.ui.update(f)
        return f

    def test_open_lists_every_module(self):
        self.ui.key(ord("c"))
        f = self.draw()
        self.assertEqual(self.ui.card, "firefox")
        self.assertTrue(self.ui.paused)
        self.assertTrue(find(f.lines, "card: firefox   2 rows in 2 boxes, all screens"))
        self.assertTrue(find(f.lines, "firewall/conns"))
        self.assertTrue(find(f.lines, "security/commands"))   # not on this screen
        row = find(f.lines, "security/commands")[0]
        self.assertIn("10s", row)                                # its age
        self.assertIn("id", row)
        self.assertFalse(find(f.lines, " ls"))                  # bash only: not in the card
        self.assertTrue(find(f.lines, "enter detail (Esc back to the card)"))
        self.ui.key(27)
        self.draw()
        self.assertIsNone(self.ui.card)
        self.assertFalse(self.ui.paused)

    def test_enter_a_card_row_and_back(self):
        self.ui.key(ord("c"))
        self.draw()
        keys = [b.key for b in self.ui.boxes]
        self.assertEqual(keys, ["card"])
        self.ui.key(ord("j"))                                    # 2nd card row: the command
        self.draw()
        self.ui.key(10)                                          # enter: its detail
        f = self.draw()
        self.assertEqual(self.ui.detail, "card")
        self.assertTrue(find(f.lines, "box title"))                # the box it is in
        self.assertTrue(find(f.lines, "commands 2"))
        self.assertTrue(find(f.lines, "cmd"))
        self.assertTrue(find(f.lines, "2026-10-25 12:00:00"))   # age column: full time
        self.ui.key(27)                                          # Esc: back to the card
        f = self.draw()
        self.assertEqual((self.ui.card, self.ui.detail), ("firefox", None))
        self.assertTrue(self.ui.paused)
        self.assertEqual(self.ui.sel["card"], 1)                 # same row still selected
        self.ui.key(27)
        self.draw()
        self.assertIsNone(self.ui.card)

    def test_no_progs_no_card(self):
        self.ui.key(ord("j"))                                    # 2nd row: no progs
        self.draw()
        self.ui.key(ord("c"))
        self.assertIsNone(self.ui.card)

    def test_filter_in_card(self):
        self.ui.key(ord("c"))
        self.draw()
        for k in "/id":
            self.ui.key(ord(k))
        self.ui.key(10)
        f = self.draw()
        self.assertEqual(self.ui.filters.get("card"), "id")
        self.assertTrue(find(f.lines, "security/commands"))
        self.assertFalse(find(f.lines, "firewall/conns"))
        self.ui.key(27)                                          # closes the card
        self.draw()
        self.ui.key(ord("c"))
        self.assertEqual(self.ui.card, "firefox")
        self.assertNotIn("card", self.ui.filters)                # a new card: no filter


class TestSparkColumn(unittest.TestCase):
    def table(self, cell):
        return {"v": 1, "status": "ok", "summary": "", "events": [], "panels": [
            {"id": "t", "title": "t", "type": "table", "columns": ["m", "trend"],
             "types": ["text", "spark"], "rows": [{"cells": ["x", cell]}]}]}

    def test_cell(self):
        self.assertEqual(module.spark_cell("1 2 3/10"), ([1, 2, 3], 10))
        self.assertEqual(module.spark_cell(""), ([], None))
        for bad in ("a b", "1 2/0", "1/x", "nan", " ".join(["1"] * 61)):
            self.assertIsNone(module.spark_cell(bad), bad)
        module.validate(self.table("0 50 100/100"))
        with self.assertRaises(module.InvalidSnapshot):
            module.validate(self.table("1,2"))

    def test_bars(self):
        self.assertEqual(render.bars("0 50 100/100", 10), SPARK[0] + SPARK[4] + SPARK[7])
        self.assertEqual(render.bars("1 2 3 4", 2), SPARK[5] + SPARK[7])       # last values, 0..max
        self.assertEqual(render.bars("5 5", 4), SPARK[7] * 2)
        self.assertEqual(render.bars("0 0", 4), SPARK[0] * 2)
        self.assertEqual(render.bars("", 4), "")
        self.assertEqual(render.spark_text("35 36 37/100"),
                         "last 37  min 35  max 37  3 points  (scale 0-100)")

    def test_layout(self):
        view = [{"name": "system", "status": "ok", "summary": "", "flags": [], "stale": False,
                 "waiting": False, "panels": [
                     {"id": "system", "title": "system", "type": "table", "sev": "ok",
                      "width": "full", "columns": ["metric", "trend"],
                      "types": ["text", "spark"],
                      "rows": [{"cells": ["cpu", " ".join(["50"] * 60) + "/100"],
                                "sev": "ok"}]}]}]
        scr = (Screen("processes", ("system",)),)
        f = layout(scr, view, [], UI(1), 60, 20, tsfmt=lambda ts: "", stampfmt=lambda ts: "")
        line = next("".join(t for t, _ in ln) for ln in f.lines
                    if "cpu" in "".join(t for t, _ in ln) and SPARK[4] in "".join(t for t, _ in ln))
        self.assertEqual(line.count(SPARK[4]), 40)                # COL_MAX, never cut with ~
        self.assertNotIn("~", line)


class TestColors(unittest.TestCase):
    """Palette 2026-10-27 (docs/architecture.md, Look): column roles on ok rows, a problem
    row in its severity color, problem lines of a detail in their color."""

    def view(self, rows, **panel):
        p = {"id": "t", "title": "t", "type": "table", "sev": "ok", "width": "full",
             "columns": ["what", "now", "when", "note"], "types": ["text", "num", "age", "text"],
             "rows": rows}
        p.update(panel)
        return [{"name": "firewall", "status": "ok", "summary": "", "flags": [],
                 "stale": False, "waiting": False, "panels": [p]}]

    def test_roles_default(self):
        lines = lay(self.view([{"cells": ["cpu", "4%", "-", "fine"], "sev": "ok"}]))
        self.assertEqual(part(lines, "cpu")[1], render.SEL + "name")       # selected: reverse
        self.assertEqual(part(lines, "4%")[1], render.SEL + "value")
        self.assertEqual(part(lines, "fine")[1], render.SEL + "text")

    def test_roles_given_and_level(self):
        rows = [{"cells": ["temp", "79 C", "-", "warn 75"], "sev": "ok", "level": "high"}]
        lines = lay(self.view(rows, roles=["name", "value", "note", "note"]))
        self.assertEqual(part(lines, "79 C")[1], render.SEL + "high")     # near its limit
        self.assertEqual(part(lines, "warn 75")[1], render.SEL + "note")

    def test_problem_row_one_color(self):
        lines = lay(self.view([{"cells": ["temp", "90 C", "-", "crit"], "sev": "crit"}]))
        self.assertEqual(part(lines, "temp")[1], render.SEL + "crit")       # selected: reverse

    def test_detail_problem_lines(self):
        rows = [{"cells": ["temp", "90 C", "-", "x"], "sev": "crit",
                 "detail": [{"k": "why", "v": "at crit", "sev": "crit"},
                            {"k": "sensor", "v": "coretemp"}]}]
        f = frame(self.view(rows), ui=UI(2, detail="firewall/t"))
        self.assertEqual(part(f.lines, "90 C")[1], "crit")                # row cells
        self.assertEqual(part(f.lines, "at crit")[1], "crit")             # marked line
        self.assertEqual(part(f.lines, "coretemp")[1], "text")
        ok = [{"cells": ["cpu", "4%", "-", "x"], "sev": "ok"}]
        f = frame(self.view(ok), ui=UI(2, detail="firewall/t"))
        self.assertEqual(part(f.lines, "4%")[1], "text")

    def test_detail_keeps_row_programs(self):
        rows = [{"cells": ["a", "1", "-", "x"], "sev": "ok", "progs": ["org.mozilla.firefox"]}]
        f = frame(self.view(rows), ui=UI(2, detail="firewall/t"))
        self.assertEqual(f.boxes[0].progs, ("org.mozilla.firefox",))

    def test_hint_in_footer(self):
        ui = UI(2)
        ui.hint = "c: no program on this line"
        self.assertEqual(text(lay(ui=ui)[-1]), " c: no program on this line")

