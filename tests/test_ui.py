import curses
import unittest

from core import registry
from core.render import BoxInfo, Frame
from core.screens import SCREENS, Screen, find, names
from core.ui import ESC, FILTER_MAX, TAB, UI

BOXES = (BoxInfo("m/a", 2, 5), BoxInfo("m/b", 30, 10, sel=3, off=0, ident="row3",
                                       filterable=True),
         BoxInfo("m/c", 1, 1))


def ui(**kw):
    u = UI(3, **kw)
    u.boxes = BOXES
    return u


def info(u, key):
    return next(b for b in u.boxes if b.key == key)


class TestKeys(unittest.TestCase):
    def test_quit(self):
        for k in (ord("q"), ord("Q")):
            self.assertFalse(ui().key(k))
        self.assertTrue(ui().key(-1))                      # getch timeout
        self.assertTrue(ui().key(ord("x")))                # unknown key ignored

    def test_q_closes_overlay_first(self):
        u = ui(help=True)
        self.assertTrue(u.key(ord("q")))
        self.assertFalse(u.help)
        self.assertFalse(u.key(ord("q")))

    def test_screens(self):
        u = ui()
        u.key(ord("3"))
        self.assertEqual(u.screen, 2)
        u.key(ord("4"))                                    # only 3 screens
        self.assertEqual(u.screen, 2)
        u.key(ord("1"))
        self.assertEqual(u.screen, 0)

    def test_focus_keys(self):
        u = ui()
        self.assertEqual(u.focused(), "m/a")               # nothing resolved yet: first
        for k in (TAB, curses.KEY_RIGHT, ord("l")):
            u.key(k)
        self.assertEqual(u.focused(), "m/a")               # 3 steps right, wraps
        for k, want in ((curses.KEY_LEFT, "m/c"), (ord("h"), "m/b"), (curses.KEY_BTAB, "m/a")):
            u.key(k)
            self.assertEqual(u.focused(), want)

    def test_focus_per_screen_and_gone(self):
        u = ui()
        u.key(TAB)
        u.key(ord("2"))
        self.assertEqual(u.focused(), "m/a")               # screen 2 has its own focus
        u.key(ord("1"))
        self.assertEqual(u.focused(), "m/b")
        u.boxes = (BoxInfo("x/y", 1, 1),)
        self.assertEqual(u.focused(), "x/y")               # focused box gone -> first
        u.boxes = ()
        self.assertIsNone(u.focused())
        u.key(TAB)                                         # no boxes: nothing happens
        u.key(ord("j"))
        u.key(10)
        self.assertEqual((u.sel, u.detail), ({}, None))

    def test_cursor(self):
        u = ui(focus={0: "m/b"})                           # 30 lines, 10 visible, sel 3
        u.anchor["m/b"] = "row3"
        u.key(ord("j"))
        self.assertEqual(u.sel["m/b"], 4)
        self.assertNotIn("m/b", u.anchor)                  # moved by hand: no re-anchor
        for k, want in ((curses.KEY_DOWN, 4), (ord("k"), 2), (curses.KEY_UP, 2),
                        (ord(" "), 12), (curses.KEY_NPAGE, 12), (curses.KEY_PPAGE, -6),
                        (ord("G"), 29), (curses.KEY_END, 29), (ord("g"), 0),
                        (curses.KEY_HOME, 0)):
            u2 = ui(focus={0: "m/b"})
            u2.key(k)
            self.assertEqual(u2.sel["m/b"], max(0, want), k)

    def test_cursor_clamped(self):
        u = ui()                                           # m/a: 2 lines
        for _ in range(5):
            u.key(ord("j"))
            u.boxes = (BoxInfo("m/a", 2, 5, sel=u.sel["m/a"]),) + BOXES[1:]
        self.assertEqual(u.sel["m/a"], 1)
        u.key(ord("k"))
        u.key(ord("k"))
        self.assertEqual(u.sel["m/a"], 0)

    def test_update(self):
        u = UI(3)
        frame = Frame([], (BoxInfo("m/a", 9, 4, sel=2, off=1, ident="t"),), focus="m/a",
                      alerts=(("fw/a", 2, "warn"),))
        u.update(frame)
        self.assertEqual((u.sel["m/a"], u.scroll["m/a"], u.anchor["m/a"]), (2, 1, "t"))
        self.assertEqual((u.focus[0], u.boxes), ("m/a", frame.boxes))
        self.assertEqual(u.bar, (("fw/a", 2, "warn"),))

    def picks(self, pick):
        boxes = (BoxInfo("m/prog", 5, 5, filterable=True, pick=pick),
                 BoxInfo("m/audit", 9, 5, filterable=True), BoxInfo("m/peers", 9, 5,
                                                                    filterable=True),
                 BoxInfo("m/kv", 3, 3))
        u = UI(3, focus={0: "m/prog"})
        u.boxes = boxes
        return u

    def test_follow(self):
        u = self.picks("brave")
        u.sel["m/audit"] = 4
        u.key(ord("f"))
        self.assertEqual(u.filters, {"m/audit": "brave", "m/peers": "brave"})
        self.assertEqual(u.sel["m/audit"], 0)              # cursor back to the top
        u.key(ord("F"))                                    # again: clear
        self.assertEqual(u.filters, {})
        u.filters["m/audit"] = "other"
        u.key(ord("f"))                                    # not all on it: set
        self.assertEqual(u.filters, {"m/audit": "brave", "m/peers": "brave"})
        u = self.picks(None)
        u.key(ord("f"))
        self.assertEqual(u.filters, {})

    def test_hide(self):
        u = self.picks("brave")
        u.filters["m/audit"] = "tcp"
        u.key(ord("x"))
        self.assertEqual(u.filters, {"m/prog": "!brave", "m/audit": "tcp !brave",
                                     "m/peers": "!brave"})
        u.key(ord("X"))                                    # once only
        self.assertEqual(u.filters["m/audit"], "tcp !brave")
        u.filters["m/peers"] = "p" * (FILTER_MAX - 3)
        u.key(ord("x"))
        self.assertEqual(u.filters["m/peers"], "p" * (FILTER_MAX - 3))   # no room: unchanged
        for pick in ("? 1000", None):                      # one word only
            u = self.picks(pick)
            u.key(ord("x"))
            self.assertEqual(u.filters, {})

    def test_ack(self):
        u = ui(help=True)
        u.bar = (("fw/a", 2, "warn"), ("fw/b", 1, "crit"))
        u.acks = {"fw/gone": (1, "warn")}
        u.key(ord("a"))                                    # works in overlay too
        self.assertEqual(u.acks, {"fw/a": (2, "warn"), "fw/b": (1, "crit")})
        self.assertTrue(u.help)
        u.bar = ()
        u.key(ord("A"))
        self.assertEqual(u.acks, {})
        u = ui(focus={0: "m/b"})
        u.key(ord("/"))
        u.key(ord("a"))                                    # typing: text, not ack
        self.assertEqual((u.typing, u.acks), ("a", {}))

    def test_detail(self):
        u = ui(focus={0: "m/b"})
        u.key(10)
        self.assertEqual((u.detail, u.paused), ("m/b", True))   # opening pauses
        self.assertTrue(u.overlay)
        u.boxes = (BoxInfo("detail", 30, 10, cursor=False),)
        self.assertEqual(u.focused(), "detail")
        u.key(ord("j"))                                    # overlay text scrolls
        self.assertEqual(u.scroll["detail"], 1)
        u.boxes = (BoxInfo("detail", 30, 10, sel=1, off=1, cursor=False),)
        u.key(ord("G"))
        self.assertEqual(u.scroll["detail"], 20)
        u.key(ord("2"))                                    # other keys: no screen switch
        self.assertEqual(u.screen, 0)
        u.key(ESC)
        self.assertEqual((u.detail, u.paused), (None, False))   # resume
        self.assertEqual(u.focus[0], "m/b")                     # focus kept

    def test_detail_keeps_manual_pause(self):
        u = ui(focus={0: "m/b"}, paused=True)
        u.key(curses.KEY_ENTER)
        u.key(13)
        self.assertEqual((u.detail, u.paused), (None, True))
        u = ui(focus={0: "m/b"})
        u.key(10)
        u.key(ord("p"))                                    # p in detail: resume now
        self.assertFalse(u.paused)
        u.key(ord("p"))
        u.key(ESC)                                         # manual pause stays
        self.assertTrue(u.paused)

    def test_detail_needs_lines(self):
        u = ui(boxes=())
        u.boxes = (BoxInfo("m/x", 0, 5), BoxInfo("note", 3, 3, cursor=False))
        u.key(10)
        self.assertIsNone(u.detail)
        u.key(TAB)
        u.key(10)
        self.assertIsNone(u.detail)

    def test_pause(self):
        u = ui()
        u.key(ord("p"))
        self.assertTrue(u.paused)
        u.key(ord("P"))
        self.assertFalse(u.paused)

    def test_mask(self):
        u = ui()
        u.key(ord("m"))
        self.assertFalse(u.mask)
        u.key(ord("?"))
        u.key(ord("M"))                                    # works in overlay too
        self.assertTrue(u.mask)

    def test_help(self):
        u = ui()
        u.key(ord("?"))
        self.assertTrue(u.help)
        u.key(ord("2"))
        self.assertEqual(u.screen, 0)
        u.key(ord("?"))
        self.assertFalse(u.help)
        u.key(ord("?"))
        u.key(curses.KEY_BACKSPACE)
        self.assertFalse(u.help)


class TestFilter(unittest.TestCase):
    def typed(self, text, **kw):
        u = ui(focus={0: "m/b"}, **kw)
        u.key(ord("/"))
        for ch in text:
            u.key(ord(ch))
        return u

    def test_type_applies_live(self):
        u = self.typed("brave q")
        self.assertEqual((u.typing, u.filters), ("brave q", {"m/b": "brave q"}))
        self.assertEqual((u.sel["m/b"], u.scroll["m/b"]), (0, 0))   # cursor back to top
        self.assertTrue(u.key(ord("q")))                             # q is text, no quit
        u.key(curses.KEY_BACKSPACE)
        u.key(127)
        u.key(10)
        self.assertEqual((u.typing, u.filters), (None, {"m/b": "brave"}))   # stripped
        self.assertEqual(u.screen, 0)

    def test_esc_restores_old(self):
        u = self.typed("drop")
        u.key(10)
        u.key(ord("/"))
        self.assertEqual(u.typing, "drop")                           # edit starts from it
        u.key(ord("x"))
        u.key(ESC)
        self.assertEqual((u.typing, u.filters), (None, {"m/b": "drop"}))

    def test_empty_clears_and_esc_outside(self):
        u = self.typed("  ")
        u.key(13)
        self.assertEqual(u.filters, {})
        u = self.typed("drop")
        u.key(10)
        u.sel["m/b"] = 5
        u.key(ESC)                                                   # not typing: clear filter
        self.assertEqual((u.filters, u.sel["m/b"]), ({}, 0))
        u.key(ESC)                                                   # nothing to clear: no-op
        self.assertEqual(u.filters, {})

    def test_only_filterable_boxes(self):
        u = ui()                                                     # focus m/a: kv-like
        u.key(ord("/"))
        self.assertIsNone(u.typing)
        u = ui(focus={0: "m/b"}, help=True)
        u.key(ord("/"))                                              # overlay: ignored
        self.assertIsNone(u.typing)

    def test_limits_and_other_keys(self):
        u = self.typed("x" * 80)
        self.assertEqual(len(u.typing), 60)
        u.key(curses.KEY_DOWN)                                       # no text, no change
        u.key(0x4e2d)                                                # non-ASCII ignored
        self.assertEqual(len(u.typing), 60)
        u.key(ord("m"))                                              # text, not mask toggle
        self.assertTrue(u.mask)


class TestDetailFind(unittest.TestCase):
    """/ n N in a detail. The renderer resolves the jump (tests/test_render.py,
    TestDetailLoop); here: what the keys set and what they leave alone."""

    def detail(self, **kw):
        u = ui(detail="m/b", **kw)
        u.boxes = (BoxInfo("detail", 30, 10, cursor=False),)
        return u

    def typed(self, text, **kw):
        u = self.detail(**kw)
        u.key(ord("/"))
        for ch in text:
            u.key(ord(ch))
        return u

    def test_type_applies_live(self):
        u = self.detail()
        u.key(ord("/"))
        self.assertEqual(u.typing, "")
        self.assertEqual((u.find, u.seek), ("", None))
        u.key(ord("1"))
        self.assertEqual((u.find, u.seek, u.mark), ("1", "first", None))
        for ch in ".2 n":                                  # n, space, q ... are text here
            u.key(ord(ch))
        self.assertTrue(u.key(ord("q")))
        self.assertEqual((u.typing, u.find), ("1.2 nq", "1.2 nq"))
        u.key(curses.KEY_BACKSPACE)
        u.key(127)
        self.assertEqual(u.find, "1.2 ")
        u.key(10)
        self.assertEqual((u.typing, u.find, u.detail), (None, "1.2 ".strip(), "m/b"))

    def test_esc_restores_old_and_keeps_the_detail(self):
        u = self.typed("abc")
        u.key(10)
        u.key(ord("/"))
        self.assertEqual(u.typing, "abc")                  # edit starts from it
        u.key(ord("x"))
        u.key(ESC)
        self.assertEqual((u.typing, u.find, u.seek, u.detail), (None, "abc", "first", "m/b"))

    def test_empty_search_does_not_seek(self):
        u = self.typed("a")
        u.update(Frame([], (BoxInfo("detail", 30, 10, cursor=False),)))
        u.key(127)
        self.assertEqual((u.find, u.seek), ("", None))
        u = self.typed("   ")
        u.key(10)
        self.assertEqual((u.find, u.seek), ("", None))

    def test_next_previous_need_a_search(self):
        u = self.detail()
        u.key(ord("n"))
        u.key(ord("N"))
        self.assertIsNone(u.seek)
        u = self.typed("a")
        u.key(10)
        u.update(Frame([], (BoxInfo("detail", 30, 10, cursor=False),)))
        u.key(ord("n"))
        self.assertEqual(u.seek, "next")
        u.key(ord("N"))
        self.assertEqual(u.seek, "prev")

    def test_update_takes_the_mark_and_clears_the_ask(self):
        u = self.typed("a")
        u.key(10)
        self.assertEqual(u.seek, "first")
        u.update(Frame([], (BoxInfo("detail", 30, 10, cursor=False, mark=7),)))
        self.assertEqual((u.mark, u.seek), (7, None))
        u.key(ord("j"))                                    # a scroll by hand: no current match
        self.assertIsNone(u.mark)

    def test_close_forgets_the_search(self):
        u = self.typed("a")
        u.key(10)
        u.mark = 3
        u.key(ESC)
        self.assertEqual((u.detail, u.find, u.mark, u.seek), (None, "", None, None))

    def test_not_in_help_or_outside(self):
        u = ui(help=True)
        u.boxes = (BoxInfo("help", 30, 10, cursor=False),)
        u.key(ord("/"))
        u.key(ord("n"))
        self.assertEqual((u.typing, u.find, u.seek), (None, "", None))
        u = ui(focus={0: "m/a"})                           # n outside a detail: nothing
        u.key(ord("n"))
        self.assertEqual((u.find, u.seek), ("", None))

    def test_open_starts_at_a_one_word_filter(self):
        for filt, want in (("1.2.3.4", "1.2.3.4"), ("1.2.3.4 !curl", "1.2.3.4"),
                           ("!curl 1.2.3.4", "1.2.3.4"), ("a b", ""), ("!curl", ""), ("", "")):
            u = ui(focus={0: "m/b"}, filters={"m/b": filt} if filt else {})
            u.key(10)
            self.assertEqual((u.detail, u.find), ("m/b", want), filt)
            self.assertEqual(u.seek, "first" if want else None, filt)


class TestWhois(unittest.TestCase):
    def test_w_opens_detail_and_asks(self):
        u = ui(focus={0: "m/b"})
        u.boxes = (BoxInfo("m/b", 30, 10, sel=3, ip="8.8.8.8"),)
        u.key(ord("w"))
        self.assertEqual((u.detail, u.lookup, u.paused), ("m/b", "8.8.8.8", True))
        u.done("8.8.8.8", [("name", "GOGL")])
        self.assertEqual((u.lookup, u.whois), (None, {"8.8.8.8": [("name", "GOGL")]}))
        u.boxes = (BoxInfo("detail", 9, 9, cursor=False, ip="8.8.8.8"),)
        u.key(ord("W"))                                    # cached: no new lookup
        self.assertIsNone(u.lookup)

    def test_w_in_detail(self):
        u = ui(detail="m/b")
        u.boxes = (BoxInfo("detail", 9, 9, cursor=False, ip="1.1.1.1"),)
        u.key(ord("w"))
        self.assertEqual((u.detail, u.lookup), ("m/b", "1.1.1.1"))

    def test_w_without_ip(self):
        u = ui(focus={0: "m/b"})
        u.key(ord("w"))
        self.assertEqual((u.detail, u.lookup), (None, None))
        u = ui(help=True)
        u.boxes = (BoxInfo("help", 9, 9, cursor=False, ip="1.1.1.1"),)
        u.key(ord("w"))
        self.assertIsNone(u.lookup)
        u = ui(focus={0: "m/b"})
        u.key(ord("/"))
        u.key(ord("w"))                                    # typing a filter: text
        self.assertEqual((u.typing, u.lookup), ("w", None))

    def test_cache_limit(self):
        u = ui()
        for i in range(105):
            u.done(f"8.8.8.{i}", [])
        self.assertEqual(len(u.whois), 100)
        self.assertNotIn("8.8.8.4", u.whois)
        self.assertIn("8.8.8.5", u.whois)


class TestScreens(unittest.TestCase):
    def test_find(self):
        self.assertEqual(find("firewall"), 0)
        self.assertEqual(find("3"), 2)
        self.assertEqual(find("processes"), 2)
        for bad in ("0", "4", "", "Firewall", "\uff11", "-1", "1 "):
            with self.assertRaises(ValueError, msg=repr(bad)):
                find(bad)

    def test_names(self):
        self.assertEqual(names(), ("firewall", "security", "processes"))
        self.assertEqual(names((Screen("a"),)), ("a",))

    def test_every_module_on_one_screen(self):
        on = [m for s in SCREENS for m in s.modules]
        self.assertEqual(len(on), len(set(on)))
        listed = sorted(imp.split(".", 1)[1] for imp in registry.MODULES)
        self.assertEqual(sorted(on), listed)

    def test_firewall_screen(self):
        s = SCREENS[find("firewall")]
        self.assertFalse(s.feed)                           # audit box shows the lines
        self.assertEqual(s.focus, "firewall/audit")

    def test_empty_screens_have_a_note(self):
        for s in SCREENS:
            if not s.modules:
                self.assertTrue(s.note, s.name)



class TestCardKey(unittest.TestCase):
    """c: the card of the selected row's program (2026-10-27 host: c seemed dead)."""

    def ui(self, progs=()):
        u = UI(3)
        u.boxes = (BoxInfo("firewall/programs", 3, 3, progs=tuple(progs)),)
        u.focus[0] = "firewall/programs"
        return u

    def test_row_with_program(self):
        u = self.ui(["org.mozilla.firefox"])
        u.key(ord("c"))
        self.assertEqual((u.card, u.paused, u.hint), ("org.mozilla.firefox", True, ""))

    def test_row_without_program_says_so(self):
        u = self.ui()
        u.key(ord("c"))
        self.assertIsNone(u.card)
        self.assertEqual(u.hint, "c: no program on this line")
        u.key(ord("j"))                                  # next key: gone
        self.assertEqual(u.hint, "")

    def test_from_detail(self):
        u = self.ui(["org.mozilla.firefox"])
        u.key(10)                                        # enter: detail
        self.assertEqual(u.detail, "firewall/programs")
        u.boxes = (BoxInfo("detail", 9, 9, cursor=False, progs=("org.mozilla.firefox",)),)
        u.key(ord("c"))
        self.assertEqual((u.card, u.detail, u.paused), ("org.mozilla.firefox", None, True))
        u.key(ESC)                                       # closes the card, resumes
        self.assertEqual((u.card, u.paused), (None, False))

    def test_from_detail_without_program(self):
        u = self.ui()
        u.key(10)
        u.boxes = (BoxInfo("detail", 9, 9, cursor=False),)
        u.key(ord("c"))
        self.assertEqual((u.card, u.detail, u.hint),
                         (None, "firewall/programs", "c: no program on this line"))

class TestLogCardKeys(unittest.TestCase):
    """enter on a counter row (logs): log card, enter goes down, Esc back up."""

    REQ = ("firewall", "firewall/counters", "fwd_vm_lan")

    def ui(self):
        u = UI(3)
        u.boxes = (BoxInfo("firewall/counters", 3, 3, logs="fwd_vm_lan"),)
        u.focus[0] = "firewall/counters"
        return u

    def test_down_and_back_up(self):
        u = self.ui()
        u.key(10)
        self.assertEqual((u.logcard, u.logreq, u.detail, u.paused), (self.REQ, self.REQ, None,
                                                                     True))
        u.logs_done(self.REQ, {"lines": 1})
        self.assertEqual((u.logreq, u.logdata), (None, {"lines": 1}))
        u.boxes = (BoxInfo("logflows", 2, 2, sel=1, ident="tcp|a|b|virbr0>wlo1|vm"),)
        u.key(10)                                        # a flow: its packets
        self.assertEqual((u.logflow, u.detail), ("tcp|a|b|virbr0>wlo1|vm", None))
        u.boxes = (BoxInfo("logpkts", 5, 5, sel=2, ident="c3"),)
        u.key(10)                                        # a packet: its fields
        self.assertEqual(u.detail, "logpkts")
        u.boxes = (BoxInfo("detail", 9, 9, cursor=False),)
        u.key(ESC)                                       # fields -> packets
        self.assertEqual((u.detail, u.logflow), (None, "tcp|a|b|virbr0>wlo1|vm"))
        u.boxes = (BoxInfo("logpkts", 5, 5, sel=2, ident="c3"),)
        u.key(ESC)                                       # packets -> flows
        self.assertEqual((u.logcard, u.logflow), (self.REQ, None))
        u.boxes = (BoxInfo("logflows", 2, 2),)
        u.key(ESC)                                       # flows -> closed, resumes
        self.assertEqual((u.logcard, u.logdata, u.paused), (None, None, False))

    def test_q_backs_out_too(self):
        u = self.ui()
        u.key(10)
        u.boxes = (BoxInfo("logflows", 2, 2),)
        self.assertTrue(u.key(ord("q")))                 # closes, never quits from the card
        self.assertIsNone(u.logcard)

    def test_row_without_logs_opens_the_detail(self):
        u = UI(3)
        u.boxes = (BoxInfo("firewall/counters", 3, 3),)
        u.key(10)
        self.assertEqual((u.logcard, u.detail), (None, "firewall/counters"))

    def test_filter_flows_then_packets(self):
        u = self.ui()
        u.key(10)
        u.boxes = (BoxInfo("logflows", 2, 2, ident="f1"),)
        for k in "/icmp":
            u.key(ord(k))
        u.key(10)
        self.assertEqual(u.filters.get("logflows"), "icmp")
        u.key(10)                                        # enter after typing: down
        self.assertEqual(u.logflow, "f1")
        u.boxes = (BoxInfo("logpkts", 2, 2, ident="p1"),)
        for k in "/SYN":
            u.key(ord(k))
        u.key(10)
        self.assertEqual(u.filters.get("logpkts"), "SYN")
        u.key(ESC)                                       # back up: packet filter gone
        self.assertNotIn("logpkts", u.filters)
        self.assertEqual(u.filters.get("logflows"), "icmp")

    def test_empty_table_enter_does_nothing(self):
        u = self.ui()
        u.key(10)
        u.boxes = (BoxInfo("logflows", 0, 2),)
        u.key(10)
        self.assertIsNone(u.logflow)

    def test_late_result_of_a_closed_card(self):
        u = self.ui()
        u.key(10)
        u.boxes = (BoxInfo("logflows", 2, 2),)
        u.key(ESC)
        u.logs_done(self.REQ, {"lines": 1})
        self.assertIsNone(u.logdata)


class TestAlertsKeys(unittest.TestCase):
    def test_open_close(self):
        u = ui()
        u.key(ord("!"))
        self.assertTrue(u.alerts)
        self.assertTrue(u.key(ord("q")))                 # q closes it, no quit
        self.assertFalse(u.alerts)
        u.key(ord("!"))
        u.key(ord("!"))
        self.assertFalse(u.alerts)
        u.key(ord("!"))
        u.key(ord("2"))                                  # a screen: view closed
        self.assertEqual((u.alerts, u.screen), (False, 1))

    def test_esc_clears_a_filter_first(self):
        u = UI(3)
        u.alerts = True
        u.boxes = (BoxInfo("alerts/crit", 3, 3, filterable=True),)
        u.filters["alerts/crit"] = "sudo"
        u.key(ESC)
        self.assertEqual((u.alerts, u.filters), (True, {}))
        u.key(ESC)
        self.assertFalse(u.alerts)

    def test_not_from_an_overlay(self):
        u = ui()
        u.help = True
        u.key(ord("!"))
        self.assertFalse(u.alerts)


if __name__ == "__main__":
    unittest.main()
