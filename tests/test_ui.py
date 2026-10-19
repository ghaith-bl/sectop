import curses
import unittest

from core import registry
from core.render import BoxInfo, Frame
from core.screens import SCREENS, Screen, find, names
from core.ui import ESC, TAB, UI

BOXES = (BoxInfo("m/a", 2, 5), BoxInfo("m/b", 30, 10, sel=3, off=0, ident="row3"),
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
        frame = Frame([], (BoxInfo("m/a", 9, 4, sel=2, off=1, ident="t"),), focus="m/a")
        u.update(frame)
        self.assertEqual((u.sel["m/a"], u.scroll["m/a"], u.anchor["m/a"]), (2, 1, "t"))
        self.assertEqual((u.focus[0], u.boxes), ("m/a", frame.boxes))

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


if __name__ == "__main__":
    unittest.main()
