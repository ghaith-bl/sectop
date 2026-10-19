import curses
import unittest

from core import registry
from core.render import BoxInfo
from core.screens import SCREENS, Screen, find, names
from core.ui import ESC, TAB, UI

BOXES = (BoxInfo("m/a", 2, 5), BoxInfo("m/b", 30, 10), BoxInfo("m/c", 1, 1))


def ui(**kw):
    u = UI(3, **kw)
    u.boxes = BOXES
    return u


class TestKeys(unittest.TestCase):
    def test_quit(self):
        for k in (ord("q"), ord("Q")):
            self.assertFalse(ui().key(k))
        self.assertFalse(ui(help=True).key(ord("q")))
        self.assertTrue(ui().key(-1))                      # getch timeout
        self.assertTrue(ui().key(ord("x")))                # unknown key ignored

    def test_screens(self):
        u = ui()
        u.key(ord("3"))
        self.assertEqual(u.screen, 2)
        u.key(ord("4"))                                    # only 3 screens
        self.assertEqual(u.screen, 2)
        u.key(ord("1"))
        self.assertEqual(u.screen, 0)

    def test_focus_cycle(self):
        u = ui()
        self.assertEqual(u.focused(), "m/a")               # default: first box
        u.key(TAB)
        self.assertEqual(u.focused(), "m/b")
        u.key(TAB)
        u.key(TAB)
        self.assertEqual(u.focused(), "m/a")               # wraps
        u.key(curses.KEY_BTAB)
        self.assertEqual(u.focused(), "m/c")

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
        self.assertEqual(u.scroll, {})

    def test_scroll_clamped(self):
        u = ui()
        u.key(TAB)                                         # m/b: 30 lines, 10 visible
        for k in (ord("j"), curses.KEY_DOWN):
            u.key(k)
        self.assertEqual(u.scroll["m/b"], 2)
        u.key(ord("G"))
        self.assertEqual(u.scroll["m/b"], 20)              # last page
        u.key(ord("j"))
        self.assertEqual(u.scroll["m/b"], 20)
        u.key(curses.KEY_PPAGE)
        self.assertEqual(u.scroll["m/b"], 11)              # page = visible - 1
        u.key(ord(" "))
        self.assertEqual(u.scroll["m/b"], 20)
        u.key(curses.KEY_HOME)
        self.assertEqual(u.scroll["m/b"], 0)
        u.key(ord("k"))
        self.assertEqual(u.scroll["m/b"], 0)

    def test_scroll_stale_offset(self):
        u = ui(scroll={"m/b": 99})                         # content shrank
        u.key(TAB)
        u.key(ord("k"))
        self.assertEqual(u.scroll["m/b"], 19)

    def test_scroll_short_box(self):
        u = ui()                                           # m/a: 2 lines, 5 visible
        u.key(ord("j"))
        u.key(curses.KEY_END)
        self.assertEqual(u.scroll["m/a"], 0)

    def test_mask(self):
        u = ui()
        u.key(ord("m"))
        self.assertFalse(u.mask)
        u.key(ord("M"))
        self.assertTrue(u.mask)

    def test_help(self):
        u = ui()
        u.key(ord("?"))
        self.assertTrue(u.help)
        u.key(ord("2"))                                    # other keys ignored in help
        u.key(TAB)
        self.assertEqual((u.screen, u.focused()), (0, "m/a"))
        u.key(ord("m"))                                    # mask still works
        self.assertFalse(u.mask)
        u.key(ESC)
        self.assertFalse(u.help)
        u.key(ord("?"))
        u.key(ord("?"))
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

    def test_empty_screens_have_a_note(self):
        for s in SCREENS:
            if not s.modules:
                self.assertTrue(s.note, s.name)


if __name__ == "__main__":
    unittest.main()
