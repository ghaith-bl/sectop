import unittest

from modules.firewall.track import LAG, MAX_CHANGES, Track


class TestTrack(unittest.TestCase):
    def track(self, *samples):
        t = Track()
        for wall, up in samples:
            t.add(wall, up)
        return t

    def test_empty(self):
        t = Track()
        self.assertIsNone(t.at(100.0))
        self.assertIsNone(t.window())

    def test_steady(self):
        t = self.track((100, True), (102, True), (104, True))
        self.assertEqual([t.at(x) for x in (99, 101, 103, 200)], ["up"] * 4)
        self.assertEqual(t.window(), "up")
        self.assertEqual(t.changes, [])

    def test_before_first_tick(self):
        t = self.track((100, False))
        self.assertEqual(t.at(100 - LAG), "down")            # journal lag
        self.assertIsNone(t.at(100 - LAG - 0.1))             # before sectop watched
        self.assertIsNone(t.window())                        # first tick

    def test_connect_window(self):
        t = self.track((100, False), (102, False), (104, True), (106, True))
        self.assertEqual(t.at(101), "down")
        self.assertEqual([t.at(x) for x in (102, 103, 104)], ["change"] * 3)
        self.assertEqual(t.at(105), "up")
        self.assertEqual(t.changes, [(102, 104, True)])
        self.assertEqual(t.window(), "up")

    def test_window_change(self):
        t = self.track((100, True), (102, False))
        self.assertEqual(t.window(), "change")
        t.add(104, False)
        self.assertEqual(t.window(), "down")

    def test_reconnect(self):
        t = self.track((100, True), (102, False), (104, False), (106, True))
        self.assertEqual([t.at(x) for x in (101, 103, 105, 107)],
                         ["change", "down", "change", "up"])

    def test_old_changes_fold(self):
        t = Track()
        for i in range(MAX_CHANGES + 3):
            t.add(100.0 + 2 * i, i % 2 == 0)
        self.assertEqual(len(t.changes), MAX_CHANGES)
        a, b, up = t.changes[0]
        self.assertEqual((t.first[0], t.at(a - 0.5)), (a, "up" if not up else "down"))
        self.assertIsNone(t.at(t.first[0] - LAG - 1))        # folded away: unknown


if __name__ == "__main__":
    unittest.main()
