"""core/homed.py: home watch (start places of the desktop home) + reader + accept."""

import os
import tempfile
import types
import unittest
from unittest import mock

from core import config, homed, statefile

UID = os.getuid()


def pw(uid=UID, home="/var/home/null"):
    return types.SimpleNamespace(pw_uid=uid, pw_dir=home, pw_name="x")


def getpw(name):
    if name in ("null", homed.OWNER):
        return pw()
    raise KeyError(name)


class TestScan(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.home = self.dir.name

    def mk(self, rel, text="x"):
        p = os.path.join(self.home, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
        return p

    def test_esc(self):
        self.assertEqual(homed.esc("a b.desktop"), "a b.desktop")
        self.assertEqual(homed.esc("a\tb\nc\\d"), "a\\x09b\\x0ac\\x5cd")
        self.assertEqual(homed.esc("\u00e9"), "\\xc3\\xa9")
        self.assertEqual(homed.esc(os.fsdecode(b"\xff")), "\\xff")       # not UTF-8

    def test_scan(self):
        self.mk(".bashrc", "alias x=y\n")
        self.mk(".config/autostart/a.desktop")
        os.symlink("/dev/null", os.path.join(self.home, ".config/autostart/b.service"))
        self.mk(".local/bin/tool")
        spots = ((".bashrc", 0), (".profile", 0), (".config/autostart", 3), (".local/bin", 0))
        got = dict(homed.scan(self.home, spots))
        self.assertEqual(sorted(got), [".bashrc", ".config/autostart",
                                       ".config/autostart/a.desktop",
                                       ".config/autostart/b.service", ".local/bin", ".profile"])
        self.assertEqual(got[".profile"], homed.ABSENT)
        st = os.lstat(os.path.join(self.home, ".bashrc"))
        self.assertEqual(got[".bashrc"], f"f {st.st_mode & 0o7777:o} {UID} 10 {st.st_mtime_ns} "
                                         f"{st.st_ctime_ns} {st.st_ino}")
        self.assertTrue(got[".config/autostart"].startswith("d "))
        self.assertTrue(got[".config/autostart/b.service"].startswith("l "))
        self.assertTrue(got[".config/autostart/b.service"].endswith(" -> /dev/null"))
        # depth 0: the dir's own entry only; a new file inside still changes it
        before = got[".local/bin"]
        self.mk(".local/bin/new")
        after = dict(homed.scan(self.home, spots))
        self.assertNotIn(".local/bin/new", after)
        self.assertNotEqual(after[".local/bin"], before)
        # a component that is a file: absent, no error
        self.assertEqual(dict(homed.scan(self.home, ((".bashrc/x", 0),))), {".bashrc/x": "absent"})

    def test_unreadable(self):
        self.mk(".ssh/id")
        with mock.patch.object(homed.os, "listdir", side_effect=PermissionError(13, "denied")):
            got = dict(homed.scan(self.home, ((".ssh", 2),)))
        self.assertEqual(got[".ssh/*"], homed.UNREADABLE)
        with mock.patch.object(homed.os, "lstat", side_effect=PermissionError(13, "denied")):
            got = dict(homed.scan(self.home, ((".ssh", 2),)))
        self.assertEqual(got, {".ssh": homed.UNREADABLE})

    def test_limits(self):
        for i in range(homed.MAX_PER_SPOT + 5):
            self.mk(f".local/bin/f{i:04d}")
        got = homed.scan(self.home, ((".local/bin", 1), (".bashrc", 0)))
        self.assertEqual(got[homed.MAX_PER_SPOT], (".local/bin/...",
                                                   f"more than {homed.MAX_PER_SPOT} entries"))
        self.assertEqual(got[-1], (".bashrc", homed.ABSENT))

    def test_spots(self):
        rels = [r for r, _ in homed.SPOTS]
        self.assertEqual(len(rels), len(set(rels)))
        for r, d in homed.SPOTS:
            self.assertFalse(r.startswith("/") or ".." in r.split("/"), r)
            self.assertIn(d, (0, 1, 2, 3), r)
        for must in (".bashrc", ".config/autostart", ".config/systemd/user", ".local/bin",
                     ".config/environment.d", ".local/share/dbus-1/services", ".bashrc.d"):
            self.assertIn(must, rels)


class TestReport(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.base = self.dir.name
        os.makedirs(os.path.join(self.base, "null"))
        self.path = os.path.join(self.base, "null", homed.FILE)

    def write(self, d):
        statefile.write(self.path, d)

    def test_roundtrip(self):
        self.write(homed.doc("null", 1000, "/var/home/null", 100.0,
                             [(".bashrc", "f 644 1000 1 2 3 4"), (".profile", "absent")]))
        got, home = homed.load_report("null", self.base, wall=lambda: 110.0, getpw=getpw)
        self.assertEqual(got, {".bashrc": "f 644 1000 1 2 3 4", ".profile": "absent"})
        self.assertEqual(home, "/var/home/null")
        with self.assertRaisesRegex(ValueError, "old"):
            homed.load_report("null", self.base, wall=lambda: 100.0 + homed.MAX_AGE + 1,
                              getpw=getpw)
        with self.assertRaisesRegex(ValueError, "no report"):
            homed.load_report("other", self.base, wall=lambda: 110.0, getpw=getpw)
        with self.assertRaisesRegex(ValueError, "no user sectop-home"):
            homed.load_report("null", self.base, getpw=lambda n: (_ for _ in ()).throw(KeyError(n)))

    def test_not_the_owner(self):
        """Written by anyone but sectop-home (the desktop user!): refused."""
        self.write(homed.doc("null", 1000, "/h", 100.0, []))
        other = lambda n: pw(uid=UID + 1)                                 # noqa: E731
        with self.assertRaises(ValueError):
            homed.load_report("null", self.base, wall=lambda: 110.0, getpw=other)

    def test_check(self):
        ok = homed.doc("null", 1000, "/h", 1.0, [(".bashrc", "absent")])
        homed.check(ok, "null")
        for bad in ({**ok, "v": 2}, {**ok, "user": "root"}, {**ok, "ts": "x"},
                    {**ok, "home": "rel"}, {**ok, "entries": [[".a"]]},
                    {**ok, "entries": [[".a\tb", "absent"]]},
                    {**ok, "entries": [[".\u00e9", "absent"]]},
                    {**ok, "entries": [["", "absent"]]},
                    {**ok, "entries": [[".a", "x\x1b[2J"]]}):
            with self.assertRaises(ValueError, msg=bad):
                homed.check(bad, "null")


class TestKnown(unittest.TestCase):
    def test_render_parse(self):
        e = {".bashrc": "f 644 1000 1 2 3 4", ".config/autostart": "d 755 1000 0 1 2 3"}
        text = homed.render_known("null", e, "2026-11-23 12:00:00")
        self.assertEqual(homed.parse_known(text), ("null", e))
        self.assertTrue(text.isascii())
        for bad in ("entry\t.a\tf\n", "user\tnull\nwhat\n", "user\tRoot!\n"):
            with self.assertRaises(ValueError):
                homed.parse_known(bad)

    def test_diff(self):
        known = {".bashrc": "f 644 1000 1 2 3 4", ".profile": "absent",
                 ".config/autostart": "d 755 1000 0 1 2 3", ".old": "f 600 1000 1 1 1 1"}
        now = {".bashrc": "f 600 1000 1 2 9 4", ".profile": "f 644 1000 5 5 5 5",
               ".config/autostart": "d 755 1000 0 1 2 3", ".x": "absent",
               ".link": "l 777 1000 3 1 1 1 -> /tmp/x"}
        self.assertEqual(homed.diff(known, now), [
            ("changed", ".bashrc", "mode 644 -> 600, ctime"),
            ("new", ".link", "link"),
            ("gone", ".old", ""),
            ("new", ".profile", "file"),
        ])
        self.assertEqual(homed.diff(known, dict(known)), [])
        self.assertEqual(homed.what_changed("l 777 1 3 1 1 1 -> /a", "l 777 1 3 1 1 1 -> /b"),
                         "link target")
        self.assertEqual(homed.what_changed("f 644 1 1 1 1 1", "unreadable"), "file -> unreadable")
        self.assertEqual(homed.what_changed("f 644 1 1 1 1 1", "d 755 1 1 1 1 1"), "file -> dir")
        self.assertEqual(homed.line("new", ".a\x1b", "file"), "new     ~/.a?  (file)")


class TestAccept(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        d = self.dir.name
        self.base = os.path.join(d, "run")
        os.makedirs(os.path.join(self.base, "null"))
        self.known = os.path.join(d, "etc", "home-known.txt")
        os.makedirs(os.path.dirname(self.known))
        self.tty = os.path.join(d, "tty")
        statefile.write(os.path.join(self.base, "null", homed.FILE),
                        homed.doc("null", 1000, "/var/home/null", 100.0,
                                  [(".bashrc", "f 644 1000 1 2 3 4")]))
        real = config.read_file
        patches = [mock.patch.object(homed.os, "geteuid", return_value=0),
                   mock.patch.object(homed.os, "fchown"),
                   mock.patch.object(homed, "read_file",
                                     side_effect=lambda p, u, m: real(p, UID, m))]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def run_accept(self, answer):
        with open(self.tty, "w") as f:
            f.write(answer)
        gr = lambda n: types.SimpleNamespace(gr_gid=0)               # noqa: E731
        with mock.patch("sys.stdout") as out:
            rc = homed.accept(self.base, self.known, self.tty, wall=lambda: 110.0,
                              getpw=getpw, getgr=gr)
        return rc, "".join(c.args[0] for c in out.write.call_args_list)

    def test_first_then_nothing_new(self):
        rc, out = self.run_accept("n\n")
        self.assertEqual(rc, 0)
        self.assertIn("first list", out)
        self.assertIn("not changed", out)
        self.assertFalse(os.path.exists(self.known))
        rc, out = self.run_accept("y\n")
        self.assertEqual(rc, 0, out)
        self.assertEqual(os.stat(self.known).st_mode & 0o777, 0o640)
        with open(self.known) as f:
            self.assertEqual(homed.parse_known(f.read()),
                             ("null", {".bashrc": "f 644 1000 1 2 3 4"}))
        rc, out = self.run_accept("")
        self.assertIn("nothing new", out)

    def test_not_root(self):
        with mock.patch.object(homed.os, "geteuid", return_value=1000), mock.patch("sys.stderr"):
            self.assertEqual(homed.accept(self.base, self.known, self.tty), 2)


class TestMain(unittest.TestCase):
    def test_usage_and_root(self):
        with mock.patch("sys.stderr"):
            self.assertEqual(homed.main([]), 2)
            self.assertEqual(homed.main(["a", "b"]), 2)
            self.assertEqual(homed.main(["-x"]), 2)
            with mock.patch.object(homed.os, "geteuid", return_value=0):
                self.assertEqual(homed.main(["null"]), 2)

    def test_watched(self):
        self.assertEqual(homed.watched("null", getpw=lambda n: pw(1000, "/var/home/null")),
                         (1000, "/var/home/null"))
        for name, p in (("root", pw(0)), ("x", pw(5)), ("Bad", pw(1000)),
                        ("null", pw(1000, "rel")), ("null", pw(1000, "/a/../b"))):
            with self.assertRaises(ValueError):
                homed.watched(name, getpw=lambda n, p=p: p)

    def test_loop_reports_errors_once(self):
        logs, writes = [], []
        n = iter(range(4))

        def write(path, d, mode):
            writes.append(d)
            if len(writes) <= 2:
                raise OSError(28, "No space left")

        homed.loop("null", 1000, "/h", "/run/x", write=write, wall=lambda: 1.0,
                   sleep=lambda s: None, log=logs.append, stop=lambda: next(n) >= 3,
                   scan=lambda h: [])
        self.assertEqual(len(writes), 3)
        self.assertEqual(len(logs), 2)
        self.assertIn("No space left", logs[0])
        self.assertEqual(logs[1], "writing again")


if __name__ == "__main__":
    unittest.main()
