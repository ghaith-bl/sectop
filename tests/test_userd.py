"""core/userd.py: user helper (socket inodes of the shared cgroup) + collector reader."""

import json
import os
import stat
import tempfile
import types
import unittest
from unittest import mock

from core import statefile, userd

UID = os.getuid()
SLICE = f"/user.slice/user-{UID}.slice/user@{UID}.service"
SHELL = f"{SLICE}/session.slice/org.gnome.Shell@user.service"


class Tree:
    """Fake /sys/fs/cgroup + /proc for one user."""

    def __init__(self):
        self.dir = tempfile.TemporaryDirectory()
        self.cg = os.path.join(self.dir.name, "cg")
        self.proc = os.path.join(self.dir.name, "proc")
        os.makedirs(self.proc)

    def cgroup(self, path, pids):
        os.makedirs(self.cg + path, exist_ok=True)
        with open(self.cg + path + "/cgroup.procs", "w") as f:
            f.write("".join(f"{p}\n" for p in pids))

    def proc_(self, pid, comm, fds=()):
        d = os.path.join(self.proc, str(pid))
        os.makedirs(os.path.join(d, "fd"))
        with open(os.path.join(d, "comm"), "w") as f:
            f.write(comm + "\n")
        for i, target in enumerate(fds):
            os.symlink(target, os.path.join(d, "fd", str(i)))


class TestScan(unittest.TestCase):
    def setUp(self):
        self.t = Tree()
        self.addCleanup(self.t.dir.cleanup)

    def test_cgroups(self):
        self.assertEqual(userd.cgroups(UID, self.t.cg), [])             # no user manager
        self.t.cgroup(SHELL, [])
        self.t.cgroup(f"{SLICE}/app.slice/app-gnome-org.gnome.Ptyxis-1.scope", [])
        self.t.cgroup(f"{SLICE}/org.gnome.Shell@wayland.service", [])
        self.assertEqual(userd.cgroups(UID, self.t.cg),
                         [f"{SLICE}/org.gnome.Shell@wayland.service", SHELL])

    def test_scan(self):
        self.t.cgroup(SHELL, [11, 12, 13, 99])
        self.t.proc_(11, "gnome-shell", ["socket:[100]", "/dev/null", "pipe:[5]"])
        self.t.proc_(12, "brave", ["socket:[201]", "socket:[200]", "socket:[201]",
                                   "anon_inode:[eventfd]"])                 # dup fd
        self.t.proc_(13, "cat", [])
        got = userd.scan(UID, self.t.cg, self.t.proc)
        self.assertEqual(got, [
            {"pid": 11, "comm": "gnome-shell", "cgroup": SHELL, "socks": [100], "denied": False},
            {"pid": 12, "comm": "brave", "cgroup": SHELL, "socks": [200, 201],
             "denied": False},
            {"pid": 13, "comm": "cat", "cgroup": SHELL, "socks": [], "denied": False}])
        doc = userd.doc(UID, 5.0, got)
        self.assertEqual(userd.check(json.loads(json.dumps(doc)), UID)[1], 5.0)

    def test_not_mine_skipped(self):
        other = UID + 1
        path = f"/user.slice/user-{other}.slice/user@{other}.service/s.slice/" \
               "org.gnome.Shell@user.service"
        self.t.cgroup(path, [11])
        self.t.proc_(11, "brave", ["socket:[1]"])                     # owned by me, not other
        self.assertEqual(userd.scan(other, self.t.cg, self.t.proc), [])

    def test_denied(self):
        self.t.cgroup(SHELL, [12])
        self.t.proc_(12, "brave", ["socket:[200]"])
        with mock.patch.object(userd.os, "scandir", side_effect=[
                os.scandir(self.t.cg + SLICE), os.scandir(self.t.cg + SLICE + "/session.slice"),
                PermissionError(13, "Permission denied")]):
            got = userd.scan(UID, self.t.cg, self.t.proc)
        self.assertEqual((got[0]["socks"], got[0]["denied"]), ([], True))

    def test_limits(self):
        self.t.cgroup(SHELL, [12])
        self.t.proc_(12, "brave", [f"socket:[{i}]" for i in range(1, 30)])
        with mock.patch.object(userd, "MAX_FDS", 5):
            self.assertEqual(len(userd.scan(UID, self.t.cg, self.t.proc)[0]["socks"]), 5)
        with mock.patch.object(userd, "MAX_SOCKS", 3):
            self.assertEqual(len(userd.scan(UID, self.t.cg, self.t.proc)[0]["socks"]), 3)


class TestCheck(unittest.TestCase):
    def good(self, **over):
        p = {"pid": 12, "comm": "brave", "cgroup": SHELL, "socks": [200], "denied": False}
        p.update(over)
        return {"v": 1, "uid": UID, "ts": 10.0, "procs": [p]}

    def test_good(self):
        procs, ts = userd.check(self.good(), UID)
        self.assertEqual((procs, ts), ([(12, "brave", SHELL, [200], False)], 10.0))
        procs, _ = userd.check(self.good(comm="b\u00e4d\x1b"), UID)
        self.assertEqual(procs[0][1], "?")                            # never drawn raw

    def test_bad(self):
        bad = [
            [], {"v": 2}, dict(self.good(), uid=UID + 1), dict(self.good(), uid=True),
            dict(self.good(), ts=-1), dict(self.good(), procs={}),
            self.good(pid=0), self.good(pid=True), self.good(socks=[0]),
            self.good(socks=["1"]), self.good(denied=1), self.good(comm=None),
            self.good(cgroup="/system.slice/x.service"),               # not shared
            self.good(cgroup=SHELL.replace(f"user-{UID}", f"user-{UID + 1}")),   # not mine
        ]
        for d in bad:
            with self.subTest(d=d), self.assertRaises(ValueError):
                userd.check(d, UID)
        with mock.patch.object(userd, "MAX_SOCKS", 0), self.assertRaises(ValueError):
            userd.check(self.good(), UID)


class TestReader(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = os.path.join(self.tmp.name, "sectop-user")
        self.wall = 100.0
        pw = types.SimpleNamespace(pw_uid=UID)

        def getpw(name):
            if name == "ghost":
                raise KeyError(name)
            return pw
        self.r = userd.Reader(self.base, wall=lambda: self.wall, getpw=getpw)

    def put(self, name, doc):
        d = os.path.join(self.base, name)
        os.makedirs(d, mode=0o750, exist_ok=True)
        os.chmod(d, 0o750)
        statefile.write(os.path.join(d, userd.FILE), doc)

    def doc(self, ts=99.0, **over):
        p = {"pid": 12, "comm": "brave", "cgroup": SHELL, "socks": [200, 201],
             "denied": False}
        p.update(over)
        return userd.doc(UID, ts, [p])

    def test_not_installed(self):
        self.assertEqual(self.r(), ({}, []))
        self.assertEqual(self.r.users, [])

    def test_owners(self):
        self.put("null", self.doc())
        owners, notes = self.r()
        self.assertEqual(notes, [])
        self.assertEqual(owners[200], userd.Owner(12, "brave", "null", SHELL))
        self.assertEqual(set(owners), {200, 201})
        self.assertEqual(self.r.users, ["null"])

    def test_denied(self):
        self.put("null", self.doc(socks=[], denied=True))
        owners, _ = self.r()
        self.assertEqual((owners, self.r.denied), ({}, {("null", 12): "brave"}))

    def test_problems(self):
        self.put("null", self.doc(ts=self.wall - userd.MAX_AGE - 1))
        self.put("ghost", self.doc())
        self.put("Bad Name", self.doc())                               # not a user name
        os.makedirs(os.path.join(self.base, "empty"), mode=0o750)
        owners, notes = self.r()
        self.assertEqual(owners, {})
        self.assertEqual(sorted(n.split(":")[0] for n in notes), ["empty", "ghost", "null"])
        self.assertIn("stuck?", next(n for n in notes if n.startswith("null")))
        self.put("null", dict(self.doc(), uid=UID + 1))
        self.assertIn("uid", self.r()[1][-1])
        os.chmod(os.path.join(self.base, "null", userd.FILE), 0o666)   # writable by others
        self.assertTrue(self.r()[1][-1].startswith("null: "))


class TestHelper(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_prepare(self):
        d = os.path.join(self.tmp.name, "null")
        os.mkdir(d, 0o700)
        userd.prepare(d, UID, os.getgid())
        self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), 0o750)
        with self.assertRaises(ValueError):
            userd.prepare(d, UID + 1, os.getgid())
        os.symlink(d, d + "-link")
        with self.assertRaises(ValueError):
            userd.prepare(d + "-link", UID, os.getgid())

    def test_loop_writes_with_group(self):
        path = os.path.join(self.tmp.name, userd.FILE)
        n, logs = iter(range(1)), []
        userd.loop(UID, os.getgid(), path, wall=lambda: 7.0, sleep=lambda s: None,
                   log=logs.append, stop=lambda: next(n, None) is None,
                   scan=lambda uid: [])
        st = os.stat(path)
        self.assertEqual((stat.S_IMODE(st.st_mode), st.st_gid), (0o640, os.getgid()))
        with open(path) as f:
            self.assertEqual(json.load(f), {"v": 1, "uid": UID, "ts": 7.0, "procs": []})
        self.assertEqual(logs, [])

    def test_main_refuses(self):
        with mock.patch("sys.stderr"):
            self.assertEqual(userd.main(["x"]), 2)
        logs = []
        with mock.patch.object(userd, "_log", logs.append):
            with mock.patch.object(userd.os, "geteuid", return_value=0):
                self.assertEqual(userd.main([]), 2)
            with mock.patch.object(userd.os, "geteuid", return_value=1000), \
                 mock.patch.object(userd.os, "getuid", return_value=1000), \
                 mock.patch.object(userd.pwd, "getpwuid",
                                   return_value=types.SimpleNamespace(pw_name="null")), \
                 mock.patch.object(userd.grp, "getgrnam",
                                   return_value=types.SimpleNamespace(gr_gid=4242)), \
                 mock.patch.object(userd.os, "getgid", return_value=1000), \
                 mock.patch.object(userd.os, "getgroups", return_value=[1000, 10]), \
                 mock.patch.object(userd, "loop") as loop:
                self.assertEqual(userd.main([]), 2)                      # not in sectop
                loop.assert_not_called()
        self.assertIn("refusing to run as root", logs[0])
        self.assertIn("not in group sectop", logs[1])


if __name__ == "__main__":
    unittest.main()
