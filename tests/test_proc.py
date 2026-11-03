import os
import tempfile
import time
import unittest

from core import proc
from core.module import InvalidSnapshot, validate

BTIME = 1792900000
APP = ("/user.slice/user-1000.slice/user@1000.service/app.slice/"
       "app-gnome-org.gnome.Ptyxis-4321.scope")


class FakeProc:
    """A /proc tree: stat (btime), <pid>/stat, <pid>/cgroup."""

    def __init__(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = self.dir.name
        with open(os.path.join(self.root, "stat"), "w", encoding="ascii") as f:
            f.write(f"cpu  1 2 3\nbtime {BTIME}\nprocesses 9\n")

    def add(self, pid: int, start_s: float, cgroup: str, comm: str = "bash",
            ppid: int = 1) -> None:
        d = os.path.join(self.root, str(pid))
        os.makedirs(d)
        ticks = int(start_s * os.sysconf("SC_CLK_TCK"))
        rest = ["S", str(ppid)] + ["0"] * 17 + [str(ticks)] + ["0"] * 30   # 22 = starttime
        with open(os.path.join(d, "stat"), "w", encoding="ascii") as f:
            f.write(f"{pid} ({comm}) " + " ".join(rest) + "\n")
        with open(os.path.join(d, "cgroup"), "w", encoding="ascii") as f:
            f.write(f"0::{cgroup}\n")

    def close(self):
        self.dir.cleanup()


class TestReader(unittest.TestCase):
    def setUp(self):
        self.p = FakeProc()
        self.r = proc.Reader(self.p.root)

    def tearDown(self):
        self.p.close()

    def test_started_before_the_record(self):
        self.p.add(4321, 100.0, APP)
        self.assertEqual(self.r.program("4321", BTIME + 200.0), "org.gnome.Ptyxis")

    def test_pid_reused(self):
        """Started after the record (pid taken again): no name, never a wrong one."""
        self.p.add(4322, 300.0, APP)
        self.assertIsNone(self.r.program("4322", BTIME + 200.0))
        self.assertEqual(self.r.program("4322", BTIME + 300.5), "org.gnome.Ptyxis")  # slack

    def test_comm_with_spaces_and_parens(self):
        self.p.add(4323, 10.0, "/system.slice/tuned.service", comm="a) b (c")
        self.assertEqual(self.r.program("4323", BTIME + 20.0), "tuned")

    def test_no_name(self):
        self.p.add(4324, 10.0, "/user.slice/user-1000.slice/session-2.scope")
        self.p.add(4325, 10.0, "/system.slice/session-c5.scope")
        self.p.add(4326, 10.0, "/")
        for pid in ("4324", "4325", "4326", "9999", "x", "", None, "0"):
            self.assertIsNone(self.r.program(pid, BTIME + 20.0), pid)

    def test_out_of_a_session_scope(self):
        """sudo ./install.sh -> systemctl (host 2026-10-26): sudo, the script and systemctl
        sit in sudo's session scope; the program is the terminal sudo was typed in."""
        sess = "/user.slice/user-1000.slice/session-c5.scope"
        self.p.add(200, 10.0, APP)                              # my shell in the terminal
        self.p.add(300, 50.0, sess, "sudo", ppid=200)
        self.p.add(400, 51.0, sess, "install.sh", ppid=300)
        self.p.add(500, 52.0, sess, "systemctl", ppid=400)
        self.assertEqual(self.r.program("500", BTIME + 53.0), "org.gnome.Ptyxis")
        self.p.add(600, 52.0, sess, "orphan", ppid=1)           # parent gone: pid 1
        self.assertIsNone(self.r.program("600", BTIME + 53.0))
        chain = [(700 + i, 700 + i + 1) for i in range(proc.MAX_HOPS + 1)]
        for pid, ppid in chain:
            self.p.add(pid, 5.0, sess, ppid=ppid)
        self.assertIsNone(self.r.program("700", BTIME + 53.0))  # walk limit
        self.p.add(800, 52.0, "/system.slice/x.service", ppid=200)
        self.assertEqual(self.r.program("800", BTIME + 53.0), "x")   # no walk: a unit

    def test_this_process(self):
        """The real /proc: no exception, a name or None."""
        got = proc.Reader().program(str(os.getpid()), time.time())
        self.assertTrue(got is None or proc.NAME_RE.fullmatch(got))

    def test_names(self):
        progs = proc.names()
        for n in ("a", "b", "a", None, "c", "d", "e", "f"):
            proc.add(progs, n)
        self.assertEqual(list(progs), ["a", "c", "d", "e", "f"])     # a moved up, b out
        self.assertEqual(proc.card_name("/system.slice/caf\\xc3\\xa9.service"), None)


class TestShared(unittest.TestCase):
    """GNOME Shell's shared cgroup (2026-11-03): its unit, own processes, strays."""

    SHELL = ("/user.slice/user-1000.slice/user@1000.service/session.slice/"
             "org.gnome.Shell@user.service")

    def test_shared(self):
        self.assertEqual(proc.shared(self.SHELL), "org.gnome.Shell@user.service")
        self.assertEqual(proc.shared(self.SHELL.replace("@user", "@wayland")),
                         "org.gnome.Shell@wayland.service")
        for cg in (APP, "/system.slice/gdm.service", "", "/",
                   "/user.slice/user-1000.slice/session-2.scope",
                   self.SHELL + "/../x.scope", self.SHELL.replace("Shell@user", "Shell")):
            self.assertIsNone(proc.shared(cg), cg)
        self.assertEqual(proc.program(self.SHELL), "org.gnome.Shell")

    def test_own(self):
        for comm in ("gnome-shell", "Xwayland", "bwrap", "glycin-image-rs", "glycin-svg"):
            self.assertTrue(proc.own(comm), comm)
        for comm in ("brave", "cat", "gnome-shellx", "xwayland", "glycin", ""):
            self.assertFalse(proc.own(comm), comm)

    def test_strays(self):
        with tempfile.TemporaryDirectory() as tmp:
            cg, pr = os.path.join(tmp, "cg"), os.path.join(tmp, "proc")
            self.assertIsNone(proc.strays(self.SHELL, cg, pr))        # unreadable
            os.makedirs(cg + self.SHELL)
            with open(cg + self.SHELL + "/cgroup.procs", "w") as f:
                f.write("11\n12\n13\n14\n99\nx\n")                     # 99: gone
            for pid, comm in ((11, "gnome-shell"), (12, "brave"), (13, "brave"),
                              (14, "caf\u00e9")):
                os.makedirs(f"{pr}/{pid}")
                with open(f"{pr}/{pid}/comm", "w") as f:
                    f.write(comm + "\n")
            got = proc.strays(self.SHELL, cg, pr)
            self.assertEqual(dict(got), {"brave": 2, "?": 1})
            self.assertEqual(proc.label(got), "brave x2, ?")
            self.assertIsNone(proc.strays("relative/path", cg, pr))
            self.assertIsNone(proc.strays("/a/../../etc", cg, pr))


class TestRowProgs(unittest.TestCase):
    def snap(self, progs):
        row = {"cells": ["x"], "progs": progs}
        return {"v": 1, "status": "ok", "summary": "", "events": [],
                "panels": [{"id": "p", "title": "t", "type": "table", "columns": ["c"],
                            "rows": [row]}]}

    def test_valid(self):
        got = validate(self.snap(["brave", "org.gnome.Ptyxis"]))
        self.assertEqual(got["panels"][0]["rows"][0]["progs"], ["brave", "org.gnome.Ptyxis"])

    def test_invalid(self):
        for bad in ([], ["a b"], ["x"] * 6, "brave", [1], ["x" * 65]):
            with self.subTest(bad=bad), self.assertRaises(InvalidSnapshot):
                validate(self.snap(bad))


if __name__ == "__main__":
    unittest.main()
