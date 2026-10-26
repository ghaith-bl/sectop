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

    def add(self, pid: int, start_s: float, cgroup: str, comm: str = "bash") -> None:
        d = os.path.join(self.root, str(pid))
        os.makedirs(d)
        ticks = int(start_s * os.sysconf("SC_CLK_TCK"))
        rest = ["S"] + ["0"] * 18 + [str(ticks)] + ["0"] * 30     # field 22 = starttime
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
