import os
import tempfile
import types
import unittest
from unittest import mock

from core import netd, statefile
from core.config import Config, ConfigError, ModuleConfig
from core.run import Result


def fake_bin(name):
    return f"/usr/bin/{name}"


class TestCommands(unittest.TestCase):
    def test_fixed_argv(self):
        c = netd.commands("proton0", fake_bin)
        self.assertEqual(c["table"], (("/usr/bin/nft", "-j", "-t", "list", "table", "inet",
                                       "hostfw"), netd.FAST))
        self.assertEqual(c["handshakes"][0], ("/usr/bin/wg", "show", "proton0",
                                               "latest-handshakes"))
        self.assertEqual({k for k, (_a, kind) in c.items() if kind == netd.SLOW},
                         {"endpoints", "fwmark", "fwmark_set"})
        self.assertTrue(all(os.path.basename(a[0]) in netd.NET_BINS for a, _k in c.values()))

    def test_bad_tunnel(self):
        for bad in ("", "a b", "x" * 16, "-; rm", 1, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                netd.commands(bad)

    def test_plan(self):
        p = netd.plan(Config())
        self.assertEqual(p["table"][1], 1.0)                    # half of 2 s, min 1 s
        self.assertEqual(p["endpoints"][1], netd.FW_SLOW / 2)
        cfg = Config(modules={"firewall": ModuleConfig(interval=6.0,
                                                       options={"tunnel": "wg9"})})
        p = netd.plan(cfg)
        self.assertEqual((p["table"][1], p["handshakes"][0][2]), (3.0, "wg9"))
        self.assertEqual(netd.plan(Config(modules={"firewall": ModuleConfig(enabled=False)})),
                         {})
        with self.assertRaises(ValueError):
            netd.plan(Config(modules={"firewall": ModuleConfig(options={"tunnel": "a b"})}))


class Clock:
    def __init__(self, t=100.0):
        self.t = t

    def __call__(self):
        return self.t


class TestLoop(unittest.TestCase):
    def test_runs_when_due_and_writes(self):
        clock, ran, written, logs = Clock(), [], [], []
        cmds = {"a": (("/usr/bin/nft", "x"), 2.0), "b": (("/usr/bin/wg", "y"), 10.0)}
        steps = iter(range(12))

        def run(argv, timeout):
            ran.append((clock.t, argv[1]))
            self.assertEqual(timeout, netd.TIMEOUT)
            return Result(0, "out", "", False, False)

        def sleep(sec):
            clock.t += sec

        netd.loop(cmds, "/base", run=run, write=lambda p, d: written.append((p, d)),
                  clock=clock, wall=lambda: 1000.0, sleep=sleep, log=logs.append,
                  stop=lambda: next(steps, None) is None)
        a_times = [t for t, n in ran if n == "x"]
        self.assertEqual(a_times[:3], [100.0, 102.0, 104.0])
        self.assertEqual([t for t, n in ran if n == "y"], [100.0, 110.0])
        p, d = written[0]
        self.assertEqual(p, "/base/a.json")
        self.assertEqual(d, {"v": 1, "name": "a", "argv": ["/usr/bin/nft", "x"], "rc": 0,
                             "out": "out", "err": "", "timed_out": False, "truncated": False,
                             "ts": 1000.0})
        self.assertEqual(logs, [])

    def test_write_problem_logged_once(self):
        logs, n = [], iter(range(5))

        def write(p, d):
            raise PermissionError(13, "Permission denied")

        netd.loop({"a": (("/usr/bin/nft", "x"), 1.0)}, "/b",
                  run=lambda a, timeout: Result(0, "", ""), write=write, clock=Clock(),
                  sleep=lambda s: None, log=logs.append, stop=lambda: next(n, None) is None)
        self.assertEqual(len(logs), 1)
        self.assertIn("PermissionError", logs[0])


class TestReader(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.wall = 1000.0
        self.reader = netd.Reader("proton0", base=self.tmp.name, owner=os.getuid,
                                  wall=lambda: self.wall, binary=fake_bin)
        self.cmds = netd.commands("proton0", fake_bin)

    def put(self, name, res=Result(0, "{}", "", False, False), ts=995.0, **over):
        doc = netd.result_doc(name, self.cmds[name][0], res, ts)
        doc.update(over)
        statefile.write(netd.path(name, self.tmp.name), doc)

    def ask(self, name):
        return self.reader(list(self.cmds[name][0]), timeout=1.0)

    def test_good(self):
        self.put("table", Result(0, '{"nftables": []}', "", False, False))
        self.assertEqual(self.ask("table"), Result(0, '{"nftables": []}', "", False, False))
        self.put("handshakes", Result(1, "", "Unable to access interface", False, False))
        self.assertEqual(self.ask("handshakes").err, "Unable to access interface")

    def test_missing_and_old(self):
        res = self.ask("table")
        self.assertEqual(res.rc, 1)
        self.assertIn("is sectop-net.service running?", res.err)
        self.put("table", ts=1000.0 - netd.FAST_MAX_AGE - 1)
        self.assertIn("stuck?", self.ask("table").err)
        self.put("endpoints", ts=1000.0 - netd.FAST_MAX_AGE - 1)    # slow: still fine
        self.assertEqual(self.ask("endpoints").rc, 0)

    def test_wrong_or_bad_file(self):
        self.put("table", argv=["/usr/bin/nft", "list", "ruleset"])
        self.assertIn("another command", self.ask("table").err)
        for over in ({"v": 2}, {"v": True}, {"rc": "0"}, {"out": None}, {"timed_out": 0},
                     {"ts": -1}, {"ts": "now"}):
            self.put("table", **over)
            res = self.ask("table")
            self.assertEqual(res.rc, 1, over)
            self.assertTrue(res.err.startswith(netd.path("table", self.tmp.name)), over)
        os.chmod(netd.path("table", self.tmp.name), 0o666)
        self.assertIn("net file:", self.ask("table").err)

    def test_user_missing_and_bug(self):
        r = netd.Reader("proton0", base=self.tmp.name, owner=lambda: None, binary=fake_bin)
        self.assertIn("user sectop-net missing", r(list(self.cmds["table"][0])).err)
        with self.assertRaises(ValueError):
            self.reader(["/usr/bin/nft", "flush", "ruleset"])


class TestMain(unittest.TestCase):
    def main(self, argv=(), euid=990, cfg=None, cfg_err=None):
        logs = []
        with mock.patch.object(netd.os, "geteuid", return_value=euid), \
             mock.patch.object(netd.configmod, "load", side_effect=cfg_err,
                               return_value=cfg or Config()), \
             mock.patch.object(netd, "_log", logs.append), \
             mock.patch.object(netd.signal, "signal"), \
             mock.patch("sys.stderr"), \
             mock.patch.object(netd, "loop") as loop:
            rc = netd.main(list(argv))
        return rc, loop, logs

    def test_refuses_root_and_args(self):
        for kw in ({"euid": 0}, {"argv": ["x"]}):
            rc, loop, _ = self.main(**kw)
            self.assertEqual(rc, 2, kw)
            loop.assert_not_called()

    def test_config_problems(self):
        rc, loop, logs = self.main(cfg_err=ConfigError("bad"))
        self.assertEqual((rc, logs), (2, ["config: bad"]))
        bad = Config(modules={"firewall": ModuleConfig(options={"tunnel": "a b"})})
        self.assertEqual(self.main(cfg=bad)[0], 2)
        off = Config(modules={"firewall": ModuleConfig(enabled=False)})
        rc, loop, logs = self.main(cfg=off)
        self.assertEqual(rc, 0)
        loop.assert_not_called()

    def test_runs(self):
        rc, loop, _ = self.main()
        self.assertEqual(rc, 0)
        self.assertEqual(set(loop.call_args.args[0]), set(netd.commands("proton0")))

    def test_owner_uid(self):
        with mock.patch.object(netd.pwd, "getpwnam", side_effect=KeyError("x")):
            self.assertIsNone(netd.owner_uid())
        with mock.patch.object(netd.pwd, "getpwnam",
                               return_value=types.SimpleNamespace(pw_uid=991)):
            self.assertEqual(netd.owner_uid(), 991)


if __name__ == "__main__":
    unittest.main()
