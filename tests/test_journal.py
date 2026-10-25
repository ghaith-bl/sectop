import json
import os
import subprocess
import sys
import tempfile
import time
import types
import unittest

from core import journal
from core.journal import Reader, matches, spec, values, wants
from core.registry import Loaded

KERNEL = {"groups": [["_TRANSPORT=kernel"]], "fields": ["MESSAGE"]}
AUDIT = {"groups": [["_TRANSPORT=audit", "_AUDIT_TYPE=1123"], ["SYSLOG_IDENTIFIER=sudo"]],
         "fields": ["MESSAGE", "_PID"]}


def ent(i, transport="kernel", msg="m", **more):
    e = {"__CURSOR": f"s=1;i={i:x};b=0;m=0;t=0;x=0",
         "__REALTIME_TIMESTAMP": str(1792410000000000 + i * 1000),
         "MESSAGE": msg, "_TRANSPORT": transport}
    e.update(more)
    return e


def lines(*entries):
    return b"".join(json.dumps(e).encode() + b"\n" for e in entries)


class Clock:
    def __init__(self, t=100.0):
        self.t = t

    def __call__(self):
        return self.t


# Fake journalctl: prints the lines it is given, then exits (rc) or waits.
PROG = r"""
import json, os, sys, time
cfg = json.loads(sys.argv[1])
if cfg.get("close_err"):
    os.close(2)
time.sleep(cfg.get("delay", 0))
for line in cfg.get("lines", []):
    sys.stdout.write(line + "\n")
    sys.stdout.flush()
if cfg.get("err"):
    sys.stderr.write(cfg["err"] + "\n")
    sys.stderr.flush()
if "rc" in cfg:
    sys.exit(cfg["rc"])
time.sleep(30)
"""


class Spawner:
    """spawn() for Reader: one fake journalctl per call, argv kept."""

    def __init__(self, *plans):
        self.plans, self.argvs = list(plans), []

    def __call__(self, argv):
        self.argvs.append(argv)
        cfg = self.plans.pop(0) if len(self.plans) > 1 else self.plans[0]
        if isinstance(cfg, BaseException):
            raise cfg
        return subprocess.Popen([sys.executable, "-I", "-c", PROG, json.dumps(cfg)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True)


def jl(*entries):
    return [json.dumps(e) for e in entries]


class TestSpec(unittest.TestCase):
    def test_good(self):
        s = spec(AUDIT)
        self.assertEqual(s.groups, ((("_TRANSPORT", "audit"), ("_AUDIT_TYPE", "1123")),
                                    (("SYSLOG_IDENTIFIER", "sudo"),)))
        self.assertEqual(s.fields, ("MESSAGE", "_PID"))
        spec({"groups": (("__CURSOR=x",),), "fields": ("A",)})     # tuples work too

    def test_bad(self):
        for raw in (None, [], {"groups": [["A=b"]]}, {**KERNEL, "x": 1},
                    {"groups": [], "fields": ["M"]}, {"groups": [[]], "fields": ["M"]},
                    {"groups": [["A=b"]] * 9, "fields": ["M"]},
                    {"groups": [["A=b"] * 9], "fields": ["M"]},
                    {"groups": [["A=b"]], "fields": []},
                    {"groups": [["A=b"]], "fields": ["M"] * 33},
                    {"groups": [["a=b"]], "fields": ["M"]},          # field: upper case
                    {"groups": [["1A=b"]], "fields": ["M"]},
                    {"groups": [["A=b c"]], "fields": ["M"]},        # no spaces
                    {"groups": [["A=b+c"]], "fields": ["M"]},        # no +
                    {"groups": [["A="]], "fields": ["M"]},
                    {"groups": [["A"]], "fields": ["M"]},
                    {"groups": [["+"]], "fields": ["M"]},
                    {"groups": [[1]], "fields": ["M"]},
                    {"groups": ["A=b"], "fields": ["M"]},            # group must be a list
                    {"groups": [["A=b"]], "fields": ["m"]},
                    {"groups": [["A=b"]], "fields": [None]}):
            with self.assertRaises(ValueError, msg=repr(raw)):
                spec(raw)


class TestMatch(unittest.TestCase):
    def test_values(self):
        self.assertEqual(values("a"), ["a"])
        self.assertEqual(values([104, 105]), ["hi"])                 # byte array
        self.assertEqual(values(["a", [98]]), ["a", "b"])            # field twice
        self.assertEqual(values(None), [])
        self.assertEqual(values([]), [])
        self.assertEqual(values([300]), [])

    def test_rules(self):
        w = wants(spec({"groups": [["_TRANSPORT=audit", "_TRANSPORT=kernel", "PRIORITY=4"],
                                   ["SYSLOG_IDENTIFIER=sudo"]], "fields": ["M"]}).groups)
        self.assertTrue(matches({"_TRANSPORT": "kernel", "PRIORITY": "4"}, w))
        self.assertTrue(matches({"_TRANSPORT": "audit", "PRIORITY": "4"}, w))   # same field: or
        self.assertFalse(matches({"_TRANSPORT": "kernel", "PRIORITY": "6"}, w))  # other: and
        self.assertFalse(matches({"_TRANSPORT": "kernel"}, w))
        self.assertTrue(matches({"SYSLOG_IDENTIFIER": "sudo"}, w))              # group: or
        self.assertTrue(matches({"SYSLOG_IDENTIFIER": ["x", "sudo"]}, w))
        self.assertFalse(matches({}, w))


class TestArgv(unittest.TestCase):
    def reader(self, **specs):
        return Reader({n: spec(s) for n, s in specs.items()}, since=1792410000.7,
                      spawn=Spawner({}))

    def test_union(self):
        r = self.reader(firewall=KERNEL, security=AUDIT, other=KERNEL)
        self.assertEqual(r.argv(), [
            journal.BIN, "-f", "-o", "json",
            "--output-fields=MESSAGE,SYSLOG_IDENTIFIER,_AUDIT_TYPE,_PID,_TRANSPORT",
            "-q", "--no-pager", "--since=@1792410000",
            "_TRANSPORT=kernel", "+", "_TRANSPORT=audit", "_AUDIT_TYPE=1123",
            "+", "SYSLOG_IDENTIFIER=sudo"])

    def test_cursor_after_an_entry(self):
        r = self.reader(firewall=KERNEL)
        r.feed(lines(ent(5)))
        self.assertEqual(r.argv()[7], "--after-cursor=s=1;i=5;b=0;m=0;t=0;x=0")
        self.assertNotIn("-n", r.argv())                 # never with -n (255 vs 259)
        r.use_cursor = False
        self.assertEqual(r.argv()[7], "--since=@1792410000")


class TestFeed(unittest.TestCase):
    def setUp(self):
        self.r = Reader({"fw": spec(KERNEL), "sec": spec(AUDIT)}, since=0,
                        spawn=Spawner({}), clock=Clock())

    def test_split_and_route(self):
        data = lines(ent(1), ent(2, "audit", _AUDIT_TYPE="1123"), ent(3, "syslog"),
                     ent(4, "syslog", SYSLOG_IDENTIFIER="sudo"))
        self.r.feed(data[:30])
        self.r.feed(data[30:])
        fw, _, note = self.r.take("fw")
        sec, _, _ = self.r.take("sec")
        self.assertEqual([e["__CURSOR"][6] for e in fw], ["1"])
        self.assertEqual([e["__CURSOR"][6] for e in sec], ["2", "4"])
        self.assertIn("restart in", note)                # never started: down
        self.assertEqual(self.r.take("fw")[0], ())      # given once
        self.assertEqual(self.r.cursor, ent(4)["__CURSOR"])   # any entry moves the cursor
        self.assertEqual(self.r.last_us, 1792410000004000)

    def test_cut_line_waits(self):
        data = lines(ent(1))
        self.r.feed(data[:-5])
        self.assertEqual(self.r.take("fw")[0], ())
        self.r.feed(data[-5:])
        self.assertEqual(len(self.r.take("fw")[0]), 1)

    def test_bad_lines(self):
        self.r.feed(b"garbage\n\n[1]\n" + json.dumps({"__CURSOR": 7}).encode() + b"\n" +
                    json.dumps({"__CURSOR": "bad cursor;$(x)"}).encode() + b"\n" +
                    lines(ent(1)))
        fw, _, note = self.r.take("fw")
        self.assertEqual(len(fw), 1)
        self.assertIn("4 bad line(s)", note)
        self.assertNotIn("bad line", self.r.take("fw")[2])     # counted once

    def test_overlong_line(self):
        self.r.feed(b'{"x": "' + b"a" * (journal.MAX_LINE + 10))
        self.r.feed(b"aaaa" * 10)
        self.r.feed(b'"}\n' + lines(ent(1)))
        fw, _, note = self.r.take("fw")
        self.assertEqual(len(fw), 1)                     # the rest of the long line skipped
        self.assertIn("1 bad line(s)", note)

    def test_bounded_buffer(self):
        n = journal.MAX_ENTRIES + 7
        self.r.feed(b"".join(lines(ent(i)) for i in range(n)))
        fw, _, note = self.r.take("fw")
        self.assertEqual(len(fw), journal.MAX_ENTRIES)
        self.assertEqual(fw[0]["__CURSOR"], ent(7)["__CURSOR"])     # oldest dropped
        self.assertIn("7 entries dropped (buffer full)", note)


class TestChild(unittest.TestCase):
    def reader(self, spawner, clock=None, **kw):
        r = Reader({"fw": spec(KERNEL)}, since=1792410000, spawn=spawner,
                   clock=clock or time.monotonic, **kw)
        self.addCleanup(r.close)
        return r

    def until(self, r, pred, limit=5.0):
        end = time.monotonic() + limit
        got = []
        while time.monotonic() < end:
            r.wait(0.05)
            got += r.take("fw")[0]
            if pred(got):
                break
        return got

    def done(self, r):
        r.child.wait(5)                                  # all output is in the pipe

    def test_follows(self):
        sp = Spawner({"lines": jl(ent(1), ent(2), ent(3, "audit"))})
        r = self.reader(sp)
        got = self.until(r, lambda g: len(g) >= 2)
        self.assertEqual([e["__CURSOR"] for e in got], [ent(1)["__CURSOR"], ent(2)["__CURSOR"]])
        self.assertTrue(r.up)
        self.assertEqual(r.take("fw")[1:], (True, ""))
        self.assertEqual(sp.argvs[0][7], "--since=@1792410000")

    def test_wait_reads_while_sleeping(self):
        r = self.reader(Spawner({"lines": jl(ent(1)), "delay": 0.2}))
        t = time.monotonic()
        r.wait(0.6)
        self.assertGreaterEqual(time.monotonic() - t, 0.6)
        self.assertEqual(len(r.take("fw")[0]), 1)

    def test_restart_from_cursor_then_time(self):
        clock = Clock()
        sp = Spawner({"lines": jl(ent(1), ent(2)), "rc": 0},
                     {"err": "Failed to seek to cursor: Invalid argument", "rc": 1},
                     {"lines": jl(ent(2), ent(3))})
        r = self.reader(sp, clock)
        r.pump()                                         # start
        self.done(r)
        r.pump()                                         # entries, then EOF
        self.assertFalse(r.up)
        got, up, note = r.take("fw")
        self.assertEqual((len(got), up), (2, False))
        self.assertEqual(note, "journalctl exited (rc 0), restart in 1 s")
        r.pump()
        self.assertFalse(r.up)                           # backoff: not yet
        clock.t += 1.0
        r.pump()
        self.assertEqual(sp.argvs[1][7], "--after-cursor=" + ent(2)["__CURSOR"])
        self.done(r)
        r.pump()                                         # cursor refused, no entry
        _, _, note = r.take("fw")
        self.assertIn("journalctl exited (rc 1: Failed to seek to cursor: Invalid argument)",
                      note)
        self.assertIn("journalctl restarted from the last entry", note)
        self.assertIn("restart in 2 s", note)            # doubled
        clock.t += 2.0
        r.pump()
        self.assertEqual(sp.argvs[2][7], "--since=@1792410000")    # second of entry 2
        got = []
        for _ in range(100):
            r.pump()
            got += r.take("fw")[0]
            if got:
                break
            time.sleep(0.02)
        self.assertEqual([e["__CURSOR"] for e in got], [ent(3)["__CURSOR"]])   # 2 skipped
        self.assertTrue(r.use_cursor)                    # a new entry: cursor again

    def test_backoff_resets_after_a_long_run(self):
        clock = Clock()
        r = self.reader(Spawner({"rc": 3}), clock)
        r.pump()
        self.done(r)
        r.pump()
        self.assertEqual(r.delay, 1.0)
        clock.t += 1.0
        r.pump()
        self.done(r)
        r.pump()
        self.assertEqual(r.delay, 2.0)
        clock.t += 2.0
        r.pump()
        clock.t += journal.RESET_AFTER
        self.done(r)
        r.pump()
        self.assertEqual(r.delay, 1.0)

    def test_not_startable(self):
        clock = Clock()
        r = self.reader(Spawner(FileNotFoundError(2, "No such file or directory")), clock)
        delays = []
        for i in range(4):
            if i:
                clock.t += r.delay
            r.pump()
            delays.append(r.delay)
        self.assertEqual(delays, [1.0, 2.0, 4.0, 8.0])
        _, up, note = r.take("fw")
        self.assertFalse(up)
        self.assertEqual(note, "journalctl not started: No such file or directory, "
                               "restart in 8 s")

    def test_stderr_closed_no_spin(self):
        r = self.reader(Spawner({"close_err": True}))
        r.pump()
        time.sleep(0.2)
        cpu = time.process_time()
        r.wait(0.5)
        self.assertLess(time.process_time() - cpu, 0.2)
        self.assertTrue(r.up)

    def test_close(self):
        r = self.reader(Spawner({}))
        r.pump()
        child = r.child
        r.close()
        self.assertIsNotNone(child.poll())
        self.assertFalse(r.up)
        r.close()                                        # twice: no error


class TestSpawn(unittest.TestCase):
    def test_trust(self):
        with self.assertRaises(FileNotFoundError):
            journal._spawn(["/nonexistent/journalctl"])
        with tempfile.NamedTemporaryFile() as f:
            os.chmod(f.name, 0o777)                      # g/o writable; mine unless I am root
            with self.assertRaises(PermissionError) as cm:
                journal._spawn([f.name])
            msg = str(cm.exception)                      # first failed rule wins (core/run.py)
            self.assertTrue(msg.startswith(f"refused: {f.name}: "), msg)
            self.assertTrue(msg.endswith(("not owned by root", "group/other writable")), msg)


class TestForModules(unittest.TestCase):
    def ld(self, name, journal_spec=None, **over):
        mod = types.SimpleNamespace()
        if journal_spec is not None:
            mod.JOURNAL = journal_spec
        kw = {"name": name, "import_name": f"modules.{name}", "enabled": True, "mod": mod}
        kw.update(over)
        return Loaded(**kw)

    def test_for_modules(self):
        r = journal.for_modules([self.ld("fw", KERNEL), self.ld("x"),
                                 self.ld("off", AUDIT, enabled=False),
                                 self.ld("bad", AUDIT, error="init: E")], since=5)
        self.assertEqual(list(r.specs), ["fw"])
        self.assertIsNone(journal.for_modules([self.ld("x")], since=5))


if __name__ == "__main__":
    unittest.main()
