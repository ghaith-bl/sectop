import os
import tempfile
import time
import unittest

from core.run import Result, run

SH = "/usr/bin/sh"  # tests only; production code never uses a shell


class TestRun(unittest.TestCase):
    def test_ok(self):
        r = run(["/usr/bin/printf", "hi"])
        self.assertEqual(r, Result(0, "hi", ""))

    def test_rc_and_stderr(self):
        r = run([SH, "-c", "echo oops >&2; exit 3"])
        self.assertEqual((r.rc, r.out, r.err), (3, "", "oops\n"))

    def test_no_shell_expansion(self):
        r = run(["/usr/bin/printf", "%s", "$HOME;id"])
        self.assertEqual(r.out, "$HOME;id")

    def test_env_fixed(self):
        r = run([SH, "-c", 'printf "%s|%s|%s" "$PATH" "$LC_ALL" "$HOME"'])
        self.assertEqual(r.out, "/usr/sbin:/usr/bin|C|")

    def test_cwd_root(self):
        self.assertEqual(run(["/usr/bin/pwd"]).out, "/\n")

    def test_stdin_devnull(self):
        r = run(["/usr/bin/cat"])
        self.assertEqual((r.rc, r.out, r.timed_out), (0, "", False))

    def test_timeout(self):
        t = time.monotonic()
        r = run([SH, "-c", "sleep 5"], timeout=0.3)
        self.assertTrue(r.timed_out)
        self.assertEqual(r.rc, -9)
        self.assertLess(time.monotonic() - t, 2)

    def test_timeout_kills_children(self):
        t = time.monotonic()
        r = run([SH, "-c", "sleep 5 & sleep 5"], timeout=0.3)
        self.assertTrue(r.timed_out)
        self.assertLess(time.monotonic() - t, 2)

    def test_pipes_closed_but_running(self):
        r = run([SH, "-c", "exec >&- 2>&-; sleep 5"], timeout=0.3)
        self.assertTrue(r.timed_out)

    def test_limit(self):
        r = run(["/usr/bin/head", "-c", "100000", "/dev/zero"], limit=1000)
        self.assertTrue(r.truncated)
        self.assertEqual(len(r.out), 1000)

    def test_invalid_utf8(self):
        r = run(["/usr/bin/printf", "a\\377b"])
        self.assertEqual(r.out, "a" + chr(0xFFFD) + "b")

    def test_not_found(self):
        r = run(["/usr/bin/does-not-exist-sectop"])
        self.assertEqual(r.rc, 127)

    def test_refuse_unsafe_binary(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x")
            with open(p, "w") as f:
                f.write("#!/usr/bin/sh\necho ran\n")
            os.chmod(p, 0o757)
            r = run([p])
        self.assertEqual(r.rc, 126)
        self.assertNotIn("ran", r.out)

    def test_refuse_directory(self):
        self.assertEqual(run(["/usr/bin"]).rc, 126)

    def test_bad_argv(self):
        for argv in ([], "ls", ["ls"], ["/usr/bin/ls", 1], None):
            with self.assertRaises(ValueError, msg=repr(argv)):
                run(argv)

    def test_bad_timeout(self):
        for t in (0, -1, 31):
            with self.assertRaises(ValueError):
                run(["/usr/bin/true"], timeout=t)


if __name__ == "__main__":
    unittest.main()
