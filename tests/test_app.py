import os
import tempfile
import types
import unittest
from unittest import mock

from core import app, statefile
from core.alerts import active, empty, step
from core.config import ConfigError

PANEL = {"id": "p", "title": "t", "type": "kv", "items": []}
NOW = 1760950000.0


def mod(name="firewall", status="ok", **over):
    m = {"name": name, "status": status, "summary": "s", "flags": [], "panels": [PANEL],
         "stale": False, "waiting": False, "engine": True}
    m.update(over)
    return m


def doc(ts=NOW, summary="s", n_feed=1, alerts=()):
    feed = [{"ts": ts - i, "sev": "warn", "code": "C", "msg": "m", "src": "firewall"}
            for i in range(n_feed)]
    return statefile.state(ts, 6.0, [mod(summary=summary)], feed, list(alerts))


def warn_alert():
    st = step(empty(), "firewall", [{"key": "k", "sev": "warn", "title": "w", "detail": "",
                                     "n": 1}], NOW)
    return active(st, NOW)


class Disk:
    """Fake stat + load for the Reader: a file that changes when set() is called."""

    def __init__(self):
        self.doc, self.ino, self.loads = None, 0, 0
        self.error = None

    def set(self, doc=None, error=None):
        self.doc, self.error = doc, error
        self.ino += 1

    def stat(self, path):
        if self.doc is None and self.error is None:
            raise FileNotFoundError(path)
        return types.SimpleNamespace(st_ino=self.ino, st_mtime_ns=1, st_size=1)

    def load(self, path, owner):
        self.loads += 1
        if self.error:
            raise statefile.StateError(self.error)
        return self.doc


class TestReader(unittest.TestCase):
    def reader(self, owner=1000):
        self.disk = Disk()
        return app.Reader("/run/sectop/state.json", owner, load=self.disk.load,
                          stat=self.disk.stat)

    def test_reads_only_when_changed(self):
        r = self.reader()
        self.disk.set(doc(summary="one"))
        self.assertTrue(r.poll())
        self.assertFalse(r.poll())
        self.assertEqual(self.disk.loads, 1)
        view, feed, alerts = r.current(NOW + 1)
        self.assertEqual((view[0]["summary"], len(feed), alerts), ("one", 1, []))
        self.disk.set(doc(summary="two"))
        self.assertTrue(r.poll())
        self.assertEqual(r.current(NOW + 1)[0][0]["summary"], "two")

    def test_missing_file_and_user(self):
        r = self.reader()
        self.assertTrue(r.poll())
        self.assertFalse(r.poll())                           # same problem: no redraw
        view, _feed, alerts = r.current(NOW)
        self.assertEqual(view, [])
        self.assertEqual((alerts[0]["key"], alerts[0]["sev"]), ("core/collector", "crit"))
        self.assertIn("is sectop.service running?", alerts[0]["detail"])
        r = self.reader(owner=None)
        r.poll()
        self.assertIn("user sectop missing", r.current(NOW)[2][0]["detail"])

    def test_alert_title_says_why(self):
        r = self.reader(owner=None)
        r.poll()
        a = r.current(NOW)[2][0]
        self.assertEqual(a["title"], "collector: " + a["detail"])
        self.assertTrue(a["title"].startswith("collector: user sectop missing"))

    def test_owner_looked_up_until_found(self):
        uids = iter([None, None, 990])
        calls = []

        def lookup():
            calls.append(1)
            return next(uids)

        self.disk = Disk()
        r = app.Reader("/x", lookup, load=self.disk.load, stat=self.disk.stat)
        self.disk.set(doc(summary="later"))
        r.poll()
        r.poll()
        self.assertIsNone(r.state)
        r.poll()                                             # user created meanwhile
        self.assertEqual(r.current(NOW)[0][0]["summary"], "later")
        r.poll()
        self.assertEqual(len(calls), 3)                      # found: not asked again

    def test_not_in_group_yet(self):
        def stat(path):
            raise PermissionError(13, "Permission denied")
        r = app.Reader("/run/sectop/state.json", 990, stat=stat)
        self.assertTrue(r.poll())
        self.assertIn("in group sectop? (log out and in", r.current(NOW)[2][0]["detail"])
        r = app.Reader("/x", 990, stat=lambda p: (_ for _ in ()).throw(OSError(5, "I/O")))
        r.poll()
        self.assertEqual(r.current(NOW)[2][0]["detail"], "/x: I/O")

    def test_bad_file_keeps_last_good(self):
        r = self.reader()
        self.disk.set(doc(summary="good"))
        r.poll()
        self.disk.set(error="state.json: owner uid 0, expected 990")
        self.assertTrue(r.poll())
        view, _f, alerts = r.current(NOW + 1)
        self.assertEqual(view[0]["summary"], "good")
        self.assertIn("owner uid 0", alerts[0]["detail"])
        self.disk.set(doc={"v": 99})                         # fails check_state
        r.poll()
        self.assertIn("state.v", r.current(NOW + 1)[2][0]["detail"])
        self.disk.set(doc(summary="back"))
        r.poll()
        self.assertEqual(r.current(NOW + 1)[2], [])

    def test_stale(self):
        r = self.reader()
        self.disk.set(doc(alerts=warn_alert()))
        r.poll()
        self.assertEqual(r.limit(), 18.0)                    # 3 x 6 s
        self.assertFalse(r.stale(NOW + 18))
        self.assertTrue(r.stale(NOW + 19))
        view, _f, alerts = r.current(NOW + 19)
        self.assertEqual((view[0]["status"], view[0]["stale"], view[0]["flags"]),
                         ("unknown", True, ["stale"]))
        self.assertEqual([a["key"] for a in alerts], ["core/collector", "firewall/k"])
        self.assertIn("no update since", alerts[0]["detail"])
        self.assertTrue(self.reader().stale(NOW))            # no data yet

    def test_off_module_stays_off(self):
        r = self.reader()
        d = doc()
        d["modules"] = [mod(status="off", panels=[])]
        self.disk.set(d)
        r.poll()
        self.assertEqual(r.current(NOW + 100)[0][0]["status"], "off")

    def test_real_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.json")
            statefile.write(path, doc(summary="disk"))
            r = app.Reader(path, os.getuid())
            self.assertTrue(r.poll())
            self.assertEqual(r.current(NOW)[0][0]["summary"], "disk")
            self.assertFalse(r.poll())


class TestSource(unittest.TestCase):
    def test_pause_freezes_view_not_reading(self):
        disk = Disk()
        r = app.Reader("/x", 1000, load=disk.load, stat=disk.stat)
        disk.set(doc(summary="one"))
        r.poll()
        ui = types.SimpleNamespace(paused=False)
        view, feed, alerts, frozen = app.source(r, ui, None, NOW)
        self.assertEqual((view[0]["summary"], len(feed), alerts, frozen), ("one", 1, [], None))
        ui.paused = True
        view, feed, alerts, frozen = app.source(r, ui, frozen, NOW)
        self.assertEqual(frozen[3], NOW)                     # ages count from the pause
        disk.set(doc(summary="two", n_feed=2))
        r.poll()                                             # still reads while paused
        view, feed, alerts, frozen = app.source(r, ui, frozen, NOW + 30)
        self.assertEqual((view[0]["summary"], len(feed), frozen[3]), ("one", 1, NOW))
        ui.paused = False
        view, feed, alerts, frozen = app.source(r, ui, frozen, NOW)
        self.assertEqual((view[0]["summary"], len(feed), frozen), ("two", 2, None))


class TestLookupStep(unittest.TestCase):
    def test_step(self):
        from core.ui import UI
        ui = UI(3)
        calls = []
        self.assertFalse(app.step_lookup(ui, lambda ip: calls.append(ip)))
        ui.lookup = "8.8.8.8"
        self.assertTrue(app.step_lookup(ui, lambda ip: calls.append(ip) or [("name", "X")]))
        self.assertEqual((calls, ui.lookup, ui.whois), (["8.8.8.8"], None,
                                                         {"8.8.8.8": [("name", "X")]}))


class TestLogsStep(unittest.TestCase):
    def test_step(self):
        from core.ui import UI
        ui = UI(3)
        calls = []
        self.assertFalse(app.step_logs(ui, [], lambda req, view: calls.append(req)))
        req = ("firewall", "firewall/counters", "out_dns")
        ui.logcard = ui.logreq = req
        self.assertTrue(app.step_logs(ui, ["v"], lambda r, v: calls.append((r, v)) or {"x": 1}))
        self.assertEqual((calls, ui.logreq, ui.logdata), ([(req, ["v"])], None, {"x": 1}))

    def test_closed_meanwhile(self):
        from core.ui import UI
        ui = UI(3)
        req = ("firewall", "firewall/counters", "out_dns")
        ui.logreq = req                               # card closed before the read ran
        app.step_logs(ui, [], lambda r, v: {"x": 1})
        self.assertEqual((ui.logreq, ui.logdata), (None, None))


class TestMain(unittest.TestCase):
    def run_main(self, argv, cfg=None, euid=1000, term="xterm-256color"):
        cfg = cfg or types.SimpleNamespace(mask_public_ips=True, console_palette=True)
        with mock.patch.dict(app.os.environ, {"TERM": term}), \
             mock.patch.object(app.configmod, "load", return_value=cfg), \
             mock.patch.object(app.os, "geteuid", return_value=euid), \
             mock.patch.object(app, "owner_uid", return_value=990), \
             mock.patch.object(app.locale, "setlocale"), \
             mock.patch.object(app.signal, "signal"), \
             mock.patch("sys.stdout") as out, mock.patch("sys.stderr") as err, \
             mock.patch.object(app.curses, "wrapper") as wrapper:
            rc = app.main(argv)
        written = lambda f: "".join(c.args[0] for c in f.write.call_args_list)
        return rc, wrapper, written(out), written(err)

    def test_config_error(self):
        with mock.patch.object(app.configmod, "load", side_effect=ConfigError("bad \x1b")), \
             mock.patch.object(app.os, "geteuid", return_value=1000), \
             mock.patch("sys.stderr") as err, \
             mock.patch.object(app.curses, "wrapper") as wrapper:
            self.assertEqual(app.main([]), 2)
        wrapper.assert_not_called()
        written = "".join(c.args[0] for c in err.write.call_args_list)
        self.assertIn("sectop: config: bad ?", written)

    def test_refuses_root(self):
        rc, wrapper, _, err = self.run_main([], euid=0)
        self.assertEqual(rc, 2)
        wrapper.assert_not_called()
        self.assertIn("refusing to run as root", err)

    def test_reader_owner(self):
        _, wrapper, _, _ = self.run_main([])
        reader = wrapper.call_args.args[1]
        self.assertEqual((reader.path, reader.owner), ("/run/sectop/state.json", 990))

    def test_start_screen(self):
        for argv, want in (([], 0), (["firewall"], 0), (["2"], 1), (["processes"], 2)):
            rc, wrapper, _, _ = self.run_main(argv)
            self.assertEqual(rc, 0)
            ui = wrapper.call_args.args[2]
            self.assertEqual((ui.screen, ui.n_screens, ui.mask), (want, 3, True), argv)

    def test_mask_from_config(self):
        _, wrapper, _, _ = self.run_main([], types.SimpleNamespace(mask_public_ips=False,
                                                                 console_palette=True))
        self.assertFalse(wrapper.call_args.args[2].mask)

    def test_bad_args(self):
        for argv in (["nope\x1b"], ["9"], ["1", "2"]):
            rc, wrapper, _, err = self.run_main(argv)
            self.assertEqual(rc, 2, argv)
            wrapper.assert_not_called()
            self.assertIn(app.USAGE, err)
            self.assertNotIn("\x1b", err)
        self.assertIn("unknown screen: 'nope\\x1b'", self.run_main(["nope\x1b"])[3])   # repr

    def test_help(self):
        rc, wrapper, out, _ = self.run_main(["--help"])
        self.assertEqual(rc, 0)
        wrapper.assert_not_called()
        self.assertIn("SCREEN: firewall | security | processes or 1-3", out)

    def test_console_palette(self):
        """TERM=linux: soft palette before curses, reset after (2026-11-10)."""
        _, wrapper, out, _ = self.run_main([], term="linux")
        wrapper.assert_called_once()
        self.assertTrue(out.startswith("\x1b]P0000000\x1b]P1ff8787"))
        self.assertTrue(out.endswith("\x1b]R"))
        self.assertEqual(out.count("\x1b]P"), 16)

    def test_console_palette_reset_on_error(self):
        with mock.patch.dict(app.os.environ, {"TERM": "linux"}), \
             mock.patch.object(app.configmod, "load", return_value=types.SimpleNamespace(
                 mask_public_ips=True, console_palette=True)), \
             mock.patch.object(app.os, "geteuid", return_value=1000), \
             mock.patch.object(app, "owner_uid", return_value=990), \
             mock.patch.object(app.locale, "setlocale"), \
             mock.patch.object(app.signal, "signal"), \
             mock.patch("sys.stdout") as out, \
             mock.patch.object(app.curses, "wrapper", side_effect=RuntimeError("x")):
            with self.assertRaises(RuntimeError):
                app.main([])
        written = "".join(c.args[0] for c in out.write.call_args_list)
        self.assertTrue(written.endswith("\x1b]R"))

    def test_no_console_palette(self):
        for term, on in (("xterm-256color", True), ("linux", False)):
            _, _, out, _ = self.run_main([], types.SimpleNamespace(
                mask_public_ips=True, console_palette=on), term=term)
            self.assertNotIn("\x1b]", out, term)

    def test_owner_uid(self):
        with mock.patch.object(app.pwd, "getpwnam", side_effect=KeyError("x")):
            self.assertIsNone(app.owner_uid())
        with mock.patch.object(app.pwd, "getpwnam",
                               return_value=types.SimpleNamespace(pw_uid=990)):
            self.assertEqual(app.owner_uid(), 990)


if __name__ == "__main__":
    unittest.main()
