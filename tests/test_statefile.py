import json
import os
import stat
import tempfile
import unittest

from core import statefile as sf
from core.alerts import active, empty, step

PANEL = {"id": "p", "title": "t", "type": "kv", "items": [{"k": "a", "v": "1"}]}


def view(**over):
    m = {"name": "firewall", "status": "ok", "summary": "s", "flags": [], "panels": [PANEL],
         "stale": False, "waiting": False, "engine": True}
    m.update(over)
    return m


def alerts():
    st = step(empty(), "firewall", [{"key": "out_dns:1.1.1.1", "sev": "warn", "title": "dns",
                                     "detail": "d", "n": 2}], 1000.0)
    return active(st, 1001.0)


def doc(**over):
    d = sf.state(1000.0, 6.0, [view()], [{"ts": 999.0, "sev": "warn", "code": "C",
                                          "msg": "m", "src": "firewall"}], alerts())
    d.update(over)
    return d


class TestWriteLoad(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "state.json")
        self.uid = os.getuid()

    def test_roundtrip_mode_and_no_temp_left(self):
        old = os.umask(0o077)
        try:
            sf.write(self.path, {"a": [1, "x"]})
        finally:
            os.umask(old)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o640)   # not the umask
        self.assertEqual(os.listdir(self.tmp.name), ["state.json"])
        self.assertEqual(sf.load(self.path, self.uid), {"a": [1, "x"]})
        sf.write(self.path, {"a": 2}, mode=0o600)                         # replaced
        self.assertEqual(sf.load(self.path, self.uid), {"a": 2})
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_leftover_temp_replaced(self):
        with open(os.path.join(self.tmp.name, ".state.json.tmp"), "w") as f:
            f.write("half")
        sf.write(self.path, [1])
        self.assertEqual(sorted(os.listdir(self.tmp.name)), ["state.json"])

    def test_encode(self):
        self.assertEqual(sf.encode({"a": "\u00e9"}), b'{"a":"\\u00e9"}')   # ASCII only
        for bad in (float("nan"), float("inf"), {1, 2}, object()):
            with self.assertRaises(sf.StateError):
                sf.encode({"x": bad})
        with self.assertRaises(sf.StateError):
            sf.write(self.path, {"x": float("nan")})
        self.assertFalse(os.path.exists(self.path))

    def test_missing(self):
        self.assertIsNone(sf.load(self.path, self.uid))
        self.assertIsNone(sf.load(os.path.join(self.tmp.name, "no", "x.json"), self.uid))

    def test_unsafe_files(self):
        sf.write(self.path, [1])
        with self.assertRaises(sf.StateError):
            sf.load(self.path, self.uid + 1)                              # wrong owner
        os.chmod(self.path, 0o660)
        with self.assertRaises(sf.StateError):
            sf.load(self.path, self.uid)                                  # group writable
        os.chmod(self.path, 0o640)
        link = os.path.join(self.tmp.name, "link.json")
        os.symlink(self.path, link)
        with self.assertRaises(sf.StateError):
            sf.load(link, self.uid)                                       # symlink
        with self.assertRaises(sf.StateError):
            sf.load(self.path, self.uid, max_size=2)                      # too large

    def test_bad_json(self):
        for data in (b"{", b"\xff", b"[" * 100000 + b"]" * 100000):
            with open(self.path, "wb") as f:
                f.write(data)
            with self.assertRaises(sf.StateError, msg=data[:10]):
                sf.load(self.path, self.uid)


class TestCheckState(unittest.TestCase):
    def test_good(self):
        d = sf.check_state(json.loads(sf.encode(doc())))
        self.assertEqual((d["ts"], d["interval"], len(d["modules"]), len(d["feed"])),
                         (1000.0, 6.0, 1, 1))
        a = d["alerts"][0]
        self.assertEqual((a["key"], a["count"], a["state"], a["noise"]),
                         ("firewall/out_dns:1.1.1.1", 2, "open", None))
        self.assertEqual(d["modules"][0]["panels"][0]["items"][0]["v"], "1")
        self.assertEqual(d["feed"][0]["src"], "firewall")

    def test_view_defaults(self):
        m = view(status="off", panels=[])
        del m["engine"]
        out = sf.check_state(doc(modules=[m]))["modules"][0]
        self.assertEqual((out["status"], out["engine"], out["panels"]), ("off", False, []))

    def test_truncates_long_text(self):
        out = sf.check_state(doc(modules=[view(summary="x" * 5000)]))
        self.assertLessEqual(len(out["modules"][0]["summary"]), 512)

    def test_bad(self):
        a = alerts()[0]
        bad = [
            "x", [], doc(v=2), doc(v=True), doc(ts=-1), doc(ts="1"), doc(interval=0.5),
            doc(modules={}), doc(modules=[view()] * 33),
            doc(modules=[view(name="Bad")]), doc(modules=[view(status="great")]),
            doc(modules=[view(flags=[1])]), doc(modules=[view(stale="no")]),
            doc(modules=[view(panels=[{"id": "p", "type": "nope"}])]),
            doc(feed=[{"ts": 1, "sev": "warn", "code": "C", "msg": "m"}]),          # no src
            doc(feed=[{"ts": -1, "sev": "warn", "code": "C", "msg": "m", "src": "a"}]),
            doc(alerts=[{**a, "key": "other/x"}]), doc(alerts=[{**a, "key": "firewall/a b"}]),
            doc(alerts=[{**a, "sev": "ok"}]), doc(alerts=[{**a, "count": 0}]),
            doc(alerts=[{**a, "count": True}]), doc(alerts=[{**a, "state": "closed"}]),
            doc(alerts=[{**a, "noise": 1}]), doc(alerts=[{**a, "hold": 4000}]),
            doc(alerts=[{**a, "true": 1}]),
        ]
        for i, d in enumerate(bad):
            with self.assertRaises(sf.StateError, msg=i):
                sf.check_state(d)

    def test_noise_reason_kept(self):
        a = {**alerts()[0], "noise": "known: akmod"}
        self.assertEqual(sf.check_state(doc(alerts=[a]))["alerts"][0]["noise"], "known: akmod")

    def test_feed_cut(self):
        ev = {"ts": 1.0, "sev": "info", "code": "C", "msg": "m", "src": "a"}
        self.assertEqual(len(sf.state(1.0, 2.0, [], [ev] * 600, [])["feed"]), sf.MAX_FEED)


if __name__ == "__main__":
    unittest.main()
