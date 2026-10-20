import datetime
import os
import tempfile
import time
import unittest

from core import noise as nz
from core.config import ConfigError

UID = os.getuid()
D = datetime.date

GOOD = b"""
[[noise]]
match = "firewall/out_ks:*"
reason = "kill switch NDP from the Proton client"
expires = 2026-12-31

[[noise]]
match = "firewall/in_lan:192.168.8.[0-9]*"
reason = "router probes"
expires = 2026-11-01
"""


def noon(day: D) -> float:
    """Epoch seconds at local noon of `day`: far from any day edge in every timezone."""
    return time.mktime((day.year, day.month, day.day, 12, 0, 0, 0, 0, -1))


class TestParse(unittest.TestCase):
    def bad(self, data: bytes):
        with self.assertRaises(ConfigError, msg=data):
            nz.parse(data)

    def test_good(self):
        a, b = nz.parse(GOOD)
        self.assertEqual(a, nz.Entry("firewall/out_ks:*", "kill switch NDP from the Proton client",
                                     D(2026, 12, 31)))
        self.assertEqual(b.expires, D(2026, 11, 1))

    def test_empty(self):
        self.assertEqual(nz.parse(b""), ())
        self.assertEqual(nz.parse(b"noise = []\n"), ())

    def test_file_level(self):
        self.bad(b"[[noise]\n")
        self.bad(b"\xff\xfe")
        self.bad(b"[core]\n")                              # unknown table
        self.bad(b"noise = 1\n")
        self.bad(b"[noise]\nmatch = 'firewall/a'\n")       # table, not array of tables
        self.bad(b"noise = [1]\n")
        many = b"".join(b'[[noise]]\nmatch = "fw/a"\nreason = "r"\nexpires = 2026-12-31\n'
                        for _ in range(nz.MAX_ENTRIES + 1))
        self.bad(many)

    def entry(self, **over):
        t = {"match": '"firewall/a"', "reason": '"r"', "expires": "2026-12-31"}
        t.update(over)
        return b"[[noise]]\n" + b"".join(f"{k} = {v}\n".encode() for k, v in t.items()
                                         if v is not None)

    def test_entry_good(self):
        for m in ('"firewall/*"', '"firewall/out_leak:fe80::1%wlo1"', '"fw/a[!b]?"'):
            self.assertEqual(len(nz.parse(self.entry(match=m))), 1, m)

    def test_entry_errors(self):
        for over in ({"match": None}, {"reason": None}, {"expires": None},
                     {"color": '"red"'},
                     {"match": '""'}, {"match": "1"}, {"match": '"firewall"'},
                     {"match": '"firewall/"'}, {"match": '"*/a"'}, {"match": '"fire*/a"'},
                     {"match": '"Firewall/a"'}, {"match": '"/a"'}, {"match": '"fw/a b"'},
                     {"match": '"fw/' + "k" * 126 + '"'},
                     {"reason": '""'}, {"reason": '"   "'}, {"reason": "1"},
                     {"reason": '"' + "r" * (nz.MAX_REASON + 1) + '"'},
                     {"expires": '"2026-12-31"'}, {"expires": "20261231"},
                     {"expires": "2026-12-31T23:59:00"},
                     {"expires": "2026-12-31T23:59:00+03:00"}, {"expires": "23:59:00"}):
            self.bad(self.entry(**over))

    def test_errors_name_the_file(self):
        with self.assertRaises(ConfigError) as cm:
            nz.parse(self.entry(reason='""'), "/etc/sectop/noise.toml")
        self.assertTrue(str(cm.exception).startswith("/etc/sectop/noise.toml: noise[0].reason"))


class TestReason(unittest.TestCase):
    def setUp(self):
        self.entries = nz.parse(GOOD)

    def test_match_and_expiry(self):
        r = nz.reason(self.entries, "firewall/out_ks:pvpnksintrf0", noon(D(2026, 12, 31)))
        self.assertEqual(r, "kill switch NDP from the Proton client")    # last day applies
        self.assertIsNone(nz.reason(self.entries, "firewall/out_ks:pvpnksintrf0",
                                    noon(D(2027, 1, 1))))                  # expired
        self.assertEqual(nz.reason(self.entries, "firewall/in_lan:192.168.8.1",
                                   noon(D(2026, 10, 20))), "router probes")

    def test_no_match(self):
        now = noon(D(2026, 10, 20))
        for key in ("firewall/out_leak:x", "other/out_ks:x", "firewall/OUT_KS:x",
                    "firewall/in_lan:10.0.0.1", "firewall/out_ks"):
            self.assertIsNone(nz.reason(self.entries, key, now), key)
        self.assertIsNone(nz.reason((), "firewall/out_ks:x", now))

    def test_first_entry_wins(self):
        e = nz.parse(self.entry_pair())
        self.assertEqual(nz.reason(e, "fw/a", noon(D(2026, 10, 20))), "first")

    @staticmethod
    def entry_pair():
        return (b'[[noise]]\nmatch = "fw/*"\nreason = "first"\nexpires = 2026-12-31\n'
                b'[[noise]]\nmatch = "fw/a"\nreason = "second"\nexpires = 2026-12-31\n')


class TestLoad(unittest.TestCase):
    """Same file checks as config.toml (tested in test_config): a few here."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = os.path.join(self._tmp.name, "sectop")
        os.mkdir(self.dir, 0o700)
        self.path = os.path.join(self.dir, "noise.toml")

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, data: bytes, mode: int = 0o644) -> None:
        with open(self.path, "wb") as f:
            f.write(data)
        os.chmod(self.path, mode)

    def test_missing(self):
        self.assertEqual(nz.load(self.path, owner_uid=UID), ())

    def test_good(self):
        self.write(GOOD)
        self.assertEqual(len(nz.load(self.path, owner_uid=UID)), 2)

    def test_refused(self):
        self.write(GOOD, 0o664)
        with self.assertRaises(ConfigError):
            nz.load(self.path, owner_uid=UID)
        self.write(GOOD)
        with self.assertRaises(ConfigError):
            nz.load(self.path, owner_uid=UID + 1)
        os.remove(self.path)
        real = os.path.join(self.dir, "real.toml")
        with open(real, "wb") as f:
            f.write(GOOD)
        os.symlink(real, self.path)
        with self.assertRaises(ConfigError):
            nz.load(self.path, owner_uid=UID)


if __name__ == "__main__":
    unittest.main()
