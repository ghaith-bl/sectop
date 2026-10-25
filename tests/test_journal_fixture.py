"""tests/journal_fixture.py: sections, fields, masks, dropped audit events."""

import io
import json
import os
import tempfile
import unittest

from tests import journal_fixture as jf

NAMES = {"alice": "user", "box1": "host", "Alice Doe": "Real Name", "Doe": "Name"}


def ent(i, msg, **kw):
    e = {"__CURSOR": f"s=abc;i={i:x};b=feed", "__REALTIME_TIMESTAMP": str(1792410751000000
                                                                          + i * 1000000),
         "__MONOTONIC_TIMESTAMP": "5", "_BOOT_ID": "f" * 32, "_MACHINE_ID": "e" * 32,
         "_HOSTNAME": "box1", "_CAP_EFFECTIVE": "0", "MESSAGE": msg}
    e.update(kw)
    return e


def marker(i, name):
    return ent(i, name, SYSLOG_IDENTIFIER="sectop-fix", _TRANSPORT="syslog")


def audit(i, aid, typ, msg):
    return ent(i, msg, _TRANSPORT="audit", _AUDIT_ID=str(aid), _AUDIT_TYPE=str(typ))


def lines(*es):
    return [json.dumps(e) + "\n" for e in es]


def hexs(s):
    return s.encode().hex().upper()


class TestMasker(unittest.TestCase):
    def test_ips(self):
        m = jf.Masker(NAMES)
        s = ("SRC=10.2.0.2 DST=8.8.8.8 again 8.8.8.8 other 1.1.1.1. cgnat 100.64.0.1 "
             "mdns 224.0.0.251 lan 192.168.8.1 v6 2a00:1450::1 [2a00:1450::1]:443 "
             "end 2a00:1450::2. ll fe80::1%wlo1 mapped ::ffff:9.9.9.9 v4port 4.4.4.4:53")
        self.assertEqual(m.text(s), (
            "SRC=10.2.0.2 DST=203.0.113.1 again 203.0.113.1 other 203.0.113.2. "
            "cgnat 100.64.0.1 mdns 224.0.0.251 lan 192.168.8.1 v6 2001:db8::1 "
            "[2001:db8::1]:443 end 2001:db8::2. ll fe80::1%wlo1 mapped 2001:db8::3 "
            "v4port 203.0.113.3:53"))
        self.assertEqual(m.n["ip4"], 4)
        self.assertEqual(m.n["ip6"], 4)

    def test_masked_text_unchanged(self):
        m = jf.Masker(NAMES)
        for s in ("203.0.113.9 2001:db8::5 02:00:00:00:00:07", "kernel 6.18.44-200.fc44",
                  "at 10:23:45", "std::string", "ACPI BIOS Error (bug): x 0x1F",
                  "999.1.1.1", "a0=7ffd1234 pid=4142 res=1"):
            self.assertEqual(m.text(s), s, s)
        self.assertEqual(sum(m.n.values()), 0)

    def test_macs(self):
        m = jf.Masker(NAMES)
        s = ("gw aa:bb:cc:dd:ee:ff again AA:BB:CC:DD:EE:FF zero 00:00:00:00:00:00 "
             "MAC=52:54:00:12:34:56:52:54:00:ab:cd:ef:08:00")
        self.assertEqual(m.text(s), (
            "gw 02:00:00:00:00:01 again 02:00:00:00:00:01 zero 00:00:00:00:00:00 "
            "MAC=02:00:00:00:00:02:02:00:00:00:00:03:08:00"))

    def test_ll_header(self):
        m = jf.Masker(NAMES)
        s = ("ll header: 00000000: 26 83 57 d7 e5 ad 42 4d 93 61 47 b3 08 00 | "
             "ll header: 00000000: ff ff ff ff ff ff 42 4d 93 61 47 b3 08 06 | "
             "ll header: 00000000: 01 02")
        self.assertEqual(m.text(s), (
            "ll header: 00000000: 02 00 00 00 00 01 02 00 00 00 00 02 08 00 | "
            "ll header: 00000000: ff ff ff ff ff ff 02 00 00 00 00 02 08 06 | "
            "ll header: 00000000: 01 02"))
        self.assertEqual(m.n["mac"], 3)

    def test_names(self):
        m = jf.Masker(NAMES)
        s = ('acct="alice" /home/alice/x unix-user:alice alicex box1.lan box1 '
             "Alice Doe, J. Doe")
        self.assertEqual(m.text(s), ('acct="user" /home/user/x unix-user:user alicex '
                                     "host.lan host Real Name, J. Name"))

    def test_hex(self):
        m = jf.Masker(NAMES)
        title = "proctitle=" + "00".join(hexs(a) for a in ("sudo", "-u", "alice", "id"))
        want = "proctitle=" + "00".join(hexs(a) for a in ("sudo", "-u", "user", "id"))
        self.assertEqual(m.text(title), want)
        arg = 'a1=' + hexs("/home/alice/my file") + ' a2="x"'
        self.assertEqual(m.text(arg), 'a1=' + hexs("/home/user/my file") + ' a2="x"')
        same = "proctitle=" + hexs("bash")
        self.assertEqual(m.text(same), same)

    def test_serial(self):
        m = jf.Masker(NAMES)
        self.assertEqual(m.text("usb 3-6: SerialNumber: 4C5300012345"),
                         "usb 3-6: SerialNumber: SERIAL")

    def test_values(self):
        m = jf.Masker(NAMES)
        b = list("to 8.8.8.8 \xff".encode("latin-1"))
        self.assertEqual(m.value(b), list("to 203.0.113.1 \xff".encode("latin-1")))
        self.assertEqual(m.value(["alice", "x"]), ["user", "x"])
        self.assertIsNone(m.value(None))
        self.assertEqual(m.value(7), 7)


class TestNamesFor(unittest.TestCase):
    def test_names(self):
        mid = "ab" * 16
        boot = "12345678-9abc-def0-1234-56789abcdef0"
        n = jf.names_for("alice", "Alice Doe,,,", "box1.lan", (mid, boot, "short"))
        self.assertEqual(n["alice"], "user")
        self.assertEqual(n["Alice Doe"], "Real Name")
        self.assertEqual(n["Doe"], "Name")
        self.assertEqual(n["box1.lan"], "host")
        self.assertEqual(n["box1"], "host")
        self.assertEqual(n[mid], "0" * 32)
        self.assertEqual(n[boot], "00000000-0000-0000-0000-000000000000")
        self.assertEqual(n[boot.replace("-", "")], "0" * 32)
        self.assertNotIn("short", n)

    def test_wifi(self):
        out = ("HomeNetwork:802-11-wireless\nWired connection 1:802-3-ethernet\n"
               "a\\:b\\\\c:802-11-wireless\nlo:loopback\nab:802-11-wireless\n")
        self.assertEqual(jf.wifi_names(out), ("HomeNetwork", "a:b\\c", "ab"))
        n = jf.names_for("alice", "", "box1", (), jf.wifi_names(out))
        self.assertEqual((n["HomeNetwork"], n["a:b\\c"]), ("wifi", "wifi"))
        self.assertNotIn("ab", n)                                     # too short
        m = jf.Masker(n)
        s = ("device (wlo1): Activation: starting connection 'HomeNetwork' (uuid) | "
             "Connected to wireless network \"HomeNetwork\" | "
             "wlo1: Trying to associate with 02:00:00:00:00:01 (SSID='Cafe Net' freq=5240)")
        self.assertEqual(m.text(s), "device (wlo1): Activation: starting connection 'wifi' "
                         "(uuid) | Connected to wireless network \"wifi\" | wlo1: Trying "
                         "to associate with 02:00:00:00:00:01 (SSID='wifi' freq=5240)")
        self.assertEqual(m.n["wifi"], 3)
        self.assertEqual(m.text("proctitle=" + hexs("nmcli c up HomeNetwork")),
                         "proctitle=" + hexs("nmcli c up wifi"))              # audit hex

    def test_host_wifi(self):
        saved = jf.NMCLI
        try:
            jf.NMCLI = ("printf", "Home Net:802-11-wireless\\nx:vpn\\n")
            self.assertEqual(jf.host_wifi(), ("Home Net",))
            jf.NMCLI = ("false",)
            self.assertIsNone(jf.host_wifi())                           # nmcli failed
            jf.NMCLI = ("/nonexistent/nmcli",)
            self.assertIsNone(jf.host_wifi())                           # no nmcli
        finally:
            jf.NMCLI = saved

    def test_common_words_stay(self):
        n = jf.names_for("null", "", "fedora", ())
        self.assertEqual(n, {})
        m = jf.Masker(n)
        s = 'key=(null) a1="/dev/null" host fedora'
        self.assertEqual(m.text(s), s)
        self.assertEqual(jf.names_for("root", "Root", "localhost", ()), {})


class TestAuditKeys(unittest.TestCase):
    def test_keys(self):
        self.assertEqual(jf.audit_keys('syscall=59 key="root_cmds"'), ("root_cmds",))
        self.assertEqual(jf.audit_keys("syscall=59 key=(null)"), ())
        self.assertEqual(jf.audit_keys("syscall=59"), ())
        both = "key=" + hexs("a") + "01" + hexs("b")
        self.assertEqual(jf.audit_keys(both), ("a", "b"))


class TestConvert(unittest.TestCase):
    def run_convert(self, es, **kw):
        return jf.convert(lines(*es), jf.Masker(NAMES), **kw)

    def test_sections_fields_cursor(self):
        es = [ent(1, "before"), marker(2, "sudo"),
              audit(3, 10, 1300, 'syscall=59 exe="/usr/bin/id" key="root_cmds"'),
              audit(4, 10, 1309, 'argc=1 a0="id" cwd="/home/alice"'),
              ent(5, "HFW-OUT-NEW: SRC=10.2.0.2 DST=8.8.8.8", _TRANSPORT="kernel"),
              marker(6, "usb"),
              ent(7, "usb 3-6: SerialNumber: ABC", _TRANSPORT="kernel",
                  _KERNEL_SUBSYSTEM="usb")]
        out, rep = self.run_convert(es)
        self.assertEqual(list(out), ["sudo", "usb"])
        self.assertEqual([e["__CURSOR"] for e in out["sudo"]],
                         ["s=1;i=1;b=0;m=0;t=0;x=0", "s=1;i=2;b=0;m=0;t=0;x=0"])
        for e in out["sudo"] + out["usb"]:
            self.assertTrue(set(e) <= set(jf.FIELDS), e)
            self.assertNotIn("_BOOT_ID", e)
            self.assertNotIn("_HOSTNAME", e)
        self.assertEqual(out["sudo"][1]["MESSAGE"], 'argc=1 a0="id" cwd="/home/user"')
        self.assertEqual(out["sudo"][0]["__REALTIME_TIMESTAMP"], "1792410754000000")
        self.assertEqual(out["usb"][0]["MESSAGE"], "usb 3-6: SerialNumber: SERIAL")
        self.assertEqual(rep["before"], 1)
        self.assertEqual(rep["hfw"], 1)
        self.assertEqual(rep["sections"]["sudo"]["events"], {"root_cmds": 1})
        self.assertEqual(rep["sections"]["sudo"]["span"], 2)
        self.assertEqual(rep["masked"], {"name": 1, "serial": 1})

    def test_drop_key(self):
        es = [marker(1, "idle"),
              audit(2, 10, 1300, 'syscall=165 exe="/usr/bin/bwrap" key="mounts"'),
              audit(3, 10, 1327, "proctitle=" + hexs("bwrap")),
              audit(4, 11, 1300, 'syscall=59 key="root_cmds"'),
              audit(5, 11, 1327, "proctitle=" + hexs("id")),
              audit(6, 12, 1300, "syscall=59 key=(null)"),
              audit(7, 13, 1105, "op=PAM:session_open")]
        out, rep = self.run_convert(es, drop=("mounts",))
        self.assertEqual([e["_AUDIT_ID"] for e in out["idle"]], ["11", "11", "12", "13"])
        r = rep["sections"]["idle"]
        self.assertEqual(r["events"], {"mounts": 1, "root_cmds": 1, "-": 1})
        self.assertEqual(r["dropped"], 1)

    def test_repeated_marker_continues(self):
        es = [marker(1, "a"), ent(2, "one"), marker(3, "a"), ent(4, "two"), marker(5, "b"),
              ent(6, "three"), marker(7, "a"), ent(8, "four")]
        out, rep = self.run_convert(es)
        self.assertEqual([e["MESSAGE"] for e in out["a"]], ["one", "two", "four"])
        self.assertEqual([e["MESSAGE"] for e in out["b"]], ["three"])
        self.assertEqual(rep["sections"]["a"]["markers"], 3)
        self.assertEqual(rep["sections"]["b"]["markers"], 1)

    def test_name_option(self):
        es = [ent(1, "avc: denied"), marker(2, "x"), ent(3, "avc: denied")]
        out, rep = self.run_convert(es, name="avc")
        self.assertEqual(list(out), ["avc"])
        self.assertEqual(len(out["avc"]), 2)
        self.assertEqual(rep["before"], 0)

    def test_errors(self):
        cases = ([ent(1, "x")], [marker(1, "Sudo X")], [marker(1, "a" * 41)])
        for es in cases:
            with self.assertRaises(jf.FixtureError, msg=repr(es)):
                self.run_convert(es)
        with self.assertRaises(jf.FixtureError):
            self.run_convert([ent(1, "x")], name="../x")

    def test_bad_lines(self):
        good = lines(marker(1, "a"), ent(2, "x"))
        bad = ["not json\n", json.dumps({"MESSAGE": "no cursor"}) + "\n", "[1]\n",
               json.dumps({"__CURSOR": 1, "__REALTIME_TIMESTAMP": "1"}) + "\n", "\n"]
        out, rep = jf.convert(good + bad, jf.Masker(NAMES))
        self.assertEqual(len(out["a"]), 1)
        self.assertEqual(rep["bad"], 4)


class TestMain(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = os.path.join(self.tmp.name, "fix")

    def run_main(self, es, *args):
        err = io.StringIO()
        rc = jf.main([self.out, *args], stdin=io.StringIO("".join(lines(*es))),
                     stdout=io.StringIO(), stderr=err, names=NAMES)
        return rc, err.getvalue()

    def read(self, name):
        with open(os.path.join(self.out, name), "rb") as f:
            return f.read()

    def test_writes_ascii_lines(self):
        es = [marker(1, "sudo"), ent(2, "caf\u00e9 alice"), marker(3, "empty")]
        rc, err = self.run_main(es)
        self.assertEqual(rc, 0, err)
        self.assertEqual(os.listdir(self.out), ["sudo.json"])
        self.assertNotIn("markers", err)
        raw = self.read("sudo.json")
        raw.decode("ascii")
        self.assertEqual(json.loads(raw)["MESSAGE"], "caf\u00e9 user")
        self.assertIn("sudo: 1 entries", err)
        self.assertIn("masked: name 1", err)

    def test_never_overwrites(self):
        es = [marker(1, "a"), ent(2, "one"), marker(3, "b"), ent(4, "two")]
        self.assertEqual(self.run_main(es)[0], 0)
        os.remove(os.path.join(self.out, "b.json"))
        before = self.read("a.json")
        rc, err = self.run_main(es)
        self.assertEqual(rc, 2)
        self.assertIn("exists, not overwritten", err)
        self.assertEqual(sorted(os.listdir(self.out)), ["a.json"])
        self.assertEqual(self.read("a.json"), before)

    def test_error_exit(self):
        rc, err = self.run_main([ent(1, "x")])
        self.assertEqual(rc, 2)
        self.assertIn("no markers", err)
        self.assertFalse(os.path.exists(self.out))

    def test_fields(self):
        out = io.StringIO()
        self.assertEqual(jf.main(["--fields"], stdout=out), 0)
        fields = out.getvalue().strip().split(",")
        self.assertIn("_AUDIT_ID", fields)
        self.assertIn("MESSAGE", fields)
        self.assertFalse([f for f in fields if f.startswith("__")])
        self.assertNotIn("_HOSTNAME", fields)
        self.assertNotIn("_MACHINE_ID", fields)
        self.assertNotIn("_BOOT_ID", fields)


if __name__ == "__main__":
    unittest.main()
