import json
import os
import tempfile
import unittest

import modules.firewall as fw
from core.module import check_module, validate
from core.run import Result
from modules.firewall import conns, journal, nft, vpn

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "firewall")


def fix(name):
    with open(os.path.join(FIX, name), encoding="ascii") as f:
        return f.read()


def ok(out=""):
    return Result(0, out, "", False, False)


def fail(err="", rc=1):
    return Result(rc, "", err, False, False)


NO_TABLE = fail("Error: No such file or directory\nlist counters table inet hostfw\n")
NO_DEV = fail("Unable to access interface: No such device\n")


class TestNft(unittest.TestCase):
    def test_counters(self):
        c = nft.counters(fix("nft-counters.json"))
        self.assertEqual(len(c), 17)
        self.assertEqual(c["out_leak"], (4, 240))
        self.assertEqual(c["in_noise"], (2236, 314488))
        self.assertEqual(list(c)[0], "out_dns_vpn")            # nft order kept

    def test_counters_bad(self):
        for text in ("[]", '{"nftables": {}}', "not json",
                     '{"nftables": [{"counter": {"name": "x", "packets": -1, "bytes": 0}}]}',
                     '{"nftables": [{"counter": {"name": "x", "packets": true, "bytes": 0}}]}'):
            with self.assertRaises(ValueError, msg=text):
                nft.counters(text)

    def test_mode(self):
        self.assertEqual(nft.mode(fix("nft-enforce.json")), "enforce")
        self.assertEqual(nft.mode(fix("nft-observe.json")), "observe")
        doc = json.loads(fix("nft-enforce.json"))
        doc["nftables"][2]["rule"]["expr"] = [{"accept": None}]
        self.assertEqual(nft.mode(json.dumps(doc)), "unknown")
        doc["nftables"].append(doc["nftables"][2])
        self.assertEqual(nft.mode(json.dumps(doc)), "unknown")

    def test_set(self):
        self.assertEqual(nft.set_elems(fix("nft-wg-fwmark.json")), [0xea13b2c])
        self.assertEqual(nft.set_elems('{"nftables": [{"set": {"name": "s"}}]}'), [])
        with self.assertRaises(ValueError):
            nft.set_elems('{"nftables": []}')

    def test_missing(self):
        self.assertTrue(nft.missing(NO_TABLE.err))
        self.assertFalse(nft.missing("Error: syntax error"))


class TestJournal(unittest.TestCase):
    def test_parse_fixture(self):
        entries, cursor, bad = journal.parse(fix("journal.json"))
        self.assertEqual([e.code for e in entries],
                         ["HFW-OUT-KS", "HFW-IN-NOISE", "HFW-IN-NOISE", "HFW-OUT-LEAK",
                          "HFW-OUT-DNS", "HFW-IN-VPN"])
        self.assertEqual(cursor, "s=0;i=7;b=0;m=0;t=0;x=0")   # last line is not HFW
        self.assertEqual(bad, 0)
        leak = entries[3]
        self.assertEqual(leak.kind, "out_leak")
        self.assertEqual(leak.fields["LEN"], "60")              # first LEN wins
        self.assertIn("SYN", leak.flags)
        self.assertEqual(leak.ts, 1792410745.725672)

    def test_summary(self):
        entries, _, _ = journal.parse(fix("journal.json"))
        s = [journal.summary(e) for e in entries]
        self.assertEqual(s[0], "icmpv6 fe80::1 -> ff02::1:ff00:1 pvpnksintrf0 type 135")
        self.assertEqual(s[3], "uid 1000 tcp 192.168.8.102:46866 -> 203.0.113.11:443 wlo1")
        self.assertEqual(s[5], "tcp 198.51.100.7:51000 -> 10.2.0.2:22 proton0")

    def test_v6_port(self):
        e = journal.Entry(0, "HFW-OUT-LEAK", "out_leak",
                          {"SRC": "2001:0db8:0000:0000:0000:0000:0000:0001", "DST": "2001:db8::2",
                           "SPT": "1", "DPT": "443", "PROTO": "TCP"}, ())
        self.assertEqual(journal.summary(e), "tcp [2001:db8::1]:1 -> [2001:db8::2]:443")

    def test_partial_and_bad_lines(self):
        text = fix("journal.json")
        cut = text[:-20]                                         # last line cut
        entries, cursor, bad = journal.parse(cut)
        self.assertEqual(cursor, "s=0;i=6;b=0;m=0;t=0;x=0")
        self.assertEqual(bad, 0)
        entries, cursor, bad = journal.parse('garbage\n{"__CURSOR": 1}\n' + text)
        self.assertEqual(bad, 2)
        self.assertEqual(len(entries), 6)

    def test_byte_array_message(self):
        msg = list(b"HFW-OUT-LEAK: OUT=wlo1 DST=203.0.113.1 \xff\x1b")
        line = json.dumps({"__CURSOR": "c", "__REALTIME_TIMESTAMP": "1000000", "MESSAGE": msg})
        [e], cursor, _ = journal.parse(line + "\n")
        self.assertEqual((e.code, cursor, e.ts), ("HFW-OUT-LEAK", "c", 1.0))
        self.assertEqual(e.fields["DST"], "203.0.113.1")

    def test_null_message_moves_cursor(self):
        line = json.dumps({"__CURSOR": "c9", "__REALTIME_TIMESTAMP": "1", "MESSAGE": None})
        self.assertEqual(journal.parse(line + "\n"), ([], "c9", 0))

    def test_empty(self):
        self.assertEqual(journal.parse(""), ([], None, 0))


class TestConns(unittest.TestCase):
    def test_fixture(self):
        cs = conns.parse(fix("ss.txt"))
        self.assertEqual(len(cs), 5)
        self.assertEqual(cs[0], conns.Conn("udp", "192.168.8.102%wlo1:68", "192.168.8.1:67",
                                           ("NetworkManager",)))
        self.assertEqual(cs[2].peer, "198.51.100.20:443")
        self.assertEqual(cs[2].procs, ("brave",))

    def test_odd_lines(self):
        text = ('tcp 0 0 [::1]:631 [::1]:5000 users:(("my app",pid=1,fd=3),("my app",pid=2,fd=4),'
                '("b\\"q",pid=3,fd=5))\n'
                "tcp 0 0 1.2.3.4:1 5.6.7.8:2\n"
                "raw 0 0 x y\n"
                "short line\n")
        cs = conns.parse(text)
        self.assertEqual(cs[0].procs, ("my app", 'b\\"q'))
        self.assertEqual(cs[1].procs, ())
        self.assertEqual(len(cs), 2)


class TestVpn(unittest.TestCase):
    def test_fixtures(self):
        self.assertEqual(vpn.handshake(fix("wg-handshakes.txt")), 1792410725)
        self.assertEqual(vpn.transfer(fix("wg-transfer.txt")), (19542372, 3103868))
        self.assertEqual(vpn.endpoint(fix("wg-endpoints.txt")), "203.0.113.83:443")
        self.assertEqual(vpn.fwmark(fix("wg-fwmark.txt")), 0xea13b2c)
        self.assertEqual(vpn.routes(fix("route4.json")),
                         [("pvpnksintrf0", 98, "100.85.0.1"), ("wlo1", 600, "192.168.8.1")])

    def test_edges(self):
        self.assertIsNone(vpn.fwmark("off\n"))
        self.assertEqual(vpn.fwmark("51820"), 51820)
        self.assertEqual(vpn.handshake("a\t0\nb\t5\n"), 5)
        self.assertEqual(vpn.routes(""), [])
        self.assertEqual(vpn.routes("[]"), [])
        for fn, text in ((vpn.handshake, ""), (vpn.transfer, "k\t1\n"), (vpn.endpoint, ""),
                         (vpn.handshake, "k\t-1\n"), (vpn.routes, "{}"),
                         (vpn.routes, '[{"dev": "x", "metric": "1"}]')):
            with self.assertRaises(ValueError, msg=(fn.__name__, text)):
                fn(text)


class Host:
    """Fake run(): answers by argv, keeps a log of calls."""

    def __init__(self):
        self.calls = []
        self.answers = {}
        self.set("nft list counters", ok(fix("nft-counters.json")))
        self.set("nft list chain", ok(fix("nft-enforce.json")))
        self.set("nft list set", ok(fix("nft-wg-fwmark.json")))
        self.set("journalctl", ok(""))
        self.set("ss", ok(fix("ss.txt")))
        self.set("wg latest-handshakes", ok(fix("wg-handshakes.txt")))
        self.set("wg transfer", ok(fix("wg-transfer.txt")))
        self.set("wg endpoints", ok(fix("wg-endpoints.txt")))
        self.set("wg fwmark", ok(fix("wg-fwmark.txt")))
        self.set("ip -4", ok(fix("route4.json")))
        self.set("ip -6", ok(""))

    def set(self, key, res):
        self.answers[key] = res

    def __call__(self, argv, timeout):
        assert os.path.isabs(argv[0]) and timeout < fw.INTERVAL, argv
        self.calls.append(argv)
        words = [os.path.basename(argv[0])] + argv[1:]
        for key, res in sorted(self.answers.items(), key=lambda kv: -len(kv[0])):
            parts = key.split()
            if parts[0] == words[0] and all(p in words for p in parts[1:]):
                return res
        raise AssertionError(f"unexpected argv {argv}")


class TestCollect(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.mode_file = os.path.join(self.tmp.name, "mode")
        with open(self.mode_file, "w") as f:
            f.write("enforce\n")
        self.rb_file = os.path.join(self.tmp.name, "rollback")
        self.host = Host()
        self.mono = 1000.0
        self.wall = 1792410745.0                      # 20 s after the fixture handshake
        self.st = fw.State(run=self.host, mono=lambda: self.mono, wall=lambda: self.wall,
                           owner=os.getuid(), mode_file=self.mode_file,
                           rollback_file=self.rb_file)

    def collect(self):
        return validate(fw.collect(self.st))          # always a valid Snapshot

    def items(self, snap, panel):
        p = next(p for p in snap["panels"] if p["id"] == panel)
        return {i["k"]: (i["v"], i["sev"]) for i in p["items"]}

    def tick(self, sec=2.0):
        self.mono += sec
        self.wall += sec

    def bump(self, name, by):
        doc = json.loads(self.host.answers["nft list counters"].out)
        for it in doc["nftables"]:
            c = it.get("counter")
            if c and c["name"] == name:
                c["packets"] += by
        self.host.set("nft list counters", ok(json.dumps(doc)))

    def test_module_api(self):
        check_module(fw)

    def test_healthy(self):
        s = self.collect()
        self.assertEqual(s["status"], "ok")
        self.assertEqual(s["summary"], "enforce | proton0 up | hs 20s | leak 4")
        self.assertEqual(self.items(s, "hostfw"),
                         {"table": ("loaded", "ok"), "mode": ("enforce", "ok"),
                          "boot mode": ("enforce", "ok"), "rollback": ("-", "ok"),
                          "journal": ("ok", "ok")})
        v = self.items(s, "vpn")
        self.assertEqual(v["tunnel"], ("proton0 up", "ok"))
        self.assertEqual(v["endpoint"], ("203.0.113.83:443", "ok"))
        self.assertEqual(v["handshake"], ("20s ago", "ok"))
        self.assertEqual(v["fwmark"], ("0xea13b2c (in set)", "ok"))
        self.assertEqual(v["default v4"], ("pvpnksintrf0 (kill switch)", "ok"))
        self.assertEqual(v["default v6"], ("none", "ok"))
        self.assertEqual(v["rx / tx"], ("19.5M / 3.1M", "ok"))
        self.assertEqual([p["id"] for p in s["panels"]],
                         ["hostfw", "vpn", "counters", "blocked", "leak", "conns"])

    def test_counters_first_tick_no_alarm(self):
        s = self.collect()
        rows = next(p for p in s["panels"] if p["id"] == "counters")["rows"]
        leak = next(r for r in rows if r["cells"][0] == "out_leak")
        self.assertEqual((leak["cells"], leak["sev"]), (["out_leak", "4", "", "240"], "ok"))

    def test_new_leak_held(self):
        self.collect()
        self.tick()
        self.bump("out_leak", 2)
        s = self.collect()
        self.assertEqual(s["status"], "crit")
        self.assertIn("new out_leak", s["summary"])
        rows = next(p for p in s["panels"] if p["id"] == "counters")["rows"]
        leak = next(r for r in rows if r["cells"][0] == "out_leak")
        self.assertEqual((leak["cells"][2], leak["sev"]), ("+2", "crit"))
        leak_spark = next(p for p in s["panels"] if p["id"] == "leak")
        self.assertEqual((leak_spark["values"], leak_spark["sev"]), ([0, 2], "crit"))
        self.tick(30)
        self.assertEqual(self.collect()["status"], "crit")   # still held
        self.tick(31)
        self.assertEqual(self.collect()["status"], "ok")     # hold over

    def test_severity_kinds(self):
        for name, sev in (("out_dns", "warn"), ("in_vpn", "warn"), ("out_ks", "info"),
                          ("in_noise", "ok"), ("out_wg", "ok"), ("out_probe", "ok")):
            with self.subTest(name=name):
                self.setUp()
                self.collect()
                self.tick()
                self.bump(name, 1)
                self.assertEqual(self.collect()["status"], sev)

    def test_blocked_spark(self):
        self.collect()
        self.tick()
        for name in ("out_ks", "in_noise", "out_wg", "out_dns"):
            self.bump(name, 3)
        s = self.collect()
        self.assertEqual(next(p for p in s["panels"] if p["id"] == "blocked")["values"], [0, 6])

    def test_counter_reset(self):
        self.collect()
        self.tick()
        doc = json.loads(fix("nft-counters.json"))
        for it in doc["nftables"]:
            if "counter" in it:
                it["counter"]["packets"] = 1 if it["counter"]["name"] == "out_leak" else 0
        self.host.set("nft list counters", ok(json.dumps(doc)))
        s = self.collect()                                    # 4 -> 1: reload, count 1
        self.assertEqual(s["status"], "crit")

    def test_events(self):
        self.host.set("journalctl", ok(fix("journal.json")))
        s = self.collect()
        self.assertEqual([(e["code"], e["sev"]) for e in s["events"]],
                         [("HFW-OUT-KS", "info"), ("HFW-OUT-LEAK", "crit"),
                          ("HFW-OUT-DNS", "warn"), ("HFW-IN-VPN", "warn")])   # IN-NOISE hidden
        self.assertEqual(s["events"][1]["msg"],
                         "uid 1000 tcp 192.168.8.102:46866 -> 203.0.113.11:443 wlo1")
        self.assertEqual(self.st.cursor, "s=0;i=7;b=0;m=0;t=0;x=0")
        self.host.calls.clear()
        self.collect()
        [argv] = [c for c in self.host.calls if c[0].endswith("journalctl")]
        self.assertIn("--after-cursor=s=0;i=7;b=0;m=0;t=0;x=0", argv)

    def test_journal_since_without_cursor(self):
        self.collect()
        argv = next(c for c in self.host.calls if c[0].endswith("journalctl"))
        self.assertIn(f"--since=@{self.st.since}", argv)
        self.assertNotIn("-g", argv)

    def test_journal_cut_output(self):
        text = fix("journal.json")
        self.host.set("journalctl", Result(-9, text[:-20], "", False, True))
        s = self.collect()
        self.assertEqual(self.items(s, "hostfw")["journal"][0], "behind (output cut, catching up)")
        self.assertEqual(self.st.cursor, "s=0;i=6;b=0;m=0;t=0;x=0")
        self.assertEqual(len(s["events"]), 4)

    def test_journal_error(self):
        self.host.set("journalctl", fail("Failed to open journal"))
        s = self.collect()
        self.assertEqual(self.items(s, "hostfw")["journal"], ("Failed to open journal", "warn"))
        self.assertEqual(s["status"], "warn")

    def test_table_missing(self):
        self.host.set("nft list counters", NO_TABLE)
        s = self.collect()
        self.assertEqual(s["status"], "crit")
        self.assertEqual(self.items(s, "hostfw")["table"], ("missing", "crit"))
        self.assertTrue(s["summary"].startswith("- | proton0 up"))
        self.assertIn("leak ?", s["summary"])
        self.assertNotIn("counters", [p["id"] for p in s["panels"]])
        self.assertIn("vpn", [p["id"] for p in s["panels"]])     # other sources still shown

    def test_observe(self):
        self.host.set("nft list chain", ok(fix("nft-observe.json")))
        s = self.collect()
        self.assertEqual(s["status"], "warn")
        self.assertEqual(self.items(s, "hostfw")["mode"], ("observe", "warn"))
        self.assertEqual(self.items(s, "hostfw")["boot mode"], ("enforce", "info"))

    def test_rollback(self):
        with open(self.rb_file, "w") as f:
            f.write(f"{int(self.wall) + 130} flush chain inet hostfw enforce\n")
        s = self.collect()
        self.assertEqual(self.items(s, "hostfw")["rollback"], ("armed, 2m 10s left", "info"))
        self.assertEqual(s["status"], "info")
        with open(self.rb_file, "w") as f:
            f.write("something else\n")
        self.assertEqual(self.items(self.collect(), "hostfw")["rollback"], ("armed", "info"))

    def test_mode_file_untrusted(self):
        os.chmod(self.mode_file, 0o666)
        s = self.collect()
        self.assertEqual(self.items(s, "hostfw")["boot mode"][1], "warn")
        os.unlink(self.mode_file)
        os.symlink("/etc/hostname", self.mode_file)            # O_NOFOLLOW
        self.assertEqual(self.items(self.collect(), "hostfw")["boot mode"][1], "warn")

    def test_tunnel_down(self):
        for key in ("wg latest-handshakes", "wg transfer", "wg endpoints", "wg fwmark"):
            self.host.set(key, NO_DEV)
        s = self.collect()
        self.assertEqual(s["status"], "warn")
        self.assertIn("proton0 down", s["summary"])
        v = self.items(s, "vpn")
        self.assertEqual(v["tunnel"], ("proton0 down (Unable to access interface: No such device)",
                                       "warn"))
        self.assertEqual(v["fwmark"], ("set 0xea13b2c", "ok"))   # kept while down: fine

    def test_fwmark_mismatch(self):
        for out in ("0x1\n", "off\n"):
            with self.subTest(out=out):
                self.host.set("wg fwmark", ok(out))
                s = self.collect()
                self.assertEqual(s["status"], "crit")
                self.assertEqual(self.items(s, "vpn")["fwmark"][1], "crit")

    def test_handshake_stale(self):
        self.collect()
        self.tick(300)                                          # 320 s old, idle
        s = self.collect()
        self.assertEqual(self.items(s, "vpn")["handshake"], ("5m ago (idle)", "ok"))
        self.assertEqual(s["status"], "ok")
        self.tick()
        self.host.set("wg transfer", ok("k\t19542372\t3200000\n"))   # tx grew, no new hs
        s = self.collect()
        self.assertEqual(self.items(s, "vpn")["handshake"], ("5m ago, sending", "crit"))
        self.assertEqual(s["status"], "crit")

    def test_handshake_never(self):
        self.host.set("wg latest-handshakes", ok("k\t0\n"))
        s = self.collect()
        self.assertEqual(self.items(s, "vpn")["handshake"], ("never", "info"))
        self.assertIn("hs never", s["summary"])

    def test_default_route_not_ks(self):
        self.host.set("ip -4", ok('[{"dst":"default","gateway":"192.168.8.1","dev":"wlo1",'
                                  '"metric":600}]'))
        s = self.collect()
        self.assertEqual(self.items(s, "vpn")["default v4"],
                         ("wlo1 via 192.168.8.1 metric 600", "warn"))
        self.assertEqual(s["status"], "warn")

    def test_parse_error_isolated(self):
        self.host.set("wg latest-handshakes", ok("garbage"))
        self.host.set("ip -4", ok("{not json"))
        s = self.collect()
        self.assertEqual(s["status"], "warn")
        self.assertIn("wg parse error", s["summary"])
        v = self.items(s, "vpn")
        self.assertEqual(v["tunnel"], ("ValueError: wg: no peer in latest-handshakes", "warn"))
        self.assertTrue(v["routes"][0].startswith("JSONDecodeError"))
        self.assertEqual(self.items(s, "hostfw")["mode"], ("enforce", "ok"))
        self.assertEqual(next(p for p in s["panels"] if p["id"] == "conns")["title"],
                         "connections 5")

    def test_conns(self):
        s = self.collect()
        p = next(p for p in s["panels"] if p["id"] == "conns")
        self.assertEqual(p["title"], "connections 5")
        self.assertEqual(p["rows"][0]["cells"],
                         ["udp", "192.168.8.1:67", "NetworkManager", "192.168.8.102%wlo1:68"])

    def test_commands(self):
        self.collect()
        argvs = [" ".join([os.path.basename(c[0])] + c[1:]) for c in self.host.calls]
        self.assertEqual(argvs, [
            "nft -j list counters table inet hostfw",
            "nft -j list chain inet hostfw enforce",
            f"journalctl _TRANSPORT=kernel -o json --output-fields=MESSAGE -q --no-pager "
            f"--since=@{self.st.since}",
            "wg show proton0 latest-handshakes",
            "wg show proton0 transfer",
            "wg show proton0 endpoints",
            "wg show proton0 fwmark",
            "nft -j list set inet hostfw wg_fwmark",
            "ip -j -4 route show default",
            "ip -j -6 route show default",
            "ss -tunapH state established",
        ])
        self.assertFalse(any("dump" in a for a in argvs))           # never prints private key


class TestInit(unittest.TestCase):
    def test_options(self):
        bad = ({"x": 1}, {"tunnel": "a b"}, {"tunnel": "x" * 16}, {"tunnel": 1},
               {"ks_ifaces": []}, {"ks_ifaces": "pvpn"}, {"ks_ifaces": ["ok", "no way"]},
               {"hold": -1}, {"hold": True}, {"hold": 4000})
        for cfg in bad:
            with self.assertRaises(ValueError, msg=repr(cfg)):
                fw.init(cfg)

    def test_start_cursor(self):
        host = Host()
        host.set("journalctl", ok('{"__CURSOR": "c1", "__REALTIME_TIMESTAMP": "1", '
                                  '"MESSAGE": "x"}\n'))
        st = fw.State(run=host)
        fw._start_cursor(st)
        self.assertEqual(st.cursor, "c1")
        self.assertIn("-n", host.calls[0])
        host.set("journalctl", fail("no journal"))
        st = fw.State(run=host)
        fw._start_cursor(st)
        self.assertIsNone(st.cursor)


if __name__ == "__main__":
    unittest.main()
