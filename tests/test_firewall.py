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

    def test_comments(self):
        c = nft.comments(fix("nft-counters.json"))
        self.assertEqual(c["out_leak"], "host to internet outside the tunnel")
        self.assertEqual(len(c), 17)
        self.assertEqual(nft.comments('{"nftables": [{"counter": {"name": "x"}}]}'), {})

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

    def test_multi_dash_prefixes(self):
        entries, cursor, bad = journal.parse(fix("journal-audit.json"))
        self.assertEqual([(e.code, e.kind, e.dir) for e in entries], [
            ("HFW-OUT-NEW", "out_new", "out"), ("HFW-OUT-NEW", "out_new", "out"),
            ("HFW-FWD-VM-NEW", "fwd_vm_new", "fwd"), ("HFW-OUT-LEAK", "out_leak", "out"),
            ("HFW-IN-LAN", "in_lan", "in"), ("HFW-IN-NOISE", "in_noise", "in"),
            ("HFW-FWD-VM-KS", "fwd_vm_ks", "fwd"), ("HFW-OUT-KS", "out_ks", "out"),
            ("HFW-OUT-LAN-ALLOW", "out_lan_allow", "out")])
        self.assertEqual((cursor, bad), ("s=1;i=9;b=0;m=0;t=0;x=0", 0))

    def test_old_and_other_prefixes(self):
        text = "".join(json.dumps({"__CURSOR": str(i), "__REALTIME_TIMESTAMP": "1",
                                   "MESSAGE": f"{code}: OUT=x"}) + "\n"
                       for i, code in enumerate(("HFW-FWD-KS", "HFW-OUT-ROUTER-ADMIN",
                                                 "HFW-FWD-VM-LAN", "HFW-OUT", "HFW--X")))
        entries, _, _ = journal.parse(text)
        self.assertEqual([e.kind for e in entries],
                         ["fwd_vm_ks", "out_router_admin", "fwd_vm_lan"])   # old prefix alias

    def test_src_dst(self):
        entries, _, _ = journal.parse(fix("journal-audit.json"))
        self.assertEqual((journal.src(entries[0]), journal.dst(entries[0])),
                         ("10.2.0.2:33146", "198.51.100.20:443"))
        self.assertEqual((journal.src(entries[7]), journal.dst(entries[7])),
                         ("fe80::1", "ff02::1:ff00:1"))                     # icmp: no port


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


class TestConnsKey(unittest.TestCase):
    def test_split(self):
        for addr, want in (("10.2.0.2:443", ("10.2.0.2", "443")),
                           ("192.168.8.102%wlo1:68", ("192.168.8.102", "68")),
                           ("[::1]:631", ("::1", "631")),
                           ("[fe80:0:0:0:0:0:0:1%wlo1]:546", ("fe80::1", "546")),
                           ("*:*", ("*", "*")), ("noport", ("noport", ""))):
            self.assertEqual(conns.split(addr), want, addr)

    def test_index(self):
        idx = conns.index(conns.parse(fix("ss.txt")))
        self.assertEqual(idx[("tcp", "10.2.0.2", "33146", "198.51.100.20", "443")], ("brave",))
        self.assertEqual(idx[("udp", "192.168.8.102", "68", "192.168.8.1", "67")],
                         ("NetworkManager",))


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

    def add_counters(self, *names):
        doc = json.loads(self.host.answers["nft list counters"].out)
        for n in names:
            doc["nftables"].append({"counter": {"family": "inet", "name": n, "table": "hostfw",
                                                "handle": 900, "packets": 0, "bytes": 0}})
        self.host.set("nft list counters", ok(json.dumps(doc)))

    def panel(self, snap, pid):
        return next(p for p in snap["panels"] if p["id"] == pid)

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
                         ["hostfw", "vpn", "counters", "blocked", "leak", "audit", "conns"])
        counters = next(p for p in s["panels"] if p["id"] == "counters")
        self.assertEqual(counters["title"], "hostfw counters  (9 zero hidden)")

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
                          ("in_noise", "ok"), ("out_wg", "ok"), ("out_probe", "ok"),
                          ("out_new", "ok"), ("fwd_vm_new", "ok")):
            with self.subTest(name=name):
                self.setUp()
                self.add_counters("out_new", "fwd_vm_new")
                self.collect()
                self.tick()
                self.bump(name, 1)
                self.assertEqual(self.collect()["status"], sev)

    def test_blocked_spark(self):
        self.add_counters("out_new")
        self.collect()
        self.tick()
        for name in ("out_ks", "in_noise", "out_wg", "out_dns", "out_new"):
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

    def rollback(self, text):
        with open(self.rb_file, "w") as f:
            f.write(text)
        return self.items(self.collect(), "hostfw")["rollback"]

    def test_rollback(self):
        # hostfw.sh rollback_arm: printf '%s\n%s\n' deadline "$*"
        deadline = int(self.wall) + 125
        self.assertEqual(self.rollback(f"{deadline}\n/usr/sbin/nft flush chain inet hostfw enforce\n"),
                         ("armed, 2m 05s left -> /usr/sbin/nft flush chain inet hostfw enforce",
                          "info"))
        self.assertEqual(self.collect()["status"], "info")
        self.assertEqual(self.rollback(f"{deadline}\n"), ("armed, 2m 05s left", "info"))
        for text in ("something else\n", "", "12\n", "\u0661\u0662\u0663\n"):
            self.assertEqual(self.rollback(text), ("armed", "info"), repr(text))

    def test_rollback_deadline_passed(self):
        # the timer fired; hostfw.sh keeps the file until confirm / observe / apply
        self.assertEqual(self.rollback(f"{int(self.wall) - 190}\nx\n"),
                         ("deadline passed 3m ago -> x", "info"))
        self.assertEqual(self.collect()["status"], "ok")          # not armed any more
        self.assertEqual(self.rollback(f"{int(self.wall)}\n"), ("deadline passed 0s ago", "info"))

    def test_zero_counters_hidden(self):
        s = self.collect()
        names = [r["cells"][0] for r in self.panel(s, "counters")["rows"]]
        self.assertEqual(names, ["out_dns_vpn", "out_wg", "out_probe", "out_dns", "out_ks",
                                 "out_leak", "in_noise", "in_vpn"])
        self.tick()
        self.bump("out_lan", 1)
        s = self.collect()
        self.assertEqual(self.panel(s, "counters")["title"], "hostfw counters  (8 zero hidden)")
        row = next(r for r in self.panel(s, "counters")["rows"] if r["cells"][0] == "out_lan")
        self.assertEqual((row["cells"][1:3], row["sev"]), (["1", "+1"], "info"))

    def audit(self, chain="nft-enforce.json"):
        self.host.set("nft list chain", ok(fix(chain)))
        self.host.set("journalctl", ok(fix("journal-audit.json")))
        self.st.hms = lambda ts: f"t{int(ts) % 100}"
        self.st.stamp = lambda ts: f"T{ts:.3f}"
        p = self.panel(self.collect(), "audit")
        return p, [r["cells"] for r in p["rows"]], [r["sev"] for r in p["rows"]]

    def test_audit(self):
        p, rows, sevs = self.audit()
        self.assertEqual(p["columns"], ["time", "dir", "verdict", "proto", "uid", "prog",
                                        "src", "dst", "iface"])
        self.assertEqual(p["title"], "audit 8")                     # IN-NOISE hidden
        self.assertEqual(rows, [                                    # newest first
            ["t59", "out", "allow", "tcp", "1000", "?", "192.168.8.102:40100", "192.168.8.50:22",
             "wlo1"],
            ["t58", "out", "drop", "icmpv6", "-", "?", "fe80::1", "ff02::1:ff00:1",
             "pvpnksintrf0"],
            ["t57", "fwd", "drop", "udp", "-", "vm", "192.168.122.10:123", "203.0.113.5:123",
             "virbr0>pvpnksintrf0"],
            ["t55", "in", "zone", "tcp", "-", "-", "192.168.8.50:51544", "192.168.8.102:22",
             "wlo1"],
            ["t54", "out", "block", "tcp", "1000", "?", "192.168.8.102:46900", "203.0.113.11:443",
             "wlo1"],
            ["t53", "fwd", "allow", "tcp", "-", "vm", "192.168.122.10:40000", "198.51.100.22:443",
             "virbr0>proton0"],
            ["t52", "out", "allow", "udp", "1000", "?", "10.2.0.2:50000", "203.0.113.50:443",
             "proton0"],
            ["t51", "out", "allow", "tcp", "1000", "brave", "10.2.0.2:33146", "198.51.100.20:443",
             "proton0"],                                            # program from ss
        ])
        self.assertEqual(sevs, ["ok", "info", "info", "warn", "crit", "ok", "ok", "ok"])
        detail = {d["k"]: d["v"] for d in p["rows"][4]["detail"]}     # the OUT-LEAK row
        self.assertEqual(detail["rule"], "out_leak  host to internet outside the tunnel")
        self.assertEqual(detail["verdict"], "block  rejected by hostfw (enforce mode)")
        self.assertEqual(detail["time"], "T1792410754.000")
        self.assertEqual(detail["prefix"], "HFW-OUT-LEAK")
        self.assertEqual((detail["TTL"], detail["UID"], detail["flags"]), ("64", "1000", "DF SYN"))
        self.assertNotIn("IN", detail)                               # empty field skipped
        keys = [d["k"] for d in p["rows"][4]["detail"]]
        self.assertEqual(keys[:6], ["rule", "verdict", "time", "prefix", "OUT", "SRC"])
        inbound = {d["k"]: d["v"] for d in p["rows"][3]["detail"]}
        self.assertTrue(inbound["verdict"].startswith("zone  hostfw only logs"))
        self.assertEqual(inbound["MAC"], "02:00:00:00:00:02:02:00:00:00:00:03:08:00")
        events = [e["code"] for e in fw.collect(self.st)["events"]]
        self.assertEqual(events, ["HFW-OUT-LEAK", "HFW-IN-LAN", "HFW-FWD-VM-KS", "HFW-OUT-KS",
                                  "HFW-OUT-LAN-ALLOW"])     # no *-NEW, no IN-NOISE events

    def test_audit_observe(self):
        _, rows, _ = self.audit("nft-observe.json")
        self.assertEqual(rows[4][2], "pass")                        # logged, not blocked

    def test_audit_keeps_newest(self):
        for _ in range(30):                                         # 8 rows per tick
            p, rows, _ = self.audit()
            self.tick()
        self.assertEqual(len(rows), fw.MAX_AUDIT)
        self.assertEqual(p["title"], f"audit {fw.MAX_AUDIT}")
        self.assertEqual(rows[0][0], "t59")

    def test_audit_without_ss(self):
        self.host.set("ss", fail("ss: boom"))
        _, rows, _ = self.audit()
        self.assertEqual(rows[-1][5], "?")                          # no program, still shown
        self.assertEqual(len(rows), 8)

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
