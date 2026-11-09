import json
import os
import tempfile
import types
import unittest
from unittest import mock

import modules.firewall as fw
from core import journal as corejournal
from core import netd
from core.module import Context, check_module, validate
from core.run import Result
from core import userd
from modules.firewall import conns, journal, nft, vpn

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "firewall")


def fix(name):
    with open(os.path.join(FIX, name), encoding="ascii") as f:
        return f.read()


def ok(out=""):
    return Result(0, out, "", False, False)


def fail(err="", rc=1):
    return Result(rc, "", err, False, False)


def live(text):
    """Complete JSON lines -> entries as core's follower hands them over (ctx.journal).
    Lines that are not JSON never reach a module (the follower counts them)."""
    out = []
    for line in text.split("\n")[:-1]:
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return tuple(out)


def lab(cells, i=0, base=0.0):
    """Age cell (epoch seconds, shown as an age) -> the name the tests give a time:
    t<seconds % 100>, or t<seconds after base>."""
    out = list(cells)
    v = float(out[i])
    out[i] = f"t{int(v - base)}" if base else f"t{int(v) % 100}"
    return out


NO_TABLE = fail("Error: No such file or directory\nlist table inet hostfw\n")
NO_DEV = fail("Unable to access interface: No such device\n")


def table(chain="nft-enforce.json"):
    """`nft -j -t list table inet hostfw` answer from the counter + chain fixtures:
    metainfo, enforce chain (+ rule), counters. Keeps the counter values of the tests.
    The real host output (nft-table-terse.json) is tested in TestNft."""
    counters = json.loads(fix("nft-counters.json"))["nftables"]
    enforce = json.loads(fix(chain))["nftables"]
    return json.dumps({"nftables": counters[:1] + enforce[1:] + counters[1:]})


class TestNft(unittest.TestCase):
    def test_counters(self):
        c = nft.counters(fix("nft-counters.json"))
        self.assertEqual(len(c), 17)
        self.assertEqual(c["out_leak"], (4, 240))
        self.assertEqual(c["in_noise"], (2236, 314488))
        self.assertEqual(list(c)[0], "out_dns_vpn")            # nft order kept

    def test_logs_from_ruleset(self):
        """2026-11-07: event vs volume counter from the rules, not from a fixed list."""
        lg = nft.logs(fix("nft-table-terse.json"))
        self.assertEqual({n for n, v in lg.items() if v is None},
                         {"out_dns_vpn", "out_wg", "out_vpn_api"})
        self.assertEqual((lg["out_dns"], lg["out_new"], lg["in_noise"]),
                         ("10/minute burst 20", "5/second burst 50", "6/minute burst 10"))
        self.assertEqual(nft.logs(fix("nft-counters.json")), {})      # no rules: unknown

    def test_logs_same_rule_and_changed_ruleset(self):
        def doc(*rules):
            return json.dumps({"nftables": [{"rule": {"chain": c, "expr": e}}
                                            for c, e in rules]})
        m = {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "wg0"}}
        lim = {"limit": {"rate": 3, "per": "second", "burst": 9}}
        log = {"log": {"prefix": "X: "}}
        text = doc(("output", [m, {"counter": "out_wg"}, {"accept": None}]),   # volume
                   ("output", [m, {"counter": "a"}, lim, log, {"accept": None}]),
                   ("deny_b", [{"counter": "b"}]), ("deny_b", [log]),     # next rule, no limit
                   ("deny_c", [{"counter": "c"}]), ("deny_c", [{"jump": {"target": "x"}}]),
                   ("deny_c", [log]),                                     # after the verdict
                   ("deny_d", [{"counter": "d"}]), ("deny_d", [m, log]))  # other match
        self.assertEqual(nft.logs(text), {"out_wg": None,
                                          "a": "3/second burst 9", "b": "",
                                          "c": None, "d": None})

    def test_why_unknown(self):
        w = fw._why_unknown
        self.assertEqual(w("2", "-", "224.0.0.22"),
                         "2: no tcp / udp socket to match (ss lists tcp / udp only)")
        self.assertEqual(w("udp", "-", "192.168.8.1"), "kernel (no socket owner in the log line)")
        self.assertTrue(w("udp", "1000", "239.255.255.250").startswith("discovery"))
        self.assertTrue(w("udp", "1000", "255.255.255.255").startswith("discovery"))
        self.assertTrue(w("udp", "1000", "ff02:0000:0000:0000:0000:0000:0000:00fb")
                        .startswith("discovery"))
        self.assertEqual(w("tcp", "1000", "203.0.113.11"),
                         "short flow, uid 1000: closed before the ss poll")

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

    def test_table_terse(self):
        # `nft -j -t list table inet hostfw` of firewall/hostfw.nft (Mullvad, 2026-10-26),
        # nft 1.0.9, counter values from my host 2026-10-20: no set elements
        text = fix("nft-table-terse.json")
        c = nft.counters(text)
        self.assertEqual(len(c), 17)
        self.assertEqual((list(c)[0], c["out_leak"], c["out_new"]),
                         ("out_dns_vpn", (4, 240), (335, 110636)))
        self.assertEqual(nft.comments(text)["out_leak"], "host to internet outside the tunnel")
        self.assertEqual(nft.mode(text), "enforce")                 # deny rules ignored
        doc = json.loads(text)
        self.assertFalse(any("elem" in it["set"] for it in doc["nftables"] if "set" in it))
        doc["nftables"] = [it for it in doc["nftables"]
                           if it.get("rule", {}).get("chain") != "enforce"]
        self.assertEqual(nft.mode(json.dumps(doc)), "observe")
        doc["nftables"] = [it for it in doc["nftables"]
                           if it.get("chain", {}).get("name") != "enforce"]
        self.assertEqual(nft.mode(json.dumps(doc)), "unknown")      # chain gone

    def test_comments(self):
        c = nft.comments(fix("nft-counters.json"))
        self.assertEqual(c["out_leak"], "host to internet outside the tunnel")
        self.assertEqual(len(c), 17)
        self.assertEqual(nft.comments('{"nftables": [{"counter": {"name": "x"}}]}'), {})

    def test_set(self):
        self.assertEqual(nft.set_elems(fix("nft-wg-fwmark.json")), [0x6d6f6c65])
        self.assertEqual(nft.set_elems('{"nftables": [{"set": {"name": "s"}}]}'), [])
        with self.assertRaises(ValueError):
            nft.set_elems('{"nftables": []}')

    def test_addr_set(self):
        # `nft -j list set inet hostfw vpn_api4` of firewall/hostfw.nft, nft 1.0.9, one
        # element added (RFC 5737)
        self.assertEqual(nft.addr_elems(fix("nft-vpn-api4.json")), ["192.0.2.10"])
        self.assertEqual(nft.addr_elems('{"nftables": [{"set": {"name": "s"}}]}'), [])
        for bad in ('{"nftables": []}', fix("nft-wg-fwmark.json"),
                    '{"nftables": [{"set": {"elem": ["192.0.2.0/24"]}}]}',
                    '{"nftables": [{"set": {"elem": ["192.0.2.010"]}}]}',
                    '{"nftables": [{"set": {"elem": [{"prefix": {}}]}}]}'):
            with self.assertRaises(ValueError, msg=bad):
                nft.addr_elems(bad)

    def test_api_addrs(self):
        # output chain: my host's `nft list chain inet mullvad output` while not connected
        # (2026-11-03, API address masked), other chains from nft-mullvad-terse.json
        # without the tunnel rules; loaded with nft 1.0.9
        self.assertEqual(nft.api_addrs(fix("nft-mullvad-disconnected.json")), ["192.0.2.10"])
        self.assertEqual(nft.api_addrs(fix("nft-mullvad-terse.json")), [])      # connected
        doc = json.loads(fix("nft-mullvad-disconnected.json"))
        rule = next(it for it in doc["nftables"] if "192.0.2.10" in json.dumps(it))
        expr = rule["rule"]["expr"]

        def with_expr(e, chain="output"):
            r = dict(rule["rule"], expr=e, chain=chain)
            return json.dumps({"nftables": [{"rule": r}]})
        self.assertEqual(nft.api_addrs(with_expr(expr[2:3] + expr[:2] + expr[3:])),
                         ["192.0.2.10"])                               # any order
        mark = {"match": {"op": "==", "left": {"meta": {"key": "mark"}}, "right": 1}}
        for e, chain in ((expr, "input"),                              # other chain
                         (expr[:2] + [mark] + expr[3:], "output"),     # relay: mark
                         (expr[:3] + [{"counter": None}] + expr[3:], "output"),
                         (expr[:3] + [{"drop": None}], "output"),
                         ([dict(expr[0], match=dict(expr[0]["match"], op="!="))]
                          + expr[1:], "output")):
            self.assertEqual(nft.api_addrs(with_expr(e, chain)), [], (e, chain))

    def test_policies(self):
        # `nft -j -t list table inet mullvad`: my host's listing 2026-10-26 (relay address
        # masked) loaded with nft 1.0.9. route (mangle) and nat chains do not filter.
        self.assertEqual(nft.policies(fix("nft-mullvad-terse.json")),
                         {"prerouting": "accept", "output": "drop", "input": "drop",
                          "forward": "drop"})
        chain = lambda name, pol: {"chain": {"name": name, "type": "filter", "hook": "output",
                                             "policy": pol}}
        two = {"nftables": [chain("a", "accept"), chain("b", "drop"), chain("c", "accept")]}
        self.assertEqual(nft.policies(json.dumps(two)), {"output": "drop"})   # drop wins
        self.assertEqual(nft.policies(fix("nft-enforce.json")), {})          # no base chain
        with self.assertRaises(ValueError):
            nft.policies('{"nftables": [{"chain": {"type": "filter", "hook": 1}}]}')

    def test_missing(self):
        self.assertTrue(nft.missing(NO_TABLE.err))
        self.assertFalse(nft.missing("Error: syntax error"))


class TestJournal(unittest.TestCase):
    def test_entries_from_follower(self):
        objs = live(fix("journal.json"))
        got, bad = journal.entries(objs + ({"__CURSOR": 1, "__REALTIME_TIMESTAMP": "1"},
                                           {"MESSAGE": "HFW-OUT-LEAK: x"}, ["x"]))
        want, _cursor, _bad = journal.parse(fix("journal.json"))
        self.assertEqual(got, want)                      # same as the text parser
        self.assertEqual(bad, 3)

    def test_parse_fixture(self):
        entries, cursor, bad = journal.parse(fix("journal.json"))
        self.assertEqual([e.code for e in entries],
                         ["HFW-OUT-LAN", "HFW-IN-NOISE", "HFW-IN-NOISE", "HFW-OUT-LEAK",
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
        self.assertEqual(s[0], "icmpv6 fe80::1 -> ff02::1:ff00:1 wlo1 type 131")
        self.assertEqual(s[3], "uid 1000 tcp 192.168.8.102:46866 -> 203.0.113.11:443 wlo1")
        self.assertEqual(s[5], "tcp 198.51.100.7:51000 -> 10.2.0.2:22 wg0-mullvad")

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
            ("HFW-FWD-VM-LAN", "fwd_vm_lan", "fwd"), ("HFW-OUT-LAN", "out_lan", "out"),
            ("HFW-OUT-LAN-ALLOW", "out_lan_allow", "out")])
        self.assertEqual((cursor, bad), ("s=1;i=9;b=0;m=0;t=0;x=0", 0))

    def test_other_prefixes(self):
        text = "".join(json.dumps({"__CURSOR": str(i), "__REALTIME_TIMESTAMP": "1",
                                   "MESSAGE": f"{code}: OUT=x"}) + "\n"
                       for i, code in enumerate(("HFW-OUT-ROUTER-ADMIN", "HFW-FWD-VM-LAN",
                                                 "HFW-OUT", "HFW--X")))
        entries, _, _ = journal.parse(text)
        self.assertEqual([e.kind for e in entries], ["out_router_admin", "fwd_vm_lan"])

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


class TestCgroup(unittest.TestCase):
    """ss --cgroup: program = innermost systemd unit (no CAP_SYS_PTRACE)."""

    def test_fixture(self):
        # `ss -tunaH --cgroup state established` as my user, 2026-10-20 (public IPs masked)
        cs = conns.parse(fix("ss-cgroup.txt"))
        self.assertEqual(len(cs), 14)
        self.assertEqual(cs[0], conns.Conn("udp", "192.168.8.102%wlo1:68", "192.168.8.1:67",
                                           ("NetworkManager",)))
        self.assertEqual([c.procs[0] for c in cs[1:]],
                         ["com.brave.Browser"] * 4 + ["org.telegram.desktop"] * 2
                         + ["com.brave.Browser"] * 7)
        idx = conns.index(cs)
        self.assertEqual(idx[("tcp", "10.2.0.2", "48372", "192.0.2.91", "443")],
                         ("org.telegram.desktop",))

    def test_program(self):
        app = "/user.slice/user-1000.slice/user@1000.service/app.slice/"
        cases = {
            app + "app-flatpak-com.brave.Browser-2324164128.scope": "com.brave.Browser",
            app + "app-gnome-org.gnome.Ptyxis-4711.scope": "org.gnome.Ptyxis",
            app + "app-gnome-brave\\x2dbrowser-8609.scope": "brave-browser",  # rpm Brave (host 2026-11-02)
            app + "app-firefox-12.scope": "firefox",                         # no launcher
            app + "app-gnome-foo\\x2dbar@autostart.service": "foo-bar",       # escaped dash
            app + "app-org.example.Tool.service": "org.example.Tool",
            app + "xdg-document-portal.service": "xdg-document-portal",
            "/system.slice/system-getty.slice/getty@tty1.service": "getty",
            "/user.slice/user-1000.slice/session-3.scope": "session",
            "/machine.slice/machine-qemu\\x2d1\\x2dlab.scope/libvirt": "machine-qemu-1-lab",
            "/x/libpod-" + "a" * 64 + ".scope/container": "libpod",
            "unreachable:1f": None, "/": None, "/user.slice": None, "": None,
        }
        for path, want in cases.items():
            self.assertEqual(conns.program(path), want, path)

    def test_ss_p_wins(self):
        line = ('tcp 0 0 1.2.3.4:1 5.6.7.8:2 users:(("curl",pid=1,fd=3)) '
                "cgroup:/system.slice/x.service\n")
        self.assertEqual(conns.parse(line)[0].procs, ("curl",))

    def test_module_asks_with_cgroup(self):
        host = Host()
        st = fw.State(run=host, net=host)
        fw._conns(st, [])
        argv = host.calls[-1]
        self.assertIn("--cgroup", argv)
        self.assertFalse(any(a.startswith("-") and "p" in a and not a.startswith("--")
                             for a in argv[1:]), argv)                    # no -p


class TestFlow(unittest.TestCase):
    def flow(self, **f):
        return journal.flow(journal.Entry(0, "HFW-OUT-NEW", "out_new", f, ()))

    def test_larger_port_left_out(self):
        self.assertEqual(self.flow(SRC="10.2.0.2", DST="1.2.3.4", SPT="51000", DPT="443"),
                         ("10.2.0.2", "1.2.3.4:443", "src", "51000"))
        self.assertEqual(self.flow(SRC="1.2.3.4", DST="10.2.0.2", SPT="443", DPT="38780"),
                         ("1.2.3.4:443", "10.2.0.2", "dst", "38780"))    # late reply from :443
        self.assertEqual(self.flow(SRC="fdeb:446c:912d:08da:0:0:0:2", DST="2001:db8::1",
                                   SPT="51814", DPT="443"),
                         ("fdeb:446c:912d:8da::2", "[2001:db8::1]:443", "src", "51814"))

    def test_kept(self):
        self.assertEqual(self.flow(SRC="a", DST="b", SPT="123", DPT="123"),
                         ("a:123", "b:123", "", ""))
        self.assertEqual(self.flow(SRC="fe80::1", DST="ff02::1"), ("fe80::1", "ff02::1", "", ""))
        self.assertEqual(self.flow(SRC="a", DST="b", SPT="x", DPT="1"), ("a:x", "b:1", "", ""))


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
        self.assertEqual(vpn.endpoint(fix("wg-endpoints.txt")), "203.0.113.129:56910")
        self.assertEqual(vpn.fwmark(fix("wg-fwmark.txt")), 0x6d6f6c65)

    def test_edges(self):
        self.assertIsNone(vpn.fwmark("off\n"))
        self.assertEqual(vpn.fwmark("51820"), 51820)
        self.assertEqual(vpn.handshake("a\t0\nb\t5\n"), 5)
        for fn, text in ((vpn.handshake, ""), (vpn.transfer, "k\t1\n"), (vpn.endpoint, ""),
                         (vpn.handshake, "k\t-1\n")):
            with self.assertRaises(ValueError, msg=(fn.__name__, text)):
                fn(text)


class Host:
    """Fake run(): answers by argv, keeps a log of calls."""

    def __init__(self):
        self.calls = []
        self.answers = {}
        self.set("nft list table", ok(table()))
        self.set("nft list set", ok(fix("nft-wg-fwmark.json")))
        self.set("nft list set vpn_api4", ok(fix("nft-vpn-api4.json")))
        self.set("journalctl", ok(""))
        self.set("ss", ok(fix("ss.txt")))
        self.set("ss closed", ok(""))                  # unconnected UDP (asked lazily)
        self.set("wg latest-handshakes", ok(fix("wg-handshakes.txt")))
        self.set("wg transfer", ok(fix("wg-transfer.txt")))
        self.set("wg endpoints", ok(fix("wg-endpoints.txt")))
        self.set("wg fwmark", ok(fix("wg-fwmark.txt")))
        self.set("nft list table mullvad", ok(fix("nft-mullvad-terse.json")))

    def set(self, key, res):
        self.answers[key] = res

    def __call__(self, argv, timeout):
        assert os.path.isabs(argv[0]), argv
        assert timeout < fw.INTERVAL or (timeout == fw.BOOT_TIMEOUT and "-b" in argv), argv
        self.calls.append(argv)
        words = [os.path.basename(argv[0])] + argv[1:]
        for key, res in sorted(self.answers.items(), key=lambda kv: -len(kv[0])):
            parts = key.split()
            if parts[0] == words[0] and all(p in words for p in parts[1:]):
                return res
        raise AssertionError(f"unexpected argv {argv}")


class Users:
    """Fake user helper reader (core/userd.py Reader): inode -> Owner."""

    def __init__(self):
        self.owners, self.notes, self.users = {}, [], []

    def __call__(self):
        return dict(self.owners), list(self.notes)


class Base(unittest.TestCase):
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
        self.sysnet = os.path.join(self.tmp.name, "net")     # not the host's /sys/class/net
        os.mkdir(self.sysnet)
        self.users = Users()
        self.cg = os.path.join(self.tmp.name, "cgroup")         # not the host's cgroups
        self.proc = os.path.join(self.tmp.name, "proc")
        self.pw = {}                                            # uid -> name, not the host's
        self.st = fw.State(run=self.host, net=self.host, mono=lambda: self.mono,
                           wall=lambda: self.wall,
                           owner=os.getuid(), mode_file=self.mode_file,
                           rollback_file=self.rb_file, sysnet=self.sysnet, users=self.users,
                           cgroup_root=self.cg, proc_root=self.proc,
                           getpw=self.getpw)

    def getpw(self, uid):
        return types.SimpleNamespace(pw_name=self.pw[uid])

    def tun(self, flags="0x1091", tun_flags=True):
        """The tunnel as a tun device in the fake sysfs (userspace WireGuard)."""
        d = os.path.join(self.sysnet, "wg0-mullvad")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "flags"), "w") as f:
            f.write(flags + "\n")
        if tun_flags:
            with open(os.path.join(d, "tun_flags"), "w") as f:
                f.write("0x1002\n")

    def ctx(self):
        """The fake host's "journalctl" answer = what the follower read since the last
        collect (rc != 0: follower down, err = why)."""
        res = self.host.answers["journalctl"]
        if res.rc != 0:
            return Context((), False, res.err.strip())
        return Context(live(res.out), True, "")

    def collect(self, ctx=None):
        return validate(fw.collect(self.st, ctx or self.ctx()))   # always a valid Snapshot

    def items(self, snap, panel):
        p = next(p for p in snap["panels"] if p["id"] == panel)
        return {i["k"]: (i["v"], i["sev"]) for i in p["items"]}

    def tick(self, sec=2.0):
        self.mono += sec
        self.wall += sec

    def bump(self, name, by):
        doc = json.loads(self.host.answers["nft list table"].out)
        for it in doc["nftables"]:
            c = it.get("counter")
            if c and c["name"] == name:
                c["packets"] += by
        self.host.set("nft list table", ok(json.dumps(doc)))

    def add_counters(self, *names):
        doc = json.loads(self.host.answers["nft list table"].out)
        for n in names:
            doc["nftables"].append({"counter": {"family": "inet", "name": n, "table": "hostfw",
                                                "handle": 900, "packets": 0, "bytes": 0}})
        self.host.set("nft list table", ok(json.dumps(doc)))

    def panel(self, snap, pid):
        return next(p for p in snap["panels"] if p["id"] == pid)

    def argvs(self):
        out = [" ".join([os.path.basename(c[0])] + c[1:]) for c in self.host.calls]
        self.host.calls.clear()
        return out


class TestCollect(Base):
    def test_module_api(self):
        check_module(fw)

    def test_healthy(self):
        s = self.collect()
        self.assertEqual(s["status"], "ok")
        self.assertEqual(s["summary"], "enforce | wg0-mullvad up | hs 20s | leak 4")
        self.assertEqual(self.items(s, "hostfw"),
                         {"table": ("loaded", "ok"), "mode": ("enforce", "ok"),
                          "noscope": ("-", "ok"),            # older ruleset: no switch
                          "boot mode": ("enforce", "ok"), "rollback": ("-", "ok"),
                          "log reader": ("ok", "ok")})
        v = self.items(s, "vpn")
        self.assertEqual(v["tunnel"], ("wg0-mullvad up", "ok"))
        self.assertEqual(v["endpoint"], ("203.0.113.129:56910", "ok"))
        self.assertEqual(v["handshake"], ("20s ago", "ok"))
        self.assertEqual(v["fwmark"], ("0x6d6f6c65 (in set)", "ok"))
        self.assertEqual(v["kill switch"], ("inet mullvad (drop)", "ok"))
        self.assertEqual(v["recv / sent"], ("19.5MB / 3.1MB", "ok"))
        self.assertEqual([p["id"] for p in s["panels"]],
                         ["hostfw", "vpn", "counters", "leak", "blocked", "programs", "peers",
                          "audit"])
        self.assertEqual([p["id"] for p in s["panels"] if p["width"] == "full"], ["audit"])
        counters = next(p for p in s["panels"] if p["id"] == "counters")
        self.assertEqual(counters["title"], "hostfw counters  (11 zero hidden)")

    def test_counter_rows_open_the_log_card(self):
        rows = self.panel(self.collect(), "counters")["rows"]
        logs = {r["cells"][0]: r.get("logs") for r in rows}
        self.assertEqual(logs["out_leak"], "out_leak")
        self.assertEqual(logs["in_noise"], "in_noise")             # noise too
        for name in fw.NOT_LOGGED & set(logs):                     # no lines: plain detail
            self.assertIsNone(logs[name])

    def test_counters_first_tick_no_alarm(self):
        s = self.collect()
        rows = next(p for p in s["panels"] if p["id"] == "counters")["rows"]
        leak = next(r for r in rows if r["cells"][0] == "out_leak")
        self.assertEqual((leak["cells"], leak["sev"]), (["out_leak", "4", "", "240"], "ok"))

    def check(self, snap, key):
        return next((c for c in snap["checks"] if c["key"] == key), None)

    def leak_row(self, snap):
        return next(r for r in self.panel(snap, "counters")["rows"] if r["cells"][0] == "out_leak")

    def test_new_leak_check(self):
        s = self.collect()
        self.assertEqual((s["v"], s["checks"]), (2, []))             # healthy: no checks
        self.tick()
        self.bump("out_leak", 2)
        s = self.collect()
        self.assertEqual(s["status"], "warn")                         # enforce: blocked
        self.assertIn("new out_leak", s["summary"])
        c = self.check(s, "new:out_leak")
        self.assertEqual((c["sev"], c["title"], c["n"], c["at"]),
                         ("warn", "new out_leak (tunnel up, blocked)", 2, self.wall))
        self.assertNotIn("hold", c)                                   # engine: by severity
        self.assertTrue(c["detail"].startswith("+2 pkt this tick; anything else leaving"))
        self.assertIn(fw.BLOCKED_NOTE, c["detail"])
        self.assertEqual((self.leak_row(s)["cells"][2], self.leak_row(s)["sev"]), ("+2", "warn"))
        self.assertEqual(self.panel(s, "leak")["title"], "out_leak 6")    # counter total
        self.tick(30)
        s = self.collect()
        self.assertEqual((s["status"], s["checks"]), ("ok", []))      # this tick only: the
        self.assertEqual(self.leak_row(s)["sev"], "warn")             # engine holds the alert,
        self.tick(271)                                                # the row keeps its color
        self.assertEqual(self.leak_row(self.collect())["sev"], "ok")  # warn: 300 s
        self.assertEqual(self.st.held, {})

    def test_new_leak_check_observe(self):
        """observe: not blocked, it may have left: crit, held 10 min."""
        self.host.set("nft list table", ok(table("nft-observe.json")))
        self.collect()
        self.tick()
        self.bump("out_leak", 1)
        s = self.collect()
        c = self.check(s, "new:out_leak")
        self.assertEqual((c["sev"], c["title"]), ("crit", "new out_leak (tunnel up)"))
        self.assertNotIn(fw.BLOCKED_NOTE, c["detail"])
        self.tick(599)
        self.assertEqual(self.leak_row(self.collect())["sev"], "crit")
        self.tick(2)
        self.assertEqual(self.leak_row(self.collect())["sev"], "ok")

    def test_hold_option(self):
        self.st.hold = 30.0
        self.collect()
        self.tick()
        self.bump("out_leak", 1)
        c = self.check(self.collect(), "new:out_leak")
        self.assertEqual(c["hold"], 30.0)

    def test_leak_context(self):
        down = ("wg latest-handshakes", "wg transfer", "wg endpoints", "wg fwmark")
        for first, sev, ctx in ((None, "info", "pre-connect"),
                                (1.0, "warn", "tunnel down, blocked")):
            with self.subTest(ctx=ctx):
                self.setUp()
                for key in down:
                    self.host.set(key, NO_DEV)
                self.st.tunnel_first = first
                self.collect()
                self.tick()
                self.bump("out_leak", 1)
                s = self.collect()
                c = self.check(s, "new:out_leak")
                self.assertEqual((c["sev"], c["title"]), (sev, f"new out_leak ({ctx})"))
                self.assertIn(fw.CONTEXT_NOTE[ctx.partition(",")[0]], c["detail"])
                self.assertEqual(self.leak_row(s)["sev"], sev)
                spark = self.panel(s, "blocked")["sev"]
                self.assertEqual(spark, sev)

    def in_vpn(self, src):
        text = fix("journal.json").replace("SRC=198.51.100.7", f"SRC={src}")
        self.collect()
        self.tick()
        self.bump("in_vpn", 1)
        self.host.set("journalctl", ok(text))
        return self.check(self.collect(), "new:in_vpn")

    def test_in_vpn_unknown_source(self):
        c = self.in_vpn("198.51.100.7")
        self.assertEqual(c["sev"], "warn")
        self.assertTrue(c["detail"].endswith("; from 198.51.100.7"))

    def test_in_vpn_late_reply(self):
        c = self.in_vpn("203.0.113.10")                      # brave has a socket open to it
        self.assertEqual(c["sev"], "info")
        self.assertIn("late replies from 1 peer(s)", c["detail"])
        self.setUp()
        self.st.peers["192.0.2.9"] = fw.Peer(1.0)
        self.st.peers["192.0.2.9"].new = 1                   # an allowed flow was logged
        self.assertEqual(self.in_vpn("192.0.2.9")["sev"], "info")

    def test_in_vpn_no_line(self):
        self.collect()
        self.tick()
        self.bump("in_vpn", 1)
        c = self.check(self.collect(), "new:in_vpn")
        self.assertEqual(c["sev"], "warn")
        self.assertIn("source unknown", c["detail"])

    def test_merge(self):
        a = {"key": "x", "sev": "warn", "title": "w", "detail": "", "n": 1}
        b = {"key": "x", "sev": "crit", "title": "c", "detail": "d", "n": 2}
        merged = fw._merge([a, b, {**a, "key": "y"}])
        self.assertEqual(merged[0], {"key": "x", "sev": "crit", "title": "c", "detail": "d",
                                     "n": 3})
        self.assertEqual(a["n"], 1)                          # input not changed
        self.assertEqual([c["key"] for c in fw._merge([b, a])], ["x"])
        self.assertEqual(fw._merge([b, a])[0]["title"], "c")

    def test_severity_kinds(self):
        for name, sev in (("out_dns", "warn"), ("in_vpn", "warn"), ("out_lan", "info"),
                          ("in_noise", "ok"), ("out_wg", "ok"), ("out_vpn_api", "ok"),
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
        for name in ("out_lan", "in_noise", "out_wg", "out_dns", "out_new"):
            self.bump(name, 3)
        s = self.collect()
        spark = next(p for p in s["panels"] if p["id"] == "blocked")
        self.assertEqual((spark["values"], spark["sev"]), ([0, 6], "warn"))   # out_dns: warn
        self.tick()
        self.bump("out_lan", 1)
        spark = next(p for p in self.collect()["panels"] if p["id"] == "blocked")
        self.assertEqual((spark["values"][-1], spark["sev"]), (1, "info"))    # out_lan only
        self.tick()
        self.assertEqual(next(p for p in self.collect()["panels"]
                              if p["id"] == "blocked")["sev"], "ok")

    def noscope(self, enforce=False):
        """Table with out_noscope (hostfw 2026-11-03): counter + chain enforce_noscope."""
        self.add_counters("out_noscope")
        doc = json.loads(self.host.answers["nft list table"].out)
        doc["nftables"].append({"chain": {"family": "inet", "table": "hostfw",
                                          "name": "enforce_noscope", "handle": 901}})
        if enforce:
            doc["nftables"].append({"rule": {"family": "inet", "table": "hostfw",
                                             "chain": "enforce_noscope", "handle": 902,
                                             "expr": [{"reject": {"type": "icmpx",
                                                                  "expr": "admin-prohibited"}}]}})
        self.host.set("nft list table", ok(json.dumps(doc)))

    def test_noscope_own_mode(self):
        self.noscope()
        s = self.collect()
        self.assertEqual(self.items(s, "hostfw")["noscope"], ("observe", "ok"))
        self.assertEqual(self.items(s, "hostfw")["mode"], ("enforce", "ok"))   # global
        self.tick()
        self.bump("out_noscope", 2)
        self.host.set("journalctl", ok(jline(
            "ns1", self.wall - 1, "HFW-OUT-NOSCOPE: IN= OUT=wg0-mullvad SRC=10.2.0.2 "
            "DST=198.51.100.7 LEN=60 PROTO=TCP SPT=40100 DPT=443 SYN UID=1000 GID=1000 ")))
        s = self.collect()
        c = self.check(s, "new:out_noscope")
        self.assertEqual((c["sev"], c["n"]), ("warn", 2))
        self.assertIn("GNOME Shell's cgroup", c["detail"])
        flow = self.panel(s, "audit")["rows"][0]
        self.assertEqual(flow["cells"][2:4], ["out", "pass"])          # observe: not blocked
        row = next(r for r in self.panel(s, "counters")["rows"] if r["cells"][0] == "out_noscope")
        self.assertEqual(row["sev"], "warn")

    def test_noscope_enforce(self):
        self.noscope(enforce=True)
        s = self.collect()
        self.assertEqual(self.items(s, "hostfw")["noscope"], ("enforce", "ok"))
        self.assertEqual(fw._verdict("out_noscope", "observe", "enforce"), "block")
        self.assertEqual(fw._verdict("out_leak", "observe", "enforce"), "pass")

    def test_split_always_blocked(self):
        """out_split (hostfw 2026-11-05): split tunneling (mullvad-exclude, setuid) off the
        VM bridges; rejected in every mode, still red: someone tried to leave the tunnel."""
        self.add_counters("out_split")
        for live in ("observe", "enforce", "?"):
            self.assertEqual(fw._verdict("out_split", live), "block", live)
        self.assertEqual(fw.kind_sev("out_split"), "crit")
        self.collect()
        self.tick()
        self.bump("out_split", 1)
        self.host.set("journalctl", ok(jline(
            "sp1", self.wall - 1, "HFW-OUT-SPLIT: IN= OUT=wlp0s20f3 SRC=192.168.1.20 "
            "DST=198.51.100.7 LEN=60 PROTO=TCP SPT=40100 DPT=443 SYN UID=1000 GID=1000 ")))
        s = self.collect()
        c = self.check(s, "new:out_split")
        self.assertEqual((c["sev"], c["n"]), ("crit", 1))
        self.assertIn("mullvad-exclude", c["detail"])
        flow = self.panel(s, "audit")["rows"][0]
        self.assertEqual(flow["cells"][2:4], ["out", "block"])

    def test_counter_reset(self):
        self.collect()
        self.tick()
        doc = json.loads(table())
        for it in doc["nftables"]:
            if "counter" in it:
                it["counter"]["packets"] = 1 if it["counter"]["name"] == "out_leak" else 0
        self.host.set("nft list table", ok(json.dumps(doc)))
        s = self.collect()                                    # 4 -> 1: reload, count 1
        self.assertEqual(s["status"], "warn")                 # out_leak, blocked

    def test_events(self):
        self.host.set("journalctl", ok(fix("journal.json")))
        s = self.collect()
        self.assertEqual([(e["code"], e["sev"]) for e in s["events"]],
                         [("HFW-OUT-LAN", "info"), ("HFW-OUT-LEAK", "warn"),  # blocked
                          ("HFW-OUT-DNS", "warn"), ("HFW-IN-VPN", "warn")])   # IN-NOISE hidden
        self.assertEqual(s["events"][1]["msg"],
                         "uid 1000 tcp 192.168.8.102:46866 -> 203.0.113.11:443 wlo1")
        self.assertFalse([c for c in self.host.calls if c[0].endswith("journalctl")])

    def test_journal_spec(self):
        sp = corejournal.spec(fw.JOURNAL)                 # every kernel entry, no -g
        self.assertEqual(sp.groups, ((("_TRANSPORT", "kernel"),),))
        self.assertEqual(sp.fields, ("MESSAGE",))

    def test_journal_note(self):
        entries = live(fix("journal.json")) + ({"__CURSOR": "x", "MESSAGE": "no time"},)
        s = self.collect(Context(entries, True, "12 entries dropped (buffer full)"))
        self.assertEqual(self.items(s, "hostfw")["log reader"],
                         ("12 entries dropped (buffer full); 1 bad entry", "info"))
        self.assertEqual(len(s["events"]), 4)
        self.assertNotIn("log_reader", [c["key"] for c in s["checks"]])

    def test_journal_down(self):
        why = "journalctl exited (rc 1: Failed to open journal), restart in 2 s"
        s = self.collect(Context(live(fix("journal.json")), False, why))
        self.assertEqual(self.items(s, "hostfw")["log reader"], (why, "warn"))
        [c] = [c for c in s["checks"] if c["key"] == "log_reader"]
        self.assertEqual((c["title"], c["detail"]), ("log reader down", why))
        self.assertEqual(s["status"], "warn")
        self.assertEqual(len(s["events"]), 4)                 # read before the exit: used
        s = self.collect(Context((), False, ""))
        self.assertEqual(self.items(s, "hostfw")["log reader"][0],
                         "journal follower not running")

    def test_table_missing(self):
        self.host.set("nft list table", NO_TABLE)
        s = self.collect()
        self.assertEqual(s["status"], "crit")
        self.assertEqual([(c["key"], c["sev"], c["title"]) for c in s["checks"]],
                         [("table", "crit", "table missing")])
        self.assertEqual(self.items(s, "hostfw")["table"], ("missing", "crit"))
        self.assertTrue(s["summary"].startswith("- | wg0-mullvad up"))
        self.assertIn("leak ?", s["summary"])
        self.assertNotIn("counters", [p["id"] for p in s["panels"]])
        self.assertIn("vpn", [p["id"] for p in s["panels"]])     # other sources still shown

    def test_observe(self):
        self.host.set("nft list table", ok(table("nft-observe.json")))
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
        self.assertEqual(names, ["out_dns_vpn", "out_wg", "out_dns", "out_leak", "in_noise",
                                 "in_vpn"])
        self.tick()
        self.bump("out_lan", 1)
        s = self.collect()
        self.assertEqual(self.panel(s, "counters")["title"], "hostfw counters  (10 zero hidden)")
        row = next(r for r in self.panel(s, "counters")["rows"] if r["cells"][0] == "out_lan")
        self.assertEqual((row["cells"][1:3], row["sev"]), (["1", "+1"], "info"))

    def audit(self, chain="nft-enforce.json"):
        self.host.set("nft list table", ok(table(chain)))
        self.host.set("journalctl", ok(fix("journal-audit.json")))
        self.st.hms = lambda ts: f"t{int(ts) % 100}"
        self.st.stamp = lambda ts: f"T{ts:.3f}"
        p = self.panel(self.collect(), "audit")
        return p, [lab(r["cells"]) for r in p["rows"]], [r["sev"] for r in p["rows"]]

    def test_leak_line_and_audit_flow_one_ref(self):
        """The alerts view merges a leak line with its audit flow (core/render.py)."""
        self.host.set("nft list table", ok(table("nft-enforce.json")))
        self.host.set("journalctl", ok(fix("journal-audit.json")))
        s = self.collect()
        [leak] = self.panel(s, "leak")["rows"]
        flows = [r for r in self.panel(s, "audit")["rows"] if r["cells"][3] == "block"
                 and r["id"].startswith("out_leak|")]
        self.assertEqual([r["ref"] for r in flows], [leak["ref"]])
        self.assertEqual((leak["sev"], flows[0]["sev"]), ("warn", "warn"))

    def test_programs(self):
        self.host.set("nft list table", ok(table("nft-enforce.json")))
        self.host.set("journalctl", ok(fix("journal-audit.json")))
        self.st.hms = lambda ts: f"t{int(ts) % 100}"
        self.st.stamp = lambda ts: f"T{ts:.3f}"
        p = self.panel(self.collect(), "programs")
        self.assertEqual(p["columns"], ["prog", "uid", "open", "out", "block", "in", "peers",
                                        "last"])
        self.assertEqual(p["title"], "programs 6  2 with open sockets")
        rows = {r["id"]: r for r in p["rows"]}
        self.assertEqual([r["id"] for r in p["rows"]][:2], ["brave", "NetworkManager"])  # open
        self.assertEqual(lab(rows["brave"]["cells"], 7),
                         ["brave", "1000", "4", "1", "0", "0", "2", "t51"])
        self.assertEqual(p["types"], ["text", "text", "num", "num", "num", "num", "num", "age"])
        self.assertEqual((rows["brave"]["tone"], rows["brave"]["filter"]), ("blue", "brave"))
        self.assertEqual(rows["brave"]["progs"], ["brave"])                # c = program card
        for other in ("? uid 1000", "(kernel)", "vm", "(inbound)"):
            self.assertNotIn("progs", rows[other], other)
        # no ss match: grouped by uid; the leak (blocked) and two allowed flows of uid 1000
        self.assertEqual(rows["? uid 1000"]["cells"][:6], ["?", "1000", "0", "2", "1", "0"])
        self.assertEqual(rows["? uid 1000"]["filter"], "? 1000")
        # no uid in the line (no socket owner): the kernel's own packets (2026-11-09)
        self.assertEqual((rows["(kernel)"]["cells"][0], rows["(kernel)"]["tone"],
                          rows["(kernel)"]["filter"]), ("(kernel)", "red", "kernel"))
        self.assertEqual(rows["vm"]["cells"][3:5], ["1", "1"])         # FWD-VM-NEW, FWD-VM-LAN
        self.assertEqual((rows["(inbound)"]["cells"][5], rows["(inbound)"]["filter"]),
                         ("1", "zone"))                                # IN-NOISE hidden
        d = {it["k"]: it["v"] for it in rows["brave"]["detail"]}
        self.assertEqual(d["open now"], "4 sockets")
        self.assertEqual(d["peers"], "198.51.100.20 (1), 203.0.113.10 (socket)")
        self.assertEqual(d["kinds"], "out_new 1")
        self.assertEqual({it["k"]: it["v"] for it in rows["(inbound)"]["detail"]}["note"],
                         fw.APP_OTHER["(inbound)"][2])
        self.assertEqual({it["k"]: it["v"] for it in rows["? uid 1000"]["detail"]}["note"],
                         "program unknown: uid 1000, the flow closed before the next ss poll "
                         "(a flow row's detail says why: short flow, discovery, not tcp / udp); "
                         "uid 1000: no process runs as it now")

    def test_programs_keep_and_limit(self):
        self.audit()
        self.host.set("journalctl", ok(""))
        self.host.set("ss", ok(""))
        self.tick()
        p = self.panel(self.collect(), "programs")
        rows = {r["id"]: r for r in p["rows"]}
        self.assertEqual(rows["brave"]["cells"][2:4], ["0", "1"])      # socket gone, line kept
        self.assertEqual(p["title"], "programs 6  0 with open sockets")
        with mock.patch.object(fw, "MAX_APPS", 2):
            self.tick()
            p = self.panel(self.collect(), "programs")
        self.assertEqual(len(p["rows"]), 2)

    def test_programs_filter_only_typeable(self):
        a = fw.App(1.0)
        for name, has in (("brave", True), ("Web Content", True), ("caf\u00e9", False)):
            row = fw._app_row(self.st, name, a, [])
            self.assertEqual("filter" in row, has, name)
        validate({"v": 1, "status": "ok", "summary": "", "events": [],
                  "panels": [{"id": "p", "title": "t", "type": "table",
                              "columns": list(fw.APP_COLUMNS),
                              "rows": [fw._app_row(self.st, "caf\u00e9", a, [])]}]})

    def test_audit(self):
        p, rows, sevs = self.audit()
        self.assertEqual(p["columns"], ["last", "n", "dir", "verdict", "proto", "uid", "prog",
                                        "src", "dst", "iface"])
        self.assertEqual(p["title"], "audit 8 flows  (8 lines)")    # IN-NOISE hidden
        self.assertEqual(p["types"], ["age", "num"] + ["text"] * 8)
        self.assertEqual(p["rows"][0]["cells"][0], f"{float(p['rows'][0]['cells'][0]):.3f}")
        self.assertEqual(rows, [                                    # newest first
            ["t59", "1", "out", "allow", "tcp", "1000", "?", "192.168.8.102", "192.168.8.50:22",
             "wlo1"],                                               # ephemeral port left out
            ["t58", "1", "out", "block", "icmpv6", "-", "(kernel)", "fe80::1", "ff02::1:ff00:1",
             "wlo1"],
            ["t57", "1", "fwd", "block", "udp", "-", "vm", "192.168.122.10:123",
             "203.0.113.5:123", "virbr0>wlo1"],                     # equal ports: both kept
            ["t55", "1", "in", "zone", "tcp", "-", "-", "192.168.8.50", "192.168.8.102:22",
             "wlo1"],                                               # inbound: service port kept
            ["t54", "1", "out", "block", "tcp", "1000", "?", "192.168.8.102", "203.0.113.11:443",
             "wlo1"],
            ["t53", "1", "fwd", "allow", "tcp", "-", "vm", "192.168.122.10", "198.51.100.22:443",
             "virbr0>wg0-mullvad"],
            ["t52", "1", "out", "allow", "udp", "1000", "?", "10.2.0.2", "203.0.113.50:443",
             "wg0-mullvad"],
            ["t51", "1", "out", "allow", "tcp", "1000", "brave", "10.2.0.2", "198.51.100.20:443",
             "wg0-mullvad"],                                        # program from ss
        ])
        self.assertEqual(sevs, ["ok", "info", "warn", "warn", "warn", "ok", "ok", "ok"])
        detail = {d["k"]: d["v"] for d in p["rows"][4]["detail"]}     # the OUT-LEAK row
        self.assertEqual(detail["blocked"], fw.BLOCKED_NOTE)           # enforce: warn
        self.assertEqual(p["rows"][4]["ref"], "fw:" + p["rows"][4]["id"])
        self.assertEqual(detail["count"], "1 line, first T1792410754.000")
        self.assertEqual(detail["src ports"], "46900")
        self.assertEqual(detail["rule"], "out_leak  host to internet outside the tunnel")
        self.assertEqual(detail["verdict"], "block  rejected by hostfw (enforce mode)")
        self.assertEqual(detail["time"], "T1792410754.000")
        self.assertEqual(detail["prefix"], "HFW-OUT-LEAK")
        self.assertEqual((detail["TTL"], detail["UID"], detail["flags"]), ("64", "1000", "DF SYN"))
        self.assertNotIn("IN", detail)                               # empty field skipped
        keys = [d["k"] for d in p["rows"][4]["detail"]]
        self.assertEqual(keys[:10], ["count", "blocked", "src ports", "why ?", "uid",
                                     "last line", "rule", "verdict", "time", "prefix"])
        self.assertEqual(detail["why ?"], "short flow, uid 1000: closed before the ss poll")
        self.assertEqual(detail["uid"], "uid 1000: no process runs as it now")
        self.assertEqual(p["rows"][4]["id"],
                         "out_leak|out|tcp|1000|192.168.8.102|203.0.113.11:443|wlo1")
        self.assertEqual({d["k"]: d["v"] for d in p["rows"][3]["detail"]}["src ports"], "51544")
        inbound = {d["k"]: d["v"] for d in p["rows"][3]["detail"]}
        self.assertTrue(inbound["verdict"].startswith("zone  hostfw only logs"))
        self.assertEqual(inbound["MAC"], "02:00:00:00:00:02:02:00:00:00:00:03:08:00")
        events = [e["code"] for e in fw.collect(self.st, self.ctx())["events"]]
        self.assertEqual(events, ["HFW-OUT-LEAK", "HFW-IN-LAN", "HFW-FWD-VM-LAN", "HFW-OUT-LAN",
                                  "HFW-OUT-LAN-ALLOW"])     # no *-NEW, no IN-NOISE events

    def test_tones(self):
        p, rows, _ = self.audit()
        self.assertEqual([(r[3], t) for r, t in zip(rows, [r["tone"] for r in p["rows"]])], [
            ("allow", "blue"), ("block", "yellow"), ("block", "yellow"), ("zone", "plain"),
            ("block", "yellow"), ("allow", "blue"), ("allow", "blue"), ("allow", "blue")])
        s = self.collect()
        tones = {r["cells"][0]: r["tone"] for r in self.panel(s, "counters")["rows"]}
        self.assertEqual(tones, {"out_dns_vpn": "blue", "out_wg": "blue", "out_dns": "yellow",
                                 "out_leak": "yellow", "in_noise": "plain", "in_vpn": "plain"})
        green = lambda pid: [i["k"] for i in self.panel(s, pid)["items"] if i.get("tone")]
        self.assertEqual(green("hostfw"), ["table", "mode", "boot mode", "log reader"])
        self.assertEqual(green("vpn"), ["tunnel", "handshake", "fwmark", "kill switch"])
        self.assertTrue(all(i["tone"] == "green" for i in self.panel(s, "vpn")["items"]
                            if "tone" in i))

    def test_no_tone_on_problems(self):
        self.host.set("nft list table", ok(table("nft-observe.json")))
        self.host.set("wg fwmark", ok("0x1\n"))
        s = self.collect()
        hostfw = {i["k"]: i for i in self.panel(s, "hostfw")["items"]}
        self.assertNotIn("tone", hostfw["mode"])                       # observe = warn
        self.assertNotIn("tone", hostfw["boot mode"])                  # differs from live
        vpn = {i["k"]: i for i in self.panel(s, "vpn")["items"]}
        self.assertNotIn("tone", vpn["fwmark"])                        # mismatch = crit
        self.assertEqual(next(r for r in self.panel(s, "counters")["rows"]
                              if r["cells"][0] == "out_dns")["tone"], "plain")   # pass

    def counter_detail(self, snap, name):
        row = next(r for r in self.panel(snap, "counters")["rows"] if r["cells"][0] == name)
        return [(d["k"], d["v"]) for d in row["detail"]]

    def test_counter_detail(self):
        self.host.set("journalctl", ok(fix("journal.json")))
        self.st.hms = lambda ts: f"t{int(ts) % 100}"
        s = self.collect()
        d = self.counter_detail(s, "out_dns")
        self.assertEqual(d[:8], [
            ("meaning", "DNS / DoT outside the VPN resolver"),
            ("match", "any other tcp/udp 53, 853 (not the VPN resolver)"),
            ("verdict", "block  rejected by hostfw (enforce mode)"),
            ("new packets", "alert new:out_dns (warn), kept crit 10 min, warn 5 min, info 1 "
                            "min after the last tick with new packets"),
            ("kind", "event: the rule logs, lines below"),
            ("log", "10/min burst 20: lines are samples, the counter is exact"),
            ("bytes", "32.6K (32640)"), ("since", "hostfw table load (a reload resets it)")])
        self.assertEqual(d[8:], [("", ""), ("last lines", "1 since sectop started"),
                                 ("t46", "uid 0 udp 192.168.8.102:40000 -> 198.51.100.53:53 "
                                         "wlo1")])
        noise = dict(self.counter_detail(s, "in_noise"))
        self.assertEqual(noise["last lines"], "2 since sectop started")     # hidden kind kept here
        self.assertEqual(noise["new packets"], "no alert (noise)")
        self.assertEqual(noise["verdict"].split()[0], "zone")
        wg = dict(self.counter_detail(s, "out_wg"))
        self.assertEqual(wg["log"], "counted only, not logged")
        self.assertEqual(wg["kind"], "volume: counted only, no log lines")
        self.assertNotIn("last lines", wg)
        self.assertEqual(wg["new packets"], "no alert (allowed traffic)")
        self.assertIn("(crit, warn when blocked, info pre-connect)", dict(self.counter_detail(s, "out_leak"))[
            "new packets"])
        self.assertEqual(dict(self.counter_detail(s, "in_vpn"))["last lines"],
                         "1 since sectop started")

    def test_counter_detail_keeps_last_lines(self):
        self.st.hms = lambda ts: f"t{int(ts) % 100}"
        text = "".join(jline(f"c{i}", 1000 + i, "HFW-OUT-DNS: OUT=wlo1 PROTO=UDP")
                       for i in range(15))
        self.host.set("journalctl", ok(text))
        d = self.counter_detail(self.collect(), "out_dns")
        lines = d[d.index(("last lines", "10 since sectop started")) + 1:]
        self.assertEqual([k for k, _ in lines], [f"t{i}" for i in range(14, 4, -1)])
        self.host.set("journalctl", ok(""))
        self.tick()
        d = dict(self.counter_detail(self.collect(), "out_leak"))
        self.assertEqual(d["last lines"], "none since sectop started")

    def test_audit_observe(self):
        _, rows, _ = self.audit("nft-observe.json")
        self.assertEqual(rows[4][3], "pass")                        # logged, not blocked

    def lan_lines(self, start, n, dst="fd00::10", spt=51800, uid="1000"):
        return "".join(jline(f"k{start + i}", 1792410000 + start + i,
                             f"HFW-OUT-LAN: IN= OUT=wlo1 SRC=fdeb:446c:912d:8da::2 "
                             f"DST={dst} PROTO=TCP SPT={spt + i} DPT=443 SYN UID={uid} ")
                       for i in range(n))

    def test_audit_groups_repeats(self):
        self.st.hms = lambda ts: f"t{int(ts) % 100}"
        self.host.set("journalctl", ok(self.lan_lines(0, 3) + self.lan_lines(10, 1, uid="994")))
        p = self.panel(self.collect(), "audit")
        self.assertEqual(p["title"], "audit 2 flows  (4 lines)")
        self.assertEqual([lab(r["cells"])[:2] + r["cells"][5:] for r in p["rows"]], [
            ["t10", "1", "994", "?", "fdeb:446c:912d:8da::2", "[fd00::10]:443", "wlo1"],
            ["t2", "3", "1000", "?", "fdeb:446c:912d:8da::2", "[fd00::10]:443", "wlo1"]])
        d = {it["k"]: it["v"] for it in p["rows"][1]["detail"]}
        self.assertEqual(d["src ports"], "51802 51801 51800  (newest first)")
        self.assertEqual(d["SPT"], "51802")                          # fields of the last line
        old_id = p["rows"][1]["id"]
        self.tick()
        self.host.set("journalctl", ok(self.lan_lines(20, 1)))
        p = self.panel(self.collect(), "audit")
        self.assertEqual([lab(r["cells"])[:2] for r in p["rows"]], [["t20", "4"], ["t10", "1"]])
        self.assertEqual(p["rows"][0]["id"], old_id)                 # same flow moved to top
        self.assertEqual(p["title"], "audit 2 flows  (5 lines)")

    def test_audit_programs(self):
        ss = ("tcp 0 0 10.2.0.2:33146 198.51.100.20:443 users:((\"brave\",pid=1,fd=1))\n"
              "tcp 0 0 10.2.0.2:33147 198.51.100.20:443 users:((\"curl\",pid=2,fd=1))\n")
        self.host.set("ss", ok(ss))
        line = ("HFW-OUT-NEW: IN= OUT=wg0-mullvad SRC=10.2.0.2 DST=198.51.100.20 PROTO=TCP "
                "SPT={} DPT=443 SYN UID=1000 ")
        self.host.set("journalctl", ok("".join(jline(f"c{i}", 1792410000 + i, line.format(p))
                                               for i, p in enumerate((33146, 40000, 33147)))))
        row = self.panel(self.collect(), "audit")["rows"][0]
        self.assertEqual(row["cells"][6], "brave,curl")             # '?' line adds nothing
        self.assertEqual({it["k"]: it["v"] for it in row["detail"]}["programs"], "brave, curl")
        self.assertEqual(row["progs"], ["brave", "curl"])
        peer = self.panel(self.collect(), "peers")["rows"][0]
        self.assertEqual(peer["progs"], ["brave", "curl"])

    @mock.patch.object(fw, "MAX_AUDIT", 20)
    def test_audit_keeps_newest(self):
        for i in range(fw.MAX_AUDIT + 5):                           # one new flow per tick
            self.host.set("journalctl", ok(self.lan_lines(i, 1, dst=f"fd00::{i:x}")))
            self.collect()
            self.tick()
        p = self.panel(self.collect(), "audit")
        self.assertEqual(len(p["rows"]), fw.MAX_AUDIT)
        self.assertTrue(p["rows"][0]["cells"][8].startswith(f"[fd00::{fw.MAX_AUDIT + 4:x}]"))
        self.assertTrue(p["rows"][-1]["cells"][8].startswith("[fd00::5]"))   # oldest out

    def test_audit_without_ss(self):
        self.host.set("ss", fail("ss: boom"))
        _, rows, _ = self.audit()
        self.assertEqual(rows[-1][6], "?")                          # no program, still shown
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
        self.assertEqual([c["key"] for c in s["checks"]], ["tunnel_down:wg0-mullvad"])
        self.assertIn("wg0-mullvad down", s["summary"])
        v = self.items(s, "vpn")
        self.assertEqual(v["tunnel"], ("wg0-mullvad down (Unable to access interface: No such "
                                       "device)", "warn"))
        self.assertEqual(v["fwmark"], ("set 0x6d6f6c65", "ok"))   # kept while down: fine
        self.assertEqual(v["kill switch"], ("inet mullvad (drop)", "ok"))   # lockdown: kept

    def test_tunnel_userspace(self):
        # Mullvad DAITA (host 2026-10-30): tun device up, wg show has no device
        for key in ("wg latest-handshakes", "wg transfer", "wg endpoints", "wg fwmark"):
            self.host.set(key, NO_DEV)
        self.tun()
        s = self.collect()
        self.assertEqual(s["checks"], [])
        self.assertEqual(s["status"], "ok")
        self.assertIn("wg0-mullvad up | userspace", s["summary"])
        v = self.items(s, "vpn")
        self.assertEqual(v["tunnel"], ("wg0-mullvad up (userspace)", "ok"))
        self.assertEqual(v["wg data"][1], "ok")
        self.assertEqual(v["fwmark"], ("set 0x6d6f6c65", "ok"))   # no live mark: no claim
        self.assertNotIn("endpoint", v)
        asked = [" ".join(c[1:]) for c in self.host.calls if c[0].endswith("/wg")]
        self.assertFalse(any("endpoints" in a or "fwmark" in a for a in asked), asked)

    def test_tunnel_userspace_not(self):
        for key in ("wg latest-handshakes", "wg transfer", "wg endpoints", "wg fwmark"):
            self.host.set(key, NO_DEV)
        for flags, tun_flags in (("0x1090", True), ("0x1091", False), ("zz", True)):
            with self.subTest(flags=flags, tun_flags=tun_flags):
                self.setUp()
                for key in ("wg latest-handshakes", "wg transfer", "wg endpoints",
                            "wg fwmark"):
                    self.host.set(key, NO_DEV)
                self.tun(flags, tun_flags)        # tun down / kernel device / bad file
                s = self.collect()
                self.assertEqual([c["key"] for c in s["checks"]], ["tunnel_down:wg0-mullvad"])
        self.assertFalse(fw.userspace(self.sysnet, "../etc"))

    def test_tunnel_userspace_then_kernel(self):
        for key in ("wg latest-handshakes", "wg transfer", "wg endpoints", "wg fwmark"):
            self.host.set(key, NO_DEV)
        self.tun()
        self.collect()
        self.host = Host()                                      # DAITA off: kernel wg again
        self.st.run = self.st.net = self.host
        self.tick()
        s = self.collect()
        v = self.items(s, "vpn")
        self.assertEqual(v["tunnel"], ("wg0-mullvad up", "ok"))
        self.assertIn("endpoint", v)                            # slow sources ran again
        self.assertEqual(v["fwmark"][1], "ok")

    def test_fwmark_mismatch(self):
        for out in ("0x1\n", "off\n"):
            with self.subTest(out=out):
                self.setUp()                                    # fresh: fwmark is a slow source
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
        c = self.check(s, "handshake_stale:wg0-mullvad")
        self.assertEqual((c["sev"], c["title"]), ("crit", "handshake stale"))
        self.assertEqual(c["detail"], "last handshake 5m ago, tx growing (keys rejected after "
                                      "180 s)")

    def test_handshake_never(self):
        self.host.set("wg latest-handshakes", ok("k\t0\n"))
        s = self.collect()
        self.assertEqual(self.items(s, "vpn")["handshake"], ("never", "info"))
        self.assertIn("hs never", s["summary"])

    def test_killswitch_missing(self):
        # lockdown mode off and disconnected, or the VPN app stopped
        self.host.set("nft list table mullvad",
                      fail("Error: No such file or directory\nlist table inet mullvad\n"))
        s = self.collect()
        self.assertEqual(self.items(s, "vpn")["kill switch"], ("inet mullvad missing", "warn"))
        c = self.check(s, "killswitch")
        self.assertEqual((c["sev"], c["title"]), ("warn", "kill switch missing"))
        self.assertIn("lockdown mode off", c["detail"])
        self.assertEqual(s["status"], "warn")

    def test_killswitch_open(self):
        doc = json.loads(fix("nft-mullvad-terse.json"))
        for it in doc["nftables"]:
            if it.get("chain", {}).get("name") in ("output", "forward"):
                it["chain"]["policy"] = "accept"
        self.host.set("nft list table mullvad", ok(json.dumps(doc)))
        s = self.collect()
        self.assertEqual(self.items(s, "vpn")["kill switch"],
                         ("inet mullvad: no drop policy on output, forward", "warn"))
        self.assertEqual(self.check(s, "killswitch")["title"], "kill switch open")

    def test_vpn_api_not_seen(self):
        s = self.collect()                                          # connected: no rule
        self.assertEqual(self.items(s, "vpn")["vpn api"],
                         ("vpn_api4 192.0.2.10 (Mullvad's not seen yet: shown only while "
                          "not connected)", "ok"))
        self.assertIsNone(self.st.api_seen)

    def test_vpn_api_same(self):
        self.host.set("nft list table mullvad", ok(fix("nft-mullvad-disconnected.json")))
        s = self.collect()
        self.assertEqual(self.items(s, "vpn")["vpn api"], ("192.0.2.10 (in vpn_api4)", "ok"))
        self.assertEqual(s["status"], "ok")

    def test_vpn_api_changed(self):
        """Mullvad's address seen while not connected, kept after the reconnect."""
        doc = fix("nft-mullvad-disconnected.json").replace("192.0.2.10", "192.0.2.77")
        self.host.set("nft list table mullvad", ok(doc))
        s = self.collect()
        want = (f"Mullvad 192.0.2.77 (seen {self.st.hms(self.wall)}), vpn_api4 192.0.2.10",
                "warn")
        self.assertEqual(self.items(s, "vpn")["vpn api"], want)
        c = self.check(s, "vpn_api")
        self.assertEqual((c["sev"], c["title"]), ("warn", "VPN API address changed"))
        self.assertIn("sudo hostfw api-update", c["detail"])
        self.host.set("nft list table mullvad", ok(fix("nft-mullvad-terse.json")))
        self.st.slow_at = None
        self.tick()
        s = self.collect()                                          # connected again
        self.assertEqual(self.items(s, "vpn")["vpn api"], want)    # still warned
        self.host.set("nft list set vpn_api4", ok(fix("nft-vpn-api4.json")
                                                  .replace("192.0.2.10", "192.0.2.77")))
        self.st.slow_at = None
        s = self.collect()                                          # after api-update
        self.assertEqual(self.items(s, "vpn")["vpn api"], ("192.0.2.77 (in vpn_api4)", "ok"))

    def test_vpn_api_set_problems(self):
        self.host.set("nft list table mullvad", ok(fix("nft-mullvad-disconnected.json")))
        self.host.set("nft list set vpn_api4", ok('{"nftables": [{"set": {"name": "x"}}]}'))
        s = self.collect()
        self.assertEqual(self.items(s, "vpn")["vpn api"][1], "warn")
        self.assertIn("vpn_api4 empty", self.items(s, "vpn")["vpn api"][0])
        self.host.set("nft list set vpn_api4", fail("Error: No such file or directory\n"))
        self.st.slow_at = None
        s = self.collect()
        self.assertEqual(self.items(s, "vpn")["vpn api"],
                         ("vpn_api4: Error: No such file or directory", "warn"))

    def test_parse_error_isolated(self):
        self.host.set("wg latest-handshakes", ok("garbage"))
        self.host.set("nft list table mullvad", ok("{not json"))
        s = self.collect()
        self.assertEqual(s["status"], "warn")
        self.assertIn("wg parse error", s["summary"])
        self.assertEqual(sorted(c["key"] for c in s["checks"]), ["parse:killswitch", "parse:wg"])
        v = self.items(s, "vpn")
        self.assertEqual(v["tunnel"], ("ValueError: wg: no peer in latest-handshakes", "warn"))
        self.assertTrue(v["kill switch"][0].startswith("JSONDecodeError"))
        self.assertEqual(self.items(s, "hostfw")["mode"], ("enforce", "ok"))
        self.assertEqual(self.panel(s, "peers")["title"], "peers 3  5 open")

    def test_peers_from_sockets(self):
        self.st.hms = lambda ts: f"t{int(ts) % 100}"
        s = self.collect()
        p = self.panel(s, "peers")
        self.assertEqual(p["columns"], ["peer", "open", "new", "drop", "prog", "last"])
        self.assertEqual(p["title"], "peers 3  5 open")
        self.assertEqual(p["types"], ["text", "num", "num", "num", "text", "age"])
        self.assertEqual([lab(r["cells"], 5) for r in p["rows"]], [
            ["203.0.113.10", "3", "0", "0", "brave", "t45"],
            ["192.168.8.1", "1", "0", "0", "NetworkManager", "t45"],      # tie: by address
            ["198.51.100.20", "1", "0", "0", "brave", "t45"]])
        self.assertEqual([r["tone"] for r in p["rows"]], ["blue"] * 3)
        self.assertEqual(p["rows"][0]["id"], "203.0.113.10")
        d = [(it["k"], it["v"]) for it in p["rows"][0]["detail"]]
        self.assertEqual(d[:5], [
            ("scope", "private"), ("open now", "3 sockets"),
            ("socket", "udp 10.2.0.2:37436 -> 203.0.113.10:443  brave"),
            ("socket", "tcp 10.2.0.2:54294 -> 203.0.113.10:443  brave"),
            ("socket", "tcp 10.2.0.2:54308 -> 203.0.113.10:443  brave")])
        self.assertEqual(dict(d)["ports"], "443")

    def test_peers_from_log(self):
        self.st.hms = lambda ts: f"t{int(ts) % 100}"
        self.st.stamp = lambda ts: f"T{int(ts)}"
        self.host.set("ss", ok(""))
        self.host.set("journalctl", ok(fix("journal-audit.json")))
        p = self.panel(self.collect(), "peers")
        cells = {r["cells"][0]: lab(r["cells"], 5) for r in p["rows"]}
        self.assertEqual(cells["198.51.100.20"], ["198.51.100.20", "0", "1", "0", "?", "t51"])
        self.assertEqual(cells["203.0.113.11"][2:4], ["0", "1"])     # the leak: blocked
        self.assertEqual(cells["192.168.8.50"][2:4], ["1", "1"])     # lan allow out + in_lan in
        self.assertNotIn("ff02::1:ff00:1", cells)                    # multicast skipped
        self.assertNotIn("192.168.8.227", cells)                     # in_noise hidden
        rows = {r["cells"][0]: r for r in p["rows"]}
        self.assertEqual(rows["203.0.113.11"]["tone"], "red")        # only blocked
        d = {it["k"]: it["v"] for it in rows["192.168.8.50"]["detail"]}
        self.assertEqual(d["verdicts"], "zone 1, allow 1")         # most first, then seen first
        self.assertEqual((d["first seen"], d["last seen"]), ("T1792410755", "T1792410759"))
        self.assertEqual((d["ports"], d["ifaces"], d["uids"]), ("51544, 22", "wlo1", "1000"))
        self.assertEqual(p["rows"][0]["cells"][0], "192.168.8.50")   # most recent first

    @mock.patch.object(fw, "MAX_PEERS", 20)
    def test_peers_order_and_limit(self):
        self.host.set("ss", ok(""))
        for i in range(fw.MAX_PEERS + 3):
            self.host.set("journalctl", ok(jline(f"c{i}", 1792410000 + i,
                                                 f"HFW-OUT-NEW: OUT=wg0-mullvad SRC=10.2.0.2 "
                                                 f"DST=198.51.{i // 256}.{i % 256} PROTO=TCP "
                                                 f"SPT=40000 DPT=443 UID=1000 ")))
            self.collect()
        self.host.set("journalctl", ok(""))
        self.host.set("ss", ok(fix("ss.txt")))
        p = self.panel(self.collect(), "peers")
        self.assertEqual(len(p["rows"]), fw.MAX_PEERS)
        self.assertEqual(p["rows"][0]["cells"][1], "3")               # open sockets first
        ips = [r["cells"][0] for r in p["rows"]]
        self.assertNotIn("198.51.0.5", ips)                          # least recently seen out
        self.assertIn("198.51.0.6", ips)
        self.assertEqual(ips[3], f"198.51.0.{fw.MAX_PEERS + 2}")     # then newest log line

    def test_ip_on_rows(self):
        self.host.set("journalctl", ok(fix("journal-audit.json")))
        s = self.collect()
        vpn_items = {i["k"]: i for i in self.panel(s, "vpn")["items"]}
        self.assertEqual(vpn_items["endpoint"]["ip"], "203.0.113.129")
        self.assertNotIn("ip", vpn_items["tunnel"])
        audit = {r["cells"][8]: r.get("ip") for r in self.panel(s, "audit")["rows"]}
        self.assertEqual(audit["198.51.100.20:443"], "198.51.100.20")       # out: dst
        self.assertEqual(audit["192.168.8.102:22"], "192.168.8.50")         # in: src
        self.assertEqual(audit["ff02::1:ff00:1"], "ff02::1:ff00:1")
        peers = self.panel(s, "peers")["rows"]
        self.assertTrue(all(r["ip"] == r["cells"][0] for r in peers))
        self.host.set("wg endpoints", ok("k\t(none)\n"))
        self.tick(fw.SLOW)                                      # endpoint: slow source
        vpn_items = {i["k"]: i for i in self.panel(self.collect(), "vpn")["items"]}
        self.assertNotIn("ip", vpn_items["endpoint"])

    def test_leak_row_ip(self):
        self.host.set("journalctl", ok(jline("l1", 1792410746, LEAK.format(spt=1))))
        row = self.panel(self.collect(), "leak")["rows"][0]
        self.assertEqual(row["ip"], "203.0.113.11")

    def test_peers_ss_error(self):
        self.host.set("ss", fail("ss: boom"))
        p = self.panel(self.collect(), "peers")
        self.assertEqual((p["title"], p["sev"]), ("peers 0  0 open  (ss: ss: boom)", "warn"))

    def test_scope(self):
        import ipaddress
        for ip, want in (("8.8.8.8", "public"), ("10.2.0.1", "private"),
                         ("100.85.0.1", "shared (CGNAT)"), ("fe80::1", "link-local"),
                         ("fdeb:446c:912d:8da::2", "unique local (ULA)"),
                         ("2607:6bc0::10", "public")):
            self.assertEqual(fw._scope(ipaddress.ip_address(ip)), want, ip)
        for bad in ("127.0.0.53", "::1", "ff02::1", "255.255.255.255", "0.0.0.0", "x"):
            self.assertIsNone(fw._addr(bad), bad)

    def test_commands(self):
        self.collect()
        argvs = self.argvs()
        self.assertEqual(argvs, [
            "nft -j -t list table inet hostfw",
            "wg show wg0-mullvad latest-handshakes",
            "wg show wg0-mullvad transfer",
            "wg show wg0-mullvad endpoints",
            "wg show wg0-mullvad fwmark",
            "nft -j list set inet hostfw wg_fwmark",
            "nft -j -t list table inet mullvad",
            "nft -j list set inet hostfw vpn_api4",
            "ss -tunaeH --cgroup state established",
        ])
        self.assertFalse(any("dump" in a for a in argvs))           # never prints private key

    def test_commands_per_tick(self):
        fast = ["nft", "wg latest-handshakes", "wg transfer", "ss"]
        words = lambda: [a.split()[0] if a.split()[0] != "wg" else "wg " + a.split()[3]
                         for a in self.argvs()]
        self.collect()
        self.assertEqual(len(words()), 9)                           # first tick: all sources
        for _ in range(int(fw.SLOW // 2) - 1):
            self.tick()
            self.collect()
            self.assertEqual(words(), fast)                         # 4 commands per tick
        self.tick()
        self.collect()
        self.assertEqual(len(words()), 9)                           # SLOW s later: all again

    def test_slow_refresh_on_tunnel_change(self):
        self.collect()
        self.tick()
        for key in ("wg latest-handshakes", "wg transfer"):
            self.host.set(key, NO_DEV)
        self.argvs()
        s = self.collect()                                          # up -> down: refresh now
        self.assertEqual([a for a in self.argvs() if not a.startswith(("journalctl", "ss"))], [
            "nft -j -t list table inet hostfw", "wg show wg0-mullvad latest-handshakes",
            "nft -j list set inet hostfw wg_fwmark", "nft -j -t list table inet mullvad",
            "nft -j list set inet hostfw vpn_api4"])
        v = self.items(s, "vpn")
        self.assertNotIn("endpoint", v)
        self.assertEqual(v["fwmark"], ("set 0x6d6f6c65", "ok"))
        self.tick()
        self.host.set("wg latest-handshakes", ok(fix("wg-handshakes.txt")))
        self.host.set("wg transfer", ok(fix("wg-transfer.txt")))
        s = self.collect()                                          # down -> up: refresh now
        self.assertEqual(self.items(s, "vpn")["fwmark"], ("0x6d6f6c65 (in set)", "ok"))
        self.assertIn("wg show wg0-mullvad endpoints", self.argvs())

    def test_slow_checks_kept(self):
        self.host.set("nft list table mullvad",
                      fail("Error: No such file or directory\nlist table inet mullvad\n"))
        self.assertEqual(self.collect()["status"], "warn")
        self.tick()
        self.argvs()
        s = self.collect()                                          # no kill switch call
        self.assertNotIn("nft -j -t list table inet mullvad", self.argvs())
        self.assertEqual(s["status"], "warn")
        self.assertEqual(self.items(s, "vpn")["kill switch"], ("inet mullvad missing", "warn"))

    def test_fwmark_unreadable(self):
        self.host.set("wg fwmark", ok("garbage\n"))
        s = self.collect()
        self.assertEqual(s["status"], "warn")                       # no mismatch claim
        self.assertTrue(self.items(s, "vpn")["fwmark"][0].startswith("live: ValueError"))
        self.assertIn("wg parse error", s["summary"])


def jline(cur, ts, msg):
    return json.dumps({"__CURSOR": cur, "__REALTIME_TIMESTAMP": str(int(ts * 1e6)),
                       "MESSAGE": msg}) + "\n"


LEAK = ("HFW-OUT-LEAK: IN= OUT=wlo1 SRC=192.168.8.102 DST=203.0.113.11 LEN=60 PROTO=TCP "
        "SPT={spt} DPT=443 SYN UID=1000 GID=1000 ")
NEW = ("HFW-OUT-NEW: IN= OUT=wg0-mullvad SRC=10.2.0.2 DST=198.51.100.20 LEN=60 PROTO=TCP "
       "SPT=33146 DPT=443 SYN UID=1000 GID=1000 ")


class TestLeakBox(Base):
    BOOT = 1792410000.0                                  # wall 1792410745 - uptime 745

    def setUp(self):
        super().setUp()
        self.uptime = os.path.join(self.tmp.name, "uptime")
        with open(self.uptime, "w") as f:
            f.write("745.00 2900.10\n")
        self.st.uptime_file = self.uptime
        self.st.hms = lambda ts: f"t{int(ts - self.BOOT)}"

    def boot(self, first=None, leaks=()):
        self.host.set("journalctl --grep=^HFW-OUT-NEW:",
                      ok(jline("n1", first, NEW)) if first is not None else fail(""))
        self.host.set("journalctl --grep=^HFW-OUT-LEAK:",
                      ok("".join(jline(c, ts, LEAK.format(spt=40000 + i))
                                 for i, (c, ts) in enumerate(leaks))))
        fw._boot_scan(self.st)

    def rows(self, snap):
        return [(lab(r["cells"], 0, self.BOOT), r["sev"])
                for r in self.panel(snap, "leak")["rows"]]

    def test_boot_scan_context(self):
        self.boot(first=self.BOOT + 40, leaks=[("b1", self.BOOT + 12), ("b2", self.BOOT + 300)])
        self.assertEqual(self.st.boot, self.BOOT)
        s = self.collect()
        self.assertEqual(self.rows(s), [
            (["t300", "1000", "tcp", "203.0.113.11:443", "wlo1", "after connect, blocked"],
             "warn"),
            (["t12", "1000", "tcp", "203.0.113.11:443", "wlo1", "pre-connect"], "info")])
        p = self.panel(s, "leak")
        self.assertEqual((p["title"], p["sev"]), ("out_leak 4", "warn"))
        self.assertEqual(p["columns"], ["age", "uid", "proto", "dst", "iface", "context"])
        self.assertEqual(p["types"], ["age"] + ["text"] * 5)
        d = {it["k"]: it["v"] for it in p["rows"][1]["detail"]}
        self.assertTrue(d["meaning"].startswith("before the first flow via the tunnel"))
        self.assertEqual(d["after boot"], "12s")
        self.assertEqual(d["rule"], "out_leak  host to internet outside the tunnel")
        self.assertEqual(d["verdict"], "block  rejected by hostfw (enforce mode)")
        self.assertEqual(d["SPT"], "40000")
        d = {it["k"]: it["v"] for it in p["rows"][0]["detail"]}
        self.assertEqual(d["after boot"], "5m 00s")

    def test_boot_scan_argv(self):
        self.boot()
        argvs = [c for c in self.host.calls if c[0].endswith("journalctl")]
        self.assertEqual([a[1:] for a in argvs], [
            ["-b", "0", "_TRANSPORT=kernel", "-o", "json", "--output-fields=MESSAGE", "-q",
             "--no-pager", "--grep=^HFW-OUT-NEW:", "-n", "+1"],
            ["-b", "0", "_TRANSPORT=kernel", "-o", "json", "--output-fields=MESSAGE", "-q",
             "--no-pager", "--grep=^HFW-OUT-LEAK:"]])
        self.assertEqual(self.st.boot_note, "")              # rc 1, no output: no match

    def test_no_tunnel_flow_this_boot(self):
        self.boot(first=None, leaks=[("b1", self.BOOT + 900)])
        self.assertEqual(self.rows(self.collect())[0][0][-1], "pre-connect")

    def test_live_dedupe_and_tunnel_up(self):
        self.boot(first=self.BOOT + 40, leaks=[("b1", self.BOOT + 12)])
        self.host.set("journalctl", ok(jline("b1", self.BOOT + 12, LEAK.format(spt=1)) +
                                       jline("l2", self.BOOT + 700, LEAK.format(spt=2))))
        s = self.collect()                                   # b1 again: follower from start
        self.assertEqual([r[0][-1] for r in self.rows(s)],
                         ["after connect, blocked", "pre-connect"])
        self.tick()                                          # l2: before sectop watched
        self.host.set("journalctl", ok(jline("l3", self.wall - 1, LEAK.format(spt=3))))
        s = self.collect()
        self.assertEqual([r[0][-1] for r in self.rows(s)],
                         ["tunnel up, blocked", "after connect, blocked", "pre-connect"])
        self.assertEqual(self.rows(s)[0][1], "warn")

    def test_live_tunnel_down(self):
        for key in ("wg latest-handshakes", "wg transfer", "wg endpoints", "wg fwmark"):
            self.host.set(key, NO_DEV)
        self.boot()
        self.host.set("journalctl", ok(jline("l1", self.wall - 1, LEAK.format(spt=1))))
        self.assertEqual(self.rows(self.collect())[0][0][-1], "pre-connect")
        self.tick()
        self.host.set("journalctl", ok(jline("n9", self.wall - 1.5, NEW) +
                                       jline("l2", self.wall - 1, LEAK.format(spt=2))))
        self.assertEqual(self.rows(self.collect())[0][0][-1], "tunnel down, blocked")
        self.assertEqual(self.st.tunnel_first, self.wall - 1.5)

    def test_connect_tick_pre_connect(self):
        """2026-10-26: pre-connect lines read on the tick the tunnel came up were
        `tunnel up` (crit). Context = state at line time."""
        down = ("wg latest-handshakes", "wg transfer", "wg endpoints", "wg fwmark")
        saved = {k: self.host.answers[k] for k in down}
        for key in down:
            self.host.set(key, NO_DEV)
        self.boot()
        self.collect()                                       # tunnel down, no flow yet
        self.tick()
        for key, res in saved.items():
            self.host.set(key, res)                          # tunnel up on this tick
        self.host.set("journalctl", ok(jline("l1", self.wall - 1.5, LEAK.format(spt=1)) +
                                       jline("n1", self.wall - 1, NEW)))
        self.bump("out_leak", 1)
        s = self.collect()
        self.assertEqual(self.rows(s), [
            (["t745", "1000", "tcp", "203.0.113.11:443", "wlo1", "pre-connect"], "info")])
        c = next(c for c in s["checks"] if c["key"] == "new:out_leak")
        self.assertEqual((c["sev"], c["title"]), ("info", "new out_leak (pre-connect)"))

    def test_counter_without_line_in_connect_window(self):
        down = ("wg latest-handshakes", "wg transfer", "wg endpoints", "wg fwmark")
        saved = {k: self.host.answers[k] for k in down}
        for key in down:
            self.host.set(key, NO_DEV)
        self.boot()
        self.collect()
        self.tick()
        for key, res in saved.items():
            self.host.set(key, res)
        self.host.set("journalctl", ok(jline("n1", self.wall - 1, NEW)))
        self.bump("out_leak", 2)                             # leak lines rate limited
        c = next(c for c in self.collect()["checks"] if c["key"] == "new:out_leak")
        self.assertEqual((c["sev"], c["title"]), ("info", "new out_leak (pre-connect)"))
        self.tick()
        self.host.set("journalctl", ok(""))
        self.bump("out_leak", 1)                             # up for the whole window
        c = next(c for c in self.collect()["checks"] if c["key"] == "new:out_leak")
        self.assertEqual((c["sev"], c["title"]), ("warn", "new out_leak (tunnel up, blocked)"))

    def test_boot_scan_error(self):
        self.host.set("journalctl --grep=^HFW-OUT-NEW:", fail("Failed to open journal"))
        self.host.set("journalctl --grep=^HFW-OUT-LEAK:",
                      ok(jline("b1", self.BOOT + 12, LEAK.format(spt=1))))
        fw._boot_scan(self.st)
        p = self.panel(self.collect(), "leak")
        self.assertEqual(p["title"], "out_leak 4  (boot scan: first flow Failed to open journal)")
        self.assertEqual([r["cells"][-1] for r in p["rows"]], ["unknown, blocked"])

    def test_boot_scan_cut_and_bad_json(self):
        text = jline("b1", self.BOOT + 12, LEAK.format(spt=1))
        self.host.set("journalctl --grep=^HFW-OUT-NEW:", fail(""))
        self.host.set("journalctl --grep=^HFW-OUT-LEAK:",
                      Result(-9, text + text[:30], "", True, False))
        fw._boot_scan(self.st)
        p = self.panel(self.collect(), "leak")
        self.assertEqual(len(p["rows"]), 1)                  # complete lines kept
        self.assertIn("(boot scan: leaks cut)", p["title"])

    def test_rows_capped_newest_first(self):
        self.boot(leaks=[(f"b{i}", self.BOOT + i) for i in range(12)])
        p = self.panel(self.collect(), "leak")
        self.assertEqual([lab(r["cells"], 0, self.BOOT)[0] for r in p["rows"]],
                         [f"t{i}" for i in range(11, 3, -1)])
        self.assertEqual(p["title"], "out_leak 4  (newest 8 of 12 lines)")
        self.assertEqual(p["sev"], "ok")                     # pre-connect only

    def test_no_uptime(self):
        self.st.uptime_file = os.path.join(self.tmp.name, "missing")
        self.boot(leaks=[("b1", self.BOOT + 12)])
        d = [it["k"] for it in self.panel(self.collect(), "leak")["rows"][0]["detail"]]
        self.assertNotIn("after boot", d)
        self.assertEqual(d[:2], ["meaning", "rule"])

    def test_since(self):
        self.assertEqual([fw._since(x) for x in (-1, 0, 119, 120, 3599, 3600, 90061)],
                         ["?", "0s", "119s", "2m 00s", "59m 59s", "1h 00m", "25h 01m"])


SHELL = "/user.slice/user-1000.slice/user@1000.service/session.slice/org.gnome.Shell@user.service"
UDP_NEW = ("HFW-OUT-NEW: IN= OUT=wg0-mullvad SRC=10.2.0.2 DST=203.0.113.50 LEN=1278 PROTO=UDP "
           "SPT={spt} DPT=443 LEN=1258 UID=1000 GID=1000 ")
TCP_NEW = ("HFW-OUT-NEW: IN= OUT=wg0-mullvad SRC=10.2.0.2 DST={dst} LEN=60 PROTO=TCP "
           "SPT={spt} DPT=443 SYN UID=1000 GID=1000 ")


class TestProgramNames(Base):
    """2026-11-03: every program named (no unexplained ?)."""

    def rows(self, snap, pid="programs"):
        return {r["id"]: r for r in self.panel(snap, pid)["rows"]}

    def detail(self, row):
        return {it["k"]: (it["v"], it.get("sev", "ok")) for it in row["detail"]}

    def lines(self, *msgs):
        self.host.set("journalctl", ok("".join(jline(f"n{i}", 1792410740 + i, m)
                                                for i, m in enumerate(msgs))))

    def shell(self, *comms):
        """Fake GNOME Shell cgroup with these processes (pids 11, 12, ...)."""
        d = self.cg + SHELL
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "cgroup.procs"), "w") as f:
            f.write("".join(f"{11 + i}\n" for i in range(len(comms))))
        for i, comm in enumerate(comms):
            os.makedirs(os.path.join(self.proc, str(11 + i)), exist_ok=True)
            with open(os.path.join(self.proc, str(11 + i), "comm"), "w") as f:
                f.write(comm + "\n")

    def shell_socket(self):
        self.host.set("ss", ok("tcp 0 0 10.2.0.2:40000 203.0.113.60:443 uid:1000 ino:777 "
                               f"sk:1 cgroup:{SHELL} <->\n"))

    def test_udp_by_local_port(self):
        app = ("/user.slice/user-1000.slice/user@1000.service/app.slice/"
               "app-brave\\x2dbrowser@43041.service")
        self.host.set("ss closed", ok(f"udp 0 0 0.0.0.0:50000 0.0.0.0:* uid:1000 ino:5 "
                                      f"cgroup:{app}\n"
                                      f"udp 0 0 0.0.0.0:50001 0.0.0.0:* cgroup:{app}\n"))
        self.lines(UDP_NEW.format(spt=50000), UDP_NEW.format(spt=50001),
                   UDP_NEW.format(spt=50002))
        snap = self.collect()
        self.assertEqual(self.argvs().count("ss -tuaneH --cgroup state closed"), 1)   # once
        rows = self.rows(snap)
        self.assertEqual(rows["brave-browser"]["cells"][3], "2")        # 2 allowed lines
        self.assertEqual(rows["brave-browser"]["progs"], ["brave-browser"])
        self.assertIn("? uid 1000", rows)                               # port 50002: none
        audit = [r["cells"][6] for r in self.panel(snap, "audit")["rows"]]
        self.assertEqual(audit, ["brave-browser"])          # one flow (ports vary), named

    def test_no_netid_lines_skipped(self):
        """`ss -uanH state closed` on my host 2026-11-03: one protocol = no Netid column.
        Such lines are not parsed (why the call asks -t too)."""
        self.assertEqual(conns.parse("0      0            0.0.0.0:41096 0.0.0.0:*\n"), [])

    def test_udp_lookup_only_when_needed(self):
        self.lines(TCP_NEW.format(dst="198.51.100.20", spt=33146))     # established match
        self.collect()
        self.assertNotIn("ss -tuaneH --cgroup state closed", self.argvs())

    def test_guess_from_peer(self):
        self.lines(TCP_NEW.format(dst="203.0.113.10", spt=40001))      # closed: no socket
        snap = self.collect()
        rows = self.rows(snap)
        g = rows["brave?"]
        self.assertEqual(g["cells"][:4], ["brave?", "1000", "0", "1"])
        self.assertNotIn("progs", g)                                    # never on a card
        self.assertIn("guess", self.detail(g)["note"][0])
        peer = self.rows(snap, "peers")["203.0.113.10"]
        self.assertEqual(peer["cells"][4], "brave")                     # guess not fed back
        flow = self.panel(snap, "audit")["rows"][0]
        self.assertEqual((flow["cells"][6], "progs" in flow), ("brave?", False))

    def test_no_guess_when_two_programs(self):
        self.host.set("ss", ok(fix("ss.txt") + "tcp 0 0 10.2.0.2:1 203.0.113.10:443 "
                               'users:(("curl",pid=9,fd=3))\n'))
        self.lines(TCP_NEW.format(dst="203.0.113.10", spt=40001))
        self.assertIn("? uid 1000", self.rows(self.collect()))

    def procs(self, *items):
        """Fake /proc: (pid, uid, cgroup) per process."""
        for pid, uid, cgroup in items:
            d = os.path.join(self.proc, str(pid))
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "status"), "w") as f:
                f.write(f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
            with open(os.path.join(d, "cgroup"), "w") as f:
                f.write(f"0::{cgroup}\n")

    def test_guess_from_uid(self):
        """2026-11-09: a service user runs one program -> its flows get that name (guess)."""
        self.pw = {994: "chrony"}
        self.procs((700, 994, "/system.slice/chronyd.service"))
        ntp = ("HFW-OUT-LEAK: IN= OUT=wlo1 SRC=192.168.8.102 DST=203.0.113.20 LEN=76 "
               "PROTO=UDP SPT=123 DPT=123 LEN=56 UID=994 GID=994 ")
        self.lines(ntp)
        snap = self.collect()
        g = self.rows(snap)["chronyd?"]
        self.assertEqual(g["cells"][:2], ["chronyd?", "994"])
        self.assertNotIn("progs", g)                                    # never on a card
        self.assertIn("only program running as uid 994 (chrony)", self.detail(g)["note"][0])
        flow = self.panel(snap, "audit")["rows"][0]
        self.assertEqual(flow["cells"][6], "chronyd?")
        d = {it["k"]: it["v"] for it in flow["detail"]}
        self.assertIn("uid 994 (chrony)", d["guess"])
        self.assertNotIn("why ?", d)
        peer = self.rows(snap, "peers")["203.0.113.20"]
        self.assertEqual(peer["cells"][4], "?")                         # guess not fed back

    def test_guess_from_uid_icmp(self):
        """Not tcp / udp: no socket match, the uid guess still works (ping as a service)."""
        self.procs((710, 995, "/system.slice/mullvad-probe.service"))
        self.lines("HFW-OUT-NEW: IN= OUT=wg0-mullvad SRC=10.2.0.2 DST=203.0.113.9 LEN=84 "
                   "PROTO=ICMP TYPE=8 CODE=0 ID=1 SEQ=1 UID=995 GID=995 ")
        self.assertIn("mullvad-probe?", self.rows(self.collect()))

    def test_no_uid_guess(self):
        """Two programs, or a process with no unit (session): no guess; the user name."""
        self.pw = {994: "chrony", 1001: "admin"}
        self.procs((700, 994, "/system.slice/chronyd.service"),
                   (701, 994, "/system.slice/other.service"),
                   (800, 1001, "/user.slice/user-1001.slice/session-c1.scope"))
        self.lines("HFW-OUT-NEW: IN= OUT=wg0-mullvad SRC=10.2.0.2 DST=203.0.113.9 LEN=60 "
                   "PROTO=TCP SPT=40000 DPT=443 SYN UID=994 GID=994 ",
                   "HFW-OUT-NEW: IN= OUT=wg0-mullvad SRC=10.2.0.2 DST=203.0.113.8 LEN=60 "
                   "PROTO=TCP SPT=40001 DPT=443 SYN UID=1001 GID=1001 ")
        snap = self.collect()
        rows = self.rows(snap)
        r = rows["? uid 994"]
        self.assertEqual((r["cells"][0], r["filter"]), ("? chrony", "? 994"))
        self.assertIn("uid 994 (chrony): 2 programs run as it now: chronyd, other",
                      self.detail(r)["note"][0])
        self.assertIn("(session)", self.detail(rows["? uid 1001"])["note"][0])
        audit = {r["cells"][5]: r for r in self.panel(snap, "audit")["rows"]}
        self.assertEqual(audit["994"]["cells"][6], "? chrony")
        d = {it["k"]: it["v"] for it in audit["994"]["detail"]}
        self.assertEqual(d["uid"], "uid 994 (chrony): 2 programs run as it now: chronyd, other")

    def test_uid_scan_once_per_tick(self):
        self.procs((700, 994, "/system.slice/chronyd.service"))
        self.lines(*(TCP_NEW.format(dst=f"203.0.113.{i}", spt=41000 + i).replace(
            "UID=1000 GID=1000", "UID=994 GID=994") for i in range(3)))
        calls = []
        real = fw.procmod.by_uid
        fw.procmod.by_uid = lambda root: calls.append(root) or real(root)
        try:
            self.assertIn("chronyd?", self.rows(self.collect()))
        finally:
            fw.procmod.by_uid = real
        self.assertEqual(calls, [self.proc])

    def test_shared_cgroup_from_helper(self):
        self.shell("gnome-shell", "brave", "brave")
        self.shell_socket()
        self.users.owners = {777: userd.Owner(12, "brave", "null", SHELL)}
        self.users.users = ["null"]
        rows = self.rows(self.collect())
        r = rows["org.gnome.Shell/brave"]
        self.assertEqual((r["sev"], r["progs"], r["filter"]),
                         ("warn", ["org.gnome.Shell"], "org.gnome.Shell/brave"))
        d = self.detail(r)
        self.assertEqual(d["shared cgroup"][1], "warn")
        self.assertIn("appunit", d["fix"][0])
        self.host.set("ss", ok(""))                                 # closed: history only
        self.tick()
        r = self.rows(self.collect())["org.gnome.Shell/brave"]
        self.assertEqual((r["sev"], self.detail(r)["shared cgroup"][1]), ("ok", "ok"))
        self.lines(TCP_NEW.format(dst="203.0.113.60", spt=40009))   # its peer again
        self.tick()
        self.assertIn("? uid 1000", self.rows(self.collect()))      # no shared guess

    def test_shared_cgroup_without_helper(self):
        self.shell("gnome-shell", "brave", "brave", "cat")
        self.shell_socket()
        r = self.rows(self.collect())["org.gnome.Shell/?"]
        d = self.detail(r)
        self.assertIn("brave x2, cat", d["shared cgroup"][0])
        self.assertIn("sectop-user@<user>.service not running", d["user helper"][0])
        self.assertEqual(r["progs"], ["org.gnome.Shell"])

    def test_shared_cgroup_own_only(self):
        self.shell("gnome-shell", "Xwayland", "glycin-image-rs")
        self.shell_socket()
        r = self.rows(self.collect())["org.gnome.Shell"]
        self.assertEqual(r["sev"], "ok")
        self.users.owners = {777: userd.Owner(11, "gnome-shell", "null", SHELL)}
        self.shell("gnome-shell", "brave")
        self.tick()
        self.assertIn("org.gnome.Shell", self.rows(self.collect()))     # its own socket

    def test_shared_owner_other_cgroup_ignored(self):
        self.shell("gnome-shell", "brave")
        self.shell_socket()
        self.users.owners = {777: userd.Owner(12, "brave", "null", SHELL + "x")}
        self.assertIn("org.gnome.Shell/?", self.rows(self.collect()))

    def test_reconnect_waits_for_fresh_slow_samples(self):
        """2026-11-03 host: false fwmark crit after a reconnect (stale 'down' sample)."""
        stamps = {"fast": self.wall, "slow": self.wall}
        slow = ("endpoints", "fwmark", "wg_fwmark")
        self.host.stamp = lambda argv: stamps["slow" if argv[-1] in slow else "fast"]
        self.collect()
        self.tick()
        for key in ("wg latest-handshakes", "wg transfer"):
            self.host.set(key, NO_DEV)
        stamps["fast"] = self.wall
        self.collect()                                              # down
        self.tick()
        self.host.set("wg latest-handshakes", ok(fix("wg-handshakes.txt")))
        self.host.set("wg transfer", ok(fix("wg-transfer.txt")))
        self.host.set("wg fwmark", NO_DEV)                          # the old 'down' sample
        self.host.set("wg endpoints", NO_DEV)
        stamps["fast"] = self.wall                                  # up, seen now
        s = self.collect()
        self.assertNotEqual(s["status"], "crit")
        v = self.items(s, "vpn")
        self.assertEqual(v["fwmark"], ("waiting for a net unit sample newer than the tunnel "
                                       "change", "ok"))
        self.assertNotIn("endpoint", v)
        self.tick()
        self.argvs()
        self.host.set("wg fwmark", ok(fix("wg-fwmark.txt")))
        self.host.set("wg endpoints", ok(fix("wg-endpoints.txt")))
        stamps["slow"] = self.wall                                  # fresh samples
        s = self.collect()
        self.assertIn("wg show wg0-mullvad endpoints", self.argvs())  # ran again at once
        v = self.items(s, "vpn")
        self.assertEqual(v["fwmark"], ("0x6d6f6c65 (in set)", "ok"))
        self.assertIn("endpoint", v)
        self.tick()
        self.collect()
        self.assertNotIn("wg show wg0-mullvad endpoints", self.argvs())  # back to SLOW

    def test_fwmark_live_unreadable_no_claim(self):
        self.host.set("wg fwmark", NO_DEV)
        s = self.collect()
        self.assertEqual(s["status"], "ok")
        self.assertEqual(self.items(s, "vpn")["fwmark"],
                         ("live: Unable to access interface: No such device", "info"))


class TestNetSource(Base):
    """nft / wg come from the net unit (core/netd.py), the rest is run here."""

    def setUp(self):
        super().setUp()
        self.ran, self.net = [], []
        host = self.host

        def run(argv, timeout):
            self.ran.append(os.path.basename(argv[0]))
            return host(argv, timeout)

        def net(argv, timeout):
            self.net.append(tuple(argv))
            return host(argv, timeout)

        self.st.run, self.st.net = run, net

    def test_routing(self):
        self.collect()
        self.assertTrue(self.net)
        self.assertFalse({"nft", "wg"} & set(self.ran))
        self.assertEqual(set(self.ran), {"ss"})
        self.assertNotIn("journalctl", self.ran)          # live lines: core's follower

    def test_net_unit_has_every_command(self):
        """Each nft / wg argv the module asks for is one the net unit runs."""
        self.st.slow_at = None
        self.collect()
        known = {argv for argv, _kind in netd.commands(self.st.tunnel).values()}
        self.assertEqual(set(self.net) - known, set())
        self.assertEqual({os.path.basename(a[0]) + " " + a[-1] for a in self.net},
                         {"nft hostfw", "wg latest-handshakes", "wg transfer",
                          "wg endpoints", "wg fwmark", "nft wg_fwmark", "nft mullvad",
                          "nft vpn_api4"})

    def test_net_error_shown(self):
        self.host.set("nft list table", fail("/run/sectop-net/table.json missing: "
                                             "is sectop-net.service running?"))
        snap = self.collect()
        self.assertIn("is sectop-net.service running?", self.items(snap, "hostfw")["table"][0])


class TestInit(unittest.TestCase):
    def test_options(self):
        bad = ({"x": 1}, {"tunnel": "a b"}, {"tunnel": "x" * 16}, {"tunnel": 1},
               {"ks_ifaces": ["wlo1"]},                     # removed option: unknown now
               {"hold": -1}, {"hold": True}, {"hold": 4000})
        for cfg in bad:
            with self.assertRaises(ValueError, msg=repr(cfg)):
                fw.init(cfg)

    def test_init_only_boot_scan(self):
        host = Host()
        real = fw.State
        with mock.patch.object(fw, "State", lambda **kw: real(run=host, net=host, **kw)):
            st = fw.init({})
        self.assertEqual([c[-1] for c in host.calls], ["+1", "--grep=^HFW-OUT-LEAK:"])
        self.assertFalse(hasattr(st, "cursor"))           # live lines: core's follower
        self.assertIsNone(st.hold)                        # no option: hold by severity
        with mock.patch.object(fw, "State", lambda **kw: real(run=host, net=host, **kw)):
            self.assertEqual(fw.init({"hold": 90}).hold, 90.0)


if __name__ == "__main__":
    unittest.main()
