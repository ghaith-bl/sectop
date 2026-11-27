import errno
import json
import os
import struct
import tempfile
import unittest

import modules.lan as lanmod
from core import alerts, eve, idsd, lan, statefile
from core.module import Context, check_module, validate
from core.screens import SCREENS, find

CTX = Context((), False, "")
T0 = 1_800_000_000.0
GW, ME, OTHER = "192.168.8.1", "192.168.8.23", "192.168.8.57"
MAC_A, MAC_B = "02:00:00:00:00:01", "02:00:00:00:00:02"
BRIDGE_HOST = "192.168.122.1"

ROUTE = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wg0-mullvad\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0
wlo1\t00000000\t0108A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
enp44s0\t00000000\t0101A8C0\t0003\t0\t0\t900\t00000000\t0\t0\t0
wlo1\t0008A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0
wlo1\t0000A8C0\t00000000\t0001\t0\t0\t600\t0000FFFF\t0\t0\t0
virbr0\t007AA8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
"""
if struct.pack("=I", 1) != struct.pack("<I", 1):      # the file is in host byte order
    ROUTE = "\n".join(
        "\t".join(f"{int.from_bytes(bytes.fromhex(x), 'little'):08X}" if i in (1, 2, 7)
                  and len(x) == 8 else x for i, x in enumerate(line.split("\t")))
        if n else line for n, line in enumerate(ROUTE.splitlines())) + "\n"

ARP = f"""IP address       HW type     Flags       HW address            Mask     Device
{GW}      0x1         0x2         {MAC_A.upper()}     *        wlo1
192.168.8.99     0x1         0x0         00:00:00:00:00:00     *        wlo1
192.168.122.50   0x1         0x2         52:54:00:12:34:56     *        virbr0
"""

FIB = f"""Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
           |-- 127.0.0.0
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
     +-- 192.168.8.0/24 2 0 2
           |-- 192.168.8.0
              /24 link UNICAST
           |-- {ME}
              /32 host LOCAL
           |-- 192.168.8.255
              /32 link BROADCAST
     |-- {BRIDGE_HOST}
        /32 host LOCAL
"""


def seen(up=True, ssid=b"home", mac=MAC_A, arp=None, local=None, kind=None, notes=()):
    s = lan.Seen()
    s.up = lan.Uplink("wlo1", GW, "192.168.8.0/24") if up else None
    s.ssid = ssid if up else None
    s.kind = kind or ("" if not up else ("wifi" if ssid else "cable"))
    s.gw_mac = mac if up else None
    s.arp = arp if arp is not None else ([(GW, mac, "wlo1")] if up and mac else [])
    s.local = local if local is not None else {ME, BRIDGE_HOST, "127.0.0.1"}
    s.notes = list(notes)
    return s


class Rig:
    """The module with temp files and a fake clock / look."""

    def __init__(self, tc, dhcp_ok=()):
        self.d = tempfile.TemporaryDirectory()
        tc.addCleanup(self.d.cleanup)
        os.chmod(self.d.name, 0o755)
        self.key = os.path.join(self.d.name, "lan.key")
        self.known = os.path.join(self.d.name, "lan-known.txt")
        self.summary = os.path.join(self.d.name, "summary.json")
        self.now = T0
        self.view = seen()
        self.st = lanmod.State(key_path=self.key, known_path=self.known, summary=self.summary,
                               etc_owner=os.getuid(), summary_owner=os.getuid(),
                               look=lambda: self.view, wall=lambda: self.now, dhcp_ok=dhcp_ok,
                               clock=lambda ts: f"C{ts:.0f}", stamp=lambda ts: f"T{ts:.0f}")

    def collect(self, dt=5.0):
        self.now += dt
        return validate(lanmod.collect(self.st, CTX))     # as core gets it

    def write_key(self, key=b"k" * 32):
        with open(self.key, "w") as f:
            f.write(key.hex() + "\n")
        os.chmod(self.key, 0o640)
        return key

    def accept(self, key, ssid=b"home", mac=MAC_A, kind="wifi", date="2026-11-27"):
        nid = lan.net_id(key, kind, ssid, "192.168.8.0/24", GW)
        known = lan.load_known(self.known, os.getuid())
        known[(nid, lan.mac_id(key, mac))] = date
        with open(self.known, "w") as f:
            f.write(lan.render_known(known))
        os.chmod(self.known, 0o640)
        return nid

    def dhcp(self, *groups):
        statefile.write(self.summary, {"v": 1, "ts": self.now, "dhcp": list(groups)}, 0o640)

    @staticmethod
    def group(iface="wlo1", server=GW, last=T0, n24=1, nh=1, types=("ack",)):
        return {"iface": iface, "server": server, "types": list(types), "first": last - 10,
                "last": last, "n24": n24, "nh": nh}


def items(snap) -> dict:
    p = next(p for p in snap["panels"] if p["id"] == "lan")
    return {it["k"]: (it["v"], it.get("sev", "ok")) for it in p["items"]}


def notes(snap) -> list:
    p = next(p for p in snap["panels"] if p["id"] == "lan")
    return [it["v"] for it in p["items"] if it["k"] == "note"]


def keys(snap) -> list:
    return [c["key"] for c in snap["checks"]]


class ParseTest(unittest.TestCase):
    def test_uplink_lowest_metric_not_a_tunnel_longest_subnet(self):
        up = lan.uplink(lan.parse_route(ROUTE))
        self.assertEqual(up, lan.Uplink("wlo1", GW, "192.168.8.0/24"))

    def test_no_default_route(self):
        text = "\n".join(line for line in ROUTE.splitlines() if "\t00000000\t0" not in line
                         or "wg0" in line)
        self.assertIsNone(lan.uplink(lan.parse_route(text)))
        self.assertIsNone(lan.uplink(lan.parse_route("Iface\n")))

    def test_arp_complete_only_lower_case(self):
        self.assertEqual(lan.parse_arp(ARP), [(GW, MAC_A, "wlo1"),
                                              ("192.168.122.50", "52:54:00:12:34:56", "virbr0")])
        self.assertEqual(lan.parse_arp("head\nnot an entry\n1.2.3 0x1 0x2 x * wlo1\n"), [])

    def test_fib_local_addresses(self):
        self.assertEqual(lan.parse_fib_local(FIB), {"127.0.0.1", ME, BRIDGE_HOST})

    def test_look_from_files(self):
        with tempfile.TemporaryDirectory() as d:
            paths = []
            for name, text in (("route", ROUTE), ("arp", ARP), ("fib", FIB)):
                p = os.path.join(d, name)
                with open(p, "w") as f:
                    f.write(text)
                paths.append(p)
            s = lan.look(*paths, ssid_of=lambda dev: b"home" if dev == "wlo1" else None)
            self.assertEqual((s.up.dev, s.kind, s.ssid, s.gw_mac, s.notes),
                             ("wlo1", "wifi", b"home", MAC_A, []))
            s = lan.look(*paths, ssid_of=lambda dev: None)
            self.assertEqual(s.kind, "cable")

            def broken(dev):
                raise OSError(errno.EACCES, "Permission denied")
            s = lan.look(*paths, ssid_of=broken)
            self.assertEqual(s.kind, "net")
            self.assertIn("Wi-Fi name not read", s.notes[0])
            s = lan.look(os.path.join(d, "none"), *paths[1:], ssid_of=broken)
            self.assertIsNone(s.up)
            self.assertIn("No such file", s.notes[0])

    def test_ids(self):
        k = b"k" * 32
        base = lan.net_id(k, "wifi", b"home", "192.168.8.0/24", GW)
        self.assertRegex(base, r"^[0-9a-f]{64}$")
        for other in (lan.net_id(k, "wifi", b"cafe", "192.168.8.0/24", GW),
                      lan.net_id(k, "cable", None, "192.168.8.0/24", GW),
                      lan.net_id(k, "wifi", b"home", "192.168.0.0/16", GW),
                      lan.net_id(k, "wifi", b"home", "192.168.8.0/24", "192.168.8.2"),
                      lan.net_id(b"x" * 32, "wifi", b"home", "192.168.8.0/24", GW)):
            self.assertNotEqual(base, other)
        self.assertEqual(lan.mac_id(k, MAC_A.upper()), lan.mac_id(k, MAC_A))
        self.assertNotEqual(lan.mac_id(k, MAC_A), lan.mac_id(k, MAC_B))

    def test_key_and_known_text(self):
        self.assertEqual(lan.parse_key(b"ab" * 32 + b"\n"), b"\xab" * 32)
        for bad in (b"", b"ab" * 31, b"zz" * 32):
            with self.assertRaises(ValueError):
                lan.parse_key(bad)
        known = {("a" * 64, "b" * 64): "2026-11-27", ("c" * 64, "d" * 64): ""}
        text = lan.render_known(known)
        self.assertEqual(lan.parse_known(text + "junk line\nab cd\n"), known)
        self.assertNotIn(":", text.replace("# ", "").split("\n", 3)[3])


class FakeSock:
    """Answers like the kernel: queued datagrams, the request bytes kept."""

    def __init__(self, answers):
        self.answers, self.sent = list(answers), []

    def send(self, msg):
        self.sent.append(msg)

    def recv(self, n):
        return self.answers.pop(0) if self.answers else b""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def kmsg(mtype, seq, payload, flags=0):
    return lan.HDR.pack(lan.HDR.size + len(payload), mtype, flags, seq, 0) + payload


def ack(seq, err=0):
    return kmsg(lan.NLMSG_ERROR, seq, struct.pack("=i", err) + b"\0" * 16)


def family(fid=30, seq=1):
    return kmsg(lan.GENL_ID_CTRL, seq, lan.GENL.pack(1, 2, 0)
                + lan.nl_attr(lan.CTRL_ATTR_FAMILY_NAME, b"nl80211\0")
                + lan.nl_attr(lan.CTRL_ATTR_FAMILY_ID, struct.pack("=H", fid)))


def iface(name, ssid=None, fid=30, seq=2):
    a = lan.nl_attr(3, struct.pack("=I", 4)) + lan.nl_attr(lan.NL80211_ATTR_IFNAME, name + b"\0")
    if ssid is not None:
        a += lan.nl_attr(lan.NL80211_ATTR_SSID, ssid)
    return kmsg(fid, seq, lan.GENL.pack(7, 1, 0) + a, lan.NLM_F_MULTI)


class NetlinkTest(unittest.TestCase):
    def test_ssid_of_the_interface(self):
        sock = FakeSock([family() + ack(1),
                         iface(b"p2p-dev-wlo1") + iface(b"wlo1", b"home net"),
                         kmsg(lan.NLMSG_DONE, 2, struct.pack("=i", 0))])
        self.assertEqual(lan.wifi_ssid("wlo1", connect=lambda: sock), b"home net")
        hdr = lan.HDR.unpack_from(sock.sent[1])
        self.assertEqual((hdr[1], hdr[2], sock.sent[1][16]),
                         (30, lan.NLM_F_REQUEST | lan.NLM_F_DUMP, lan.NL80211_CMD_GET_INTERFACE))
        self.assertIn(b"nl80211\0", sock.sent[0])

    def test_not_connected_not_wifi_no_driver(self):
        done = kmsg(lan.NLMSG_DONE, 2, struct.pack("=i", 0))
        sock = FakeSock([family() + ack(1), iface(b"wlo1") + done])
        self.assertIsNone(lan.wifi_ssid("wlo1", connect=lambda: sock))
        sock = FakeSock([family() + ack(1), iface(b"wlo1", b"x") + done])
        self.assertIsNone(lan.wifi_ssid("enp44s0", connect=lambda: sock))
        sock = FakeSock([ack(1, -errno.ENOENT)])
        self.assertIsNone(lan.wifi_ssid("wlo1", connect=lambda: sock))

    def test_errors(self):
        sock = FakeSock([ack(1, -errno.EPERM)])
        with self.assertRaises(OSError) as c:
            lan.wifi_ssid("wlo1", connect=lambda: sock)
        self.assertEqual(c.exception.errno, errno.EPERM)
        with self.assertRaises(OSError):
            lan.wifi_ssid("wlo1", connect=lambda: FakeSock([]))
        with self.assertRaises(ValueError):
            lan.nl_messages(lan.HDR.pack(400, 2, 0, 1, 0) + b"short")
        self.assertEqual(lan.nl_attrs(lan.nl_attr(4, b"ab") + b"\x40\x00"), {4: b"ab"})

    def test_other_seq_ignored(self):
        sock = FakeSock([kmsg(lan.GENL_ID_CTRL, 9, b"xxxx") + family() + ack(1),
                         iface(b"wlo1", b"n") + kmsg(lan.NLMSG_DONE, 2, b"\0" * 4)])
        self.assertEqual(lan.wifi_ssid("wlo1", connect=lambda: sock), b"n")

    def test_real_kernel_family(self):
        try:
            s = lan.nl_socket()
        except OSError as e:
            self.skipTest(f"no generic netlink here: {e}")
        with s:
            self.assertEqual(lan.genl_family(s, b"nlctrl"), lan.GENL_ID_CTRL)
            self.assertIsNone(lan.genl_family(s, b"no-such-family", seq=3))


class ModuleTest(unittest.TestCase):
    def test_interface_and_screen(self):
        check_module(lanmod)
        self.assertIn("lan", SCREENS[find("firewall")].modules)

    def test_init_options(self):
        self.assertEqual(lanmod.init({}).dhcp_ok, set())
        self.assertEqual(lanmod.init({"dhcp_ok": ["192.168.8.2"]}).dhcp_ok, {"192.168.8.2"})
        for bad in ({"dhcp_ok": "192.168.8.2"}, {"dhcp_ok": ["x"]}, {"dhcp_ok": ["::1"]},
                    {"other": 1}):
            with self.assertRaises(ValueError):
                lanmod.init(bad)


class RouterTest(unittest.TestCase):
    def test_new_network_first_mac_info_then_change_red(self):
        r = Rig(self)
        snap = r.collect()
        it = items(snap)
        self.assertEqual(it["router MAC"], (f"not accepted yet; same since C{T0 + 5:.0f}", "info"))
        self.assertEqual(it["accept"][1], "info")
        self.assertEqual((snap["status"], snap["checks"]), ("info", []))
        self.assertRegex(it["network"][0], r"^Wi-Fi, id [0-9a-f]{8} \(no name shown\)$")
        r.view = seen(mac=MAC_B)
        snap = r.collect()
        id8 = it["network"][0].split()[2]
        self.assertEqual(keys(snap), [f"gw_changed:{id8}"])
        c = snap["checks"][0]
        self.assertEqual((c["sev"], c["hold"]), ("crit", 3600.0))
        self.assertIn("seen first", c["detail"])
        self.assertEqual(items(snap)["MACs seen"], ("2 this session, 1 not trusted", "crit"))
        self.assertEqual(snap["status"], "crit")
        r.view = seen(mac=MAC_A)                       # back: no new report, the row stays red
        snap = r.collect()
        self.assertEqual(keys(snap), [])
        self.assertEqual(items(snap)["MACs seen"][1], "crit")

    def test_alert_opens_and_is_held(self):
        r = Rig(self)
        r.collect()
        r.view = seen(mac=MAC_B)
        snap = r.collect()
        st = alerts.step(alerts.empty(), "lan", snap["checks"], r.now)
        [a] = alerts.active(st, r.now)
        self.assertEqual((a["sev"], a["state"]), ("crit", "open"))
        r.view = seen(mac=MAC_A)
        st = alerts.step(st, "lan", r.collect()["checks"], r.now)
        [a] = alerts.active(st, r.now)
        self.assertEqual(a["state"], "held")

    def test_accepted_network(self):
        r = Rig(self)
        key = r.write_key()
        r.accept(key)
        r.dhcp(Rig.group())
        snap = r.collect()
        self.assertEqual(items(snap)["router MAC"], ("accepted 2026-11-27", "ok"))
        self.assertNotIn("accept", items(snap))
        self.assertEqual((snap["status"], snap["checks"]), ("ok", []))
        r.view = seen(mac=MAC_B)
        snap = r.collect()
        self.assertEqual([c["sev"] for c in snap["checks"]], ["crit"])
        self.assertIn("not an accepted one", snap["checks"][0]["detail"])
        self.assertIn("--lan-accept", snap["checks"][0]["detail"])

    def test_new_router_accepted_during_the_run(self):
        r = Rig(self)
        key = r.write_key()
        r.accept(key)
        r.collect()
        r.view = seen(mac=MAC_B)
        self.assertEqual(len(r.collect()["checks"]), 1)
        r.accept(key, mac=MAC_B, date="2026-11-28")    # a replaced router of my own
        snap = r.collect()
        self.assertEqual((items(snap)["router MAC"], items(snap)["MACs seen"]),
                         (("accepted 2026-11-28", "ok"), ("2 this session, 0 not trusted", "ok")))
        self.assertEqual(snap["checks"], [])

    def test_two_routers_accepted_for_one_network(self):
        r = Rig(self)
        key = r.write_key()
        r.accept(key)
        r.accept(key, mac=MAC_B, date="2026-11-28")
        r.view = seen(mac=MAC_B)
        snap = r.collect()
        self.assertEqual(items(snap)["router MAC"], ("accepted 2026-11-28", "ok"))
        self.assertEqual(snap["checks"], [])

    def test_other_wifi_same_router_address_is_another_network(self):
        r = Rig(self)
        key = r.write_key()
        r.accept(key)
        r.view = seen(ssid=b"cafe", mac=MAC_B)         # 192.168.8.1 too, another router
        snap = r.collect()
        self.assertEqual(items(snap)["router MAC"][1], "info")
        self.assertEqual(snap["checks"], [])

    def test_accept_seen_by_a_running_collector(self):
        r = Rig(self)
        r.collect()
        key = r.write_key()
        r.accept(key)
        snap = r.collect()
        self.assertEqual(items(snap)["router MAC"][1], "ok")

    def test_bad_key_file_is_a_note(self):
        r = Rig(self)
        r.write_key()
        os.chmod(r.key, 0o666)
        snap = r.collect()
        self.assertEqual(snap["status"], "warn")
        self.assertIn("group/other writable", notes(snap)[0])

    def test_router_mac_on_another_address(self):
        r = Rig(self)
        r.view = seen(arp=[(GW, MAC_A, "wlo1"), (OTHER, MAC_A, "wlo1"), (OTHER, MAC_A, "virbr0"),
                           ("192.168.8.60", MAC_B, "wlo1")])
        snap = r.collect()
        self.assertEqual(keys(snap), [f"mac_dup:{OTHER}"])
        self.assertEqual(items(snap)["same MAC"], (f"also {OTHER}", "crit"))

    def test_no_network_no_mac_yet(self):
        r = Rig(self)
        r.view = seen(up=False)
        snap = r.collect()
        self.assertEqual(items(snap)["network"], ("none: no default route", "info"))
        self.assertEqual(snap["checks"], [])
        r.view = seen(mac=None)
        snap = r.collect()
        self.assertEqual(items(snap)["router MAC"], ("not in the ARP table yet", "info"))
        self.assertEqual(snap["checks"], [])

    def test_no_mac_or_wifi_name_in_the_snapshot(self):
        r = Rig(self)
        r.collect()
        r.view = seen(mac=MAC_B, ssid=b"home")
        text = json.dumps(r.collect())
        for secret in (MAC_A, MAC_B, MAC_A.upper(), "home"):
            self.assertNotIn(secret, text)


class DhcpTest(unittest.TestCase):
    def rows(self, snap):
        p = next(p for p in snap["panels"] if p["id"] == "dhcp")
        return [(row["cells"][3], row["cells"][4], row["cells"][5], row["sev"])
                for row in p["rows"]]

    def test_router_ok_other_server_red_once_then_count(self):
        r = Rig(self)
        r.collect()                                    # since = T0 + 5
        r.dhcp(Rig.group(last=T0 + 6), Rig.group(server=OTHER, last=T0 + 7, n24=2))
        snap = r.collect()
        self.assertEqual(self.rows(snap), [("wlo1", OTHER, "NOT the router: rogue DHCP?", "crit"),
                                           ("wlo1", GW, "the router", "ok")])
        [c] = snap["checks"]
        self.assertEqual((c["key"], c["at"], c["n"], c["hold"]),
                         (f"dhcp_rogue:wlo1:{OTHER}", T0 + 7, 2, 3600.0))
        self.assertEqual(items(snap)["DHCP 24 h"], ("2 server(s), 1 rogue", "crit"))
        self.assertEqual(r.collect()["checks"], [])    # same summary: nothing new
        r.dhcp(Rig.group(server=OTHER, last=T0 + 20, n24=5))
        [c] = r.collect()["checks"]
        self.assertEqual((c["n"], c["at"]), (3, T0 + 20))

    def test_answer_before_this_network_not_checked(self):
        r = Rig(self)
        r.now = T0 + 1000
        r.dhcp(Rig.group(server=OTHER, last=T0 + 900),    # 105 s before: older network
               Rig.group(server="192.168.8.2", last=T0 + 950))   # 55 s before: counts
        snap = r.collect()
        self.assertEqual([x[2:] for x in self.rows(snap)],
                         [("NOT the router: rogue DHCP?", "crit"),
                          ("before this network (not checked)", "info")])

    def test_bridges_other_interfaces_config(self):
        r = Rig(self, dhcp_ok={"192.168.8.2"})
        r.dhcp(Rig.group(iface="virbr0", server=BRIDGE_HOST, last=T0),
               Rig.group(iface="virbr-browse", server="192.168.123.15", last=T0 - 1),
               Rig.group(server="192.168.8.2", last=T0 - 2),
               Rig.group(iface="enp44s0", server="192.168.1.1", last=T0 - 3))
        snap = r.collect()
        self.assertEqual([x[2:] for x in self.rows(snap)],
                         [("this host", "ok"),
                          ("NOT this host: rogue DHCP on a VM bridge?", "crit"),
                          ("fine (config dhcp_ok)", "ok"),
                          ("another network (not checked)", "info")])
        self.assertEqual(keys(snap), ["dhcp_rogue:virbr-browse:192.168.123.15"])
        self.assertIn("not this host", snap["checks"][0]["title"])

    def test_no_summary_bad_summary(self):
        r = Rig(self)
        snap = r.collect()
        self.assertEqual(items(snap)["DHCP 24 h"], ("not watched (no ids summary)", "info"))
        statefile.write(r.summary, {"v": 1, "dhcp": [{"iface": "wlo1"}]}, 0o640)
        snap = r.collect()
        self.assertIn("dhcp.server", notes(snap)[0])
        statefile.write(r.summary, {"v": 1}, 0o640)        # older sectop-ids: no dhcp part
        snap = r.collect()
        self.assertEqual(items(snap)["DHCP 24 h"], ("0 server(s), 0 rogue", "ok"))


class AcceptTest(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        os.chmod(d.name, 0o755)
        self.key, self.known = os.path.join(d.name, "lan.key"), os.path.join(d.name, "known")
        self.tty = os.path.join(d.name, "tty")
        self.lines = []
        self.view = seen()

    def run_accept(self, answer="1\n", euid=0):
        with open(self.tty, "w") as f:
            f.write(answer)

        class G:
            gr_gid = os.getgid()
        return lan.accept(self.key, self.known, self.tty, look_fn=lambda: self.view,
                          wall=lambda: T0, getgr=lambda name: G, euid=lambda: euid,
                          out=lambda *a, **k: self.lines.append(" ".join(map(str, a))),
                          owner=os.getuid())

    def test_first_accept_makes_key_and_list(self):
        self.assertEqual(self.run_accept(), 0)
        key = lan.load_key(self.key, os.getuid())
        known = lan.load_known(self.known, os.getuid())
        nid = lan.net_id(key, "wifi", b"home", "192.168.8.0/24", GW)
        self.assertEqual(list(known), [(nid, lan.mac_id(key, MAC_A))])
        for p in (self.key, self.known):
            self.assertEqual(os.stat(p).st_mode & 0o777, 0o640)
        text = "\n".join(self.lines)
        self.assertIn(f"id {nid[:8]}", text)
        for secret in (MAC_A, MAC_A.upper(), "home"):
            self.assertNotIn(secret, text)
        self.lines.clear()
        self.assertEqual(self.run_accept(), 0)
        self.assertIn("already accepted (", self.lines[-1])

    def test_no_or_wrong_answers_change_nothing(self):
        for answer in ("0\n", "", "y\nyes\n2\n"):
            self.assertEqual(self.run_accept(answer), 0)
            self.assertFalse(os.path.exists(self.known), answer)
        self.assertIn("not changed", self.lines[-1])

    def test_refusals(self):
        self.assertEqual(self.run_accept(euid=1000), 2)
        self.view = seen(up=False)
        self.assertEqual(self.run_accept(), 1)
        self.view = seen(mac=None)
        self.assertEqual(self.run_accept(), 1)
        self.assertIn("no ARP entry", self.lines[-1])
        self.assertFalse(os.path.exists(self.key))


class IdsdDhcpTest(unittest.TestCase):
    @staticmethod
    def line(ts=T0, kind="reply", dtype="ack", src=GW, iface="wlo1"):
        import datetime
        tz = datetime.timezone(datetime.timedelta(hours=3))
        return json.dumps({
            "timestamp": datetime.datetime.fromtimestamp(ts, tz).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"),
            "flow_id": 1, "in_iface": iface, "event_type": "dhcp", "src_ip": src,
            "src_port": 67, "dest_ip": "255.255.255.255", "dest_port": 68, "proto": "UDP",
            "ip_v": 4, "dhcp": {"type": kind, "id": 1, "client_mac": MAC_B,
                                "assigned_ip": OTHER, "hostname": "phone", "dhcp_type": dtype}
        }).encode()

    def test_parse_reply_only_no_client_data(self):
        et, x = eve.parse_line(self.line(), T0)
        self.assertEqual((et, x.server, x.iface, x.dtype, x.ts), ("dhcp", GW, "wlo1", "ack", T0))
        self.assertEqual(sorted(x.__slots__), ["dtype", "iface", "server", "ts"])
        self.assertEqual(eve.parse_line(self.line(kind="request", src="0.0.0.0"), T0)[1], None)
        _, x = eve.parse_line(self.line(iface="bad name!", dtype="Weird"), T0)
        self.assertEqual((x.iface, x.dtype), ("", "?"))

    def test_counted_per_interface_and_server(self):
        c = idsd.Counts()
        c.add([self.line(T0), self.line(T0 + 3600), self.line(T0 + 7200, src=OTHER),
               self.line(T0, kind="request", src="0.0.0.0")], T0 + 7200)
        c.prune(T0 + 7200)
        doc = c.doc(T0 + 7200, "", 0, T0)
        self.assertEqual(doc["other"], {"dhcp": 4})
        self.assertEqual([(d["server"], d["n24"], d["types"]) for d in doc["dhcp"]],
                         [(OTHER, 1, ["ack"]), (GW, 2, ["ack"])])
        self.assertEqual(lanmod.check_dhcp(json.loads(json.dumps(doc["dhcp"])))[1]["n24"], 2)
        c.prune(T0 + 25 * 3600 + 7200)
        self.assertEqual(c.doc(T0, "", 0, T0)["dhcp"], [])

    def test_cap(self):
        c = idsd.Counts()
        c.add([self.line(T0 + i, src=f"192.168.8.{i + 2}") for i in range(idsd.MAX_DHCP + 5)],
              T0 + 100)
        c.prune(T0 + 100)
        servers = [d["server"] for d in c.doc(T0 + 100, "", 0, T0)["dhcp"]]
        self.assertEqual(len(servers), idsd.MAX_DHCP)
        self.assertEqual(servers[0], f"192.168.8.{idsd.MAX_DHCP + 6}")


if __name__ == "__main__":
    unittest.main()
