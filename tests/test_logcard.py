import json
import unittest

from core import logs
from core.run import Result
from modules.firewall import logcard

MAC = "52:54:00:00:00:01:52:54:00:00:00:02:08:00"
PING = ("HFW-FWD-VM-LAN: IN=virbr0 OUT=wlo1 MAC=" + MAC + " SRC=192.168.122.122 "
        "DST=1.1.1.1 LEN=84 TOS=0x00 PREC=0x00 TTL=63 ID={i} DF PROTO=ICMP TYPE=8 CODE=0 "
        "ID=7 SEQ={i} ")
SVC = ("HFW-FWD-VM-LAN: IN=virbr0 OUT=wlo1 MAC=" + MAC + " SRC=192.168.122.122 "
       "DST=10.96.0.1 LEN=60 TOS=0x00 PREC=0x00 TTL=63 ID={i} DF PROTO=TCP SPT={spt} DPT=443 "
       "WINDOW=64240 RES=0x00 SYN URGP=0 ")
NOISE = ("HFW-IN-NOISE: IN=wlo1 OUT= MAC=ff:ff:ff:ff:ff:ff:52:54:00:00:00:03:08:00 "
         "SRC=192.168.8.18 DST=255.255.255.255 LEN=136 TOS=0x00 PREC=0x00 TTL=64 ID=1 "
         "PROTO=UDP SPT=49152 DPT=25860 LEN=116 ")
INFO = {"pkts": "20", "verdict": "block  rejected by hostfw (enforce mode)",
        "meaning": "VM to LAN / outside the tunnel",
        "match": "VM traffic to LAN / uplink (not via the tunnel)",
        "log": "10/min burst 20: lines are samples, the counter is exact"}


def jline(cur, ts, msg):
    return json.dumps({"__CURSOR": cur, "__REALTIME_TIMESTAMP": str(int(ts * 1e6)),
                       "MESSAGE": msg}) + "\n"


def host_lines():
    """The host 2026-11-04 (addresses kept, MACs replaced): 3 pings while Mullvad was
    disconnected, then 17 SYNs of the VM's cluster to its service address."""
    out = [jline(f"c{i}", 1000 + i, PING.format(i=i)) for i in range(3)]
    out += [jline(f"c{3 + i}", 1012 + i * 0.1, SVC.format(i=i, spt=40000 + i))
            for i in range(17)]
    return "".join(out)


class Run:
    def __init__(self, res):
        self.res, self.calls = res, []

    def __call__(self, argv, timeout, limit):
        self.calls.append((argv, timeout, limit))
        return self.res


def ok(out):
    return Result(0, out, "", False, False)


def card(text, info=INFO, rule="fwd_vm_lan"):
    return logcard.card(rule, info, run=Run(ok(text)), hms=lambda ts: f"h{int(ts)}",
                        stamp=lambda ts: f"s{int(ts)}")


class TestQuery(unittest.TestCase):
    def test_argv_from_the_rule_only(self):
        self.assertEqual(logcard.argv("fwd_vm_lan"), [
            "/usr/bin/journalctl", "-b", "0", "_TRANSPORT=kernel", "-o", "json",
            "--output-fields=MESSAGE", "-q", "--no-pager", "--grep=^HFW-FWD-VM-LAN: ",
            "-n", "3000"])
        self.assertEqual(logcard.code("out_lan_allow"), "HFW-OUT-LAN-ALLOW")
        for bad in ("", "FWD", "x;rm", "a b", "a" * 41, "1x", "x.*"):
            with self.assertRaises(ValueError):
                logcard.argv(bad)

    def test_load(self):
        run = Run(ok(host_lines() + jline("n", 2000, NOISE)))
        entries, note = logcard.load("fwd_vm_lan", run)
        self.assertEqual((len(entries), note), (20, ""))       # other rules dropped
        self.assertEqual(run.calls[0][1:], (logcard.TIMEOUT, logcard.OUT_LIMIT))

    def test_load_sorts_oldest_first(self):
        lines = host_lines().splitlines(keepends=True)
        entries, _ = logcard.load("fwd_vm_lan", Run(ok("".join(reversed(lines)))))
        self.assertEqual([e.cursor for e in entries], [f"c{i}" for i in range(20)])
        row = card("".join(reversed(lines)))["flows"]["rows"][0]
        self.assertLess(float(row["cells"][1]), float(row["cells"][0]))   # first < last

    def test_load_problems(self):
        _, note = logcard.load("fwd_vm_lan", Run(Result(-9, host_lines(), "", True, False)))
        self.assertIn("read cut", note)
        _, note = logcard.load("fwd_vm_lan", Run(Result(1, "", "Failed to open journal\n",
                                                        False, False)))
        self.assertEqual(note, "journalctl failed (rc 1): Failed to open journal")
        entries, note = logcard.load("fwd_vm_lan", Run(Result(1, "", "", False, False)))
        self.assertEqual((entries, note), ([], ""))           # rc 1, nothing: no match
        _, note = logcard.load("fwd_vm_lan", Run(ok(host_lines() + "{bad\n")))
        self.assertEqual(note, "1 unreadable journal line skipped")
        many = "".join(jline(f"c{i}", 1000 + i, SVC.format(i=i, spt=40000 + i))
                       for i in range(logcard.MAX_LINES))
        _, note = logcard.load("fwd_vm_lan", Run(ok(many)))
        self.assertEqual(note, f"newest {logcard.MAX_LINES} lines only")


class TestCard(unittest.TestCase):
    def test_flows(self):
        c = card(host_lines())
        rows = c["flows"]["rows"]
        self.assertEqual([r["cells"][2:] for r in rows], [
            ["17", "tcp", "192.168.122.122", "10.96.0.1:443", "virbr0>wlo1", "vm"],
            ["3", "icmp 8 echo", "192.168.122.122", "1.1.1.1", "virbr0>wlo1", "vm"]])
        self.assertEqual({(r["sev"], r["tone"]) for r in rows}, {("warn", "yellow")})
        self.assertEqual(rows[1]["ip"], "1.1.1.1")             # w = whois of the far side
        self.assertEqual(float(rows[0]["cells"][0]), 1013.6)   # last, first: ages
        self.assertEqual(float(rows[0]["cells"][1]), 1012.0)
        ports = dict((d["k"], d["v"]) for d in rows[0]["detail"])["source ports"]
        self.assertTrue(ports.startswith("40000 40001"))
        self.assertEqual(c["lines"], 20)

    def test_head_counted_vs_logged(self):
        head = card(host_lines())["flows"]["head"]
        self.assertEqual(head[0][0], "HFW-FWD-VM-LAN   counted 20 packets (since the hostfw "
                                     "table load)   logged 20 lines (this boot)")
        self.assertEqual(head[1], ("every counted packet has its line", "note"))
        self.assertEqual(head[2], ("verdict  block  rejected by hostfw (enforce mode)", "warn"))
        more = card(host_lines(), {**INFO, "pkts": "50"})["flows"]["head"]
        self.assertEqual(more[1], ("30 packets counted, not logged: 10/min burst 20: lines are "
                                   "samples, the counter is exact", "note"))
        fewer = card(host_lines(), {**INFO, "pkts": "5"})["flows"]["head"]
        self.assertIn("table was reloaded", fewer[1][0])
        none = card("")["flows"]["head"]
        self.assertEqual(none[-1], ("no lines this boot", "note"))

    def test_packets_and_fields(self):
        c = card(host_lines())
        fid = c["flows"]["rows"][1]["id"]
        self.assertEqual(c["names"][fid], "icmp 8 echo 192.168.122.122 -> 1.1.1.1  "
                                          "virbr0>wlo1  uid vm")
        p = c["packets"][fid]
        self.assertTrue(p["detail_only"])
        self.assertEqual(p["head"], [
            ("flow  icmp 8 echo 192.168.122.122 -> 1.1.1.1  virbr0>wlo1  uid vm", "value"),
            ("3 lines, first s1000, last s1002   (oldest first)", "note")])
        self.assertEqual([r["cells"] for r in p["rows"]][0],
                         ["h1000", "icmp 8 echo", "192.168.122.122", "1.1.1.1", "-", "84",
                          "63", "virbr0>wlo1"])
        tcp = c["packets"][c["flows"]["rows"][0]["id"]]["rows"][0]
        self.assertEqual(tcp["cells"][2:5], ["192.168.122.122:40000", "10.96.0.1:443", "SYN"])
        f = {d["k"]: (d["v"], d["style"]) for d in tcp["detail"] if d["k"]}
        self.assertEqual(f["rule"], ("HFW-FWD-VM-LAN  VM to LAN / outside the tunnel", "name"))
        self.assertEqual(f["verdict"][1], "warn")               # blocked: its severity color
        self.assertEqual(f["time"], ("s1012", "text"))
        self.assertEqual(f["source (SRC)"], ("192.168.122.122", "value"))
        self.assertEqual(f["dest port (DPT)"], ("443", "value"))
        self.assertEqual(f["source port (SPT)"], ("40000", "value"))
        self.assertEqual(f["mac (dst:src:type) (MAC)"][1], "text")
        self.assertEqual(f["flags"], ("DF SYN", "high"))

    def test_colors_per_rule(self):
        noise = card(jline("n", 2000, NOISE), {**INFO, "verdict": "zone  ..."}, "in_noise")
        self.assertEqual((noise["flows"]["rows"][0]["sev"], noise["flows"]["rows"][0]["tone"]),
                         ("ok", "dim"))
        new = ("HFW-OUT-NEW: IN= OUT=wg0-mullvad SRC=10.2.0.2 DST=198.51.100.20 LEN=60 "
               "PROTO=TCP SPT=33146 DPT=443 SYN UID=1000 GID=1000 ")
        allowed = card(jline("a", 1, new), {**INFO, "verdict": "allow  ..."}, "out_new")
        r = allowed["flows"]["rows"][0]
        self.assertEqual((r["sev"], r["tone"], r["cells"][-1]), ("ok", "blue", "1000"))
        fields = allowed["packets"][r["id"]]["rows"][0]["detail"]
        self.assertEqual(fields[1]["style"], "value")           # allowed: safe color

    def test_leak_colors_by_verdict(self):
        self.assertEqual(logcard.colors("out_leak", "block"), ("warn", "yellow"))   # blocked
        self.assertEqual(logcard.colors("out_leak", "pass"), ("crit", "plain"))     # observe
        self.assertEqual(logcard.colors("out_dns", "block"), ("warn", "yellow"))

    def test_icmpv6_names(self):
        e = logcard.journal.parse(jline("x", 1, "HFW-OUT-LAN: IN= OUT=wlo1 SRC=fe80::1 "
                                                "DST=ff02::1 PROTO=ICMPv6 TYPE=135 CODE=0 "))[0]
        self.assertEqual(logcard.proto(e[0]), "icmpv6 135 neighbor solicit")


class TestCoreLogs(unittest.TestCase):
    VIEW = [{"name": "firewall", "panels": [
        {"id": "counters", "type": "table", "rows": [
            {"cells": ["fwd_vm_lan", "20", "", "1.3K"], "logs": "fwd_vm_lan",
             "detail": [{"k": "meaning", "v": "VM to LAN"}, {"k": "", "v": ""},
                        {"k": "verdict", "v": "block  rejected"}]}]}]}]

    def test_info_from_the_row(self):
        self.assertEqual(logs.info(self.VIEW, "firewall/counters", "fwd_vm_lan"),
                         {"meaning": "VM to LAN", "verdict": "block  rejected", "pkts": "20"})
        self.assertEqual(logs.info(self.VIEW, "firewall/counters", "out_dns"), {})

    def test_load(self):
        c = logs.load(("firewall", "firewall/counters", "fwd_vm_lan"), self.VIEW,
                      run=Run(ok(host_lines())))
        self.assertEqual((c["code"], c["lines"]), ("HFW-FWD-VM-LAN", 20))
        self.assertEqual(logs.load(("security", "x/y", "a"), []),
                         {"error": "no log card for module security"})
        bad = logs.load(("firewall", "firewall/counters", "x;y"), [], run=Run(ok("")))
        self.assertTrue(bad["error"].startswith("log card: ValueError"))


if __name__ == "__main__":
    unittest.main()
