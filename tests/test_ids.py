import json
import os
import tempfile
import unittest

import modules.ids as ids
from core import alerts
from core.module import Context, check_module, validate
from core.screens import SCREENS, find

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# real eve lines (2026-11-25): the hardening's made-up capture (tests/ids_pcap.py,
# documentation addresses) through Suricata 8.0.8 with its ids/suricata.yaml + local.rules
SAMPLE = os.path.join(ROOT, "tests", "fixtures", "ids", "eve-local-rules.json")
T0 = ids.parse_ts("2026-01-01T03:00:00.000000+0300")
CTX = Context((), False, "")


def sample():
    with open(SAMPLE, "rb") as f:
        return f.read()


def et_line(ts=T0 + 5, sid=2001219, sev=2, sigsev="Major", src="198.51.100.9"):
    """An ET Open alert line as Suricata 8 writes it (rule metadata on)."""
    return json.dumps({
        "timestamp": "2026-01-01T03:00:%02d.000000+0300" % (ts - T0), "flow_id": 1,
        "event_type": "alert", "src_ip": src, "src_port": 50000, "dest_ip": "192.0.2.10",
        "dest_port": 22, "proto": "TCP", "pkt_src": "wire/pcap",
        "alert": {"action": "allowed", "gid": 1, "signature_id": sid, "rev": 20,
                  "signature": "ET SCAN Potential SSH Scan", "category": "Attempted Information Leak",
                  "severity": sev, "metadata": {"signature_severity": [sigsev],
                                                "attack_target": ["Server"]}},
    }).encode() + b"\n"


class Eve:
    """eve.json in a temp dir + the module with a fake clock."""

    def __init__(self, tc, data=b""):
        self.d = tempfile.TemporaryDirectory()
        tc.addCleanup(self.d.cleanup)
        self.path = os.path.join(self.d.name, "eve.json")
        if data is not None:
            self.write(data, "wb")
        self.now = T0 + 10
        self.st = ids.State(path=self.path, wall=lambda: self.now, stamp=lambda ts: f"T{ts:.0f}")
        tc.addCleanup(self.st.close)

    def write(self, data, mode="ab"):
        with open(self.path, mode) as f:
            f.write(data)

    def collect(self):
        return validate(ids.collect(self.st, CTX))


def rows(snap, box="ids"):
    p = next(p for p in snap["panels"] if p["id"] == box)
    return p["rows"]


class ModuleTest(unittest.TestCase):
    def test_interface_and_screen(self):
        check_module(ids)
        self.assertIn("ids", SCREENS[find("firewall")].modules)
        self.assertEqual(SCREENS[find("1")].name, "firewall")

    def test_init_options(self):
        self.assertEqual(ids.init({}).path, ids.EVE_PATH)
        self.assertEqual(ids.init({"path": "/tmp/x.json"}).path, "/tmp/x.json")
        with self.assertRaises(ValueError):
            ids.init({"path": "rel.json"})
        with self.assertRaises(ValueError):
            ids.init({"bogus": 1})


class SampleTest(unittest.TestCase):
    def test_groups_worst_first(self):
        e = Eve(self, sample())
        snap = e.collect()
        r = rows(snap)
        self.assertEqual(len(r), 9)                       # 9 rules, one source each
        sevs = [x["sev"] for x in r]
        self.assertEqual(sevs, sorted(sevs, key=lambda s: -ids.RANK[s]))
        kinds = {x["cells"][2]: x["sev"] for x in r}
        self.assertEqual(kinds["leak"], "crit")
        self.assertEqual(kinds["scan"], "crit")
        self.assertEqual(kinds["probe"], "warn")
        self.assertEqual(kinds["vm_lan"], "warn")
        self.assertEqual(kinds["vm_probe"], "warn")
        # newest first within crit: the TLS leak (flow timeout line) is the last crit line
        self.assertIn("TLS outside the tunnel", r[0]["cells"][3])
        dns = next(x for x in r if "DNS outside" in x["cells"][3])
        self.assertEqual(dns["cells"][4:], ["192.0.2.10", "198.51.100.53:53"])
        self.assertEqual(dns["ip"], "192.0.2.10")
        d = {it["k"]: it["v"] for it in dns["detail"]}
        self.assertEqual(d["sid"], "9200010")
        self.assertEqual(d["kind"], "leak")
        self.assertEqual(d["proto"], "UDP / dns")
        self.assertTrue(d["rule"].startswith("local rule"))
        self.assertEqual(len(rows(snap, "eve")), 9)
        self.assertEqual(snap["summary"], "24 h: crit 5 | warn 4 | info 0")

    def test_checks_crit_and_warn_once(self):
        e = Eve(self, sample())
        snap = e.collect()
        keys = {c["key"]: c for c in snap["checks"]}
        self.assertEqual(len(keys), 9)
        self.assertEqual(keys["ids:9200010:192.0.2.10"]["sev"], "crit")
        self.assertEqual(keys["ids:9200003:192.0.2.53"]["sev"], "warn")
        self.assertEqual(keys["ids:9200010:192.0.2.10"]["n"], 1)
        self.assertEqual(e.collect()["checks"], [])      # nothing new: no check again

    def test_alert_engine_opens_new_not_backlog(self):
        e = Eve(self, sample())
        e.now = T0 + 30
        st = alerts.step(alerts.empty(), "ids", e.collect()["checks"], e.now)
        opened = {a["key"] for a in alerts.active(st, e.now, [])}
        self.assertIn("ids/ids:9200010:192.0.2.10", opened)
        # a collector restart a day later: the same lines are backlog, nothing opens
        e2 = Eve(self, sample())
        e2.now = T0 + 86000
        st2 = alerts.step(alerts.empty(), "ids", e2.collect()["checks"], e2.now)
        self.assertEqual(alerts.active(st2, e2.now, []), [])


class EtTest(unittest.TestCase):
    def test_et_severity(self):
        self.assertEqual(ids.rate("", 1, []), "crit")
        self.assertEqual(ids.rate("", 3, ["Critical"]), "crit")
        self.assertEqual(ids.rate("", 2, []), "warn")
        self.assertEqual(ids.rate("", 3, ["Major"]), "warn")
        self.assertEqual(ids.rate("", 3, ["Minor"]), "info")
        self.assertEqual(ids.rate("probe", 1, []), "warn")      # the kind wins
        self.assertEqual(ids.rate("leak", 3, []), "crit")

    def test_et_line_grouped_by_source(self):
        e = Eve(self, et_line() + et_line(ts=T0 + 6) + et_line(ts=T0 + 7, src="198.51.100.10"))
        r = rows(e.collect())
        self.assertEqual([(x["cells"][1], x["cells"][2], x["cells"][4], x["sev"]) for x in r],
                         [("1", "et", "198.51.100.10", "warn"), ("2", "et", "198.51.100.9", "warn")])
        d = {it["k"]: it["v"] for it in r[1]["detail"]}
        self.assertEqual(d["severity"], "2 (Major)")
        self.assertEqual(d["rule"], "ET Open")
        self.assertEqual(d["category"], "Attempted Information Leak")

    def test_info_no_check(self):
        e = Eve(self, et_line(sev=3, sigsev="Minor"))
        snap = e.collect()
        self.assertEqual(rows(snap)[0]["sev"], "info")
        self.assertEqual(snap["checks"], [])


class FileTest(unittest.TestCase):
    def test_tail_follows_appends_and_partial_lines(self):
        e = Eve(self, b"")
        self.assertEqual(rows(e.collect()), [])
        line = et_line()
        e.write(line[:30])
        self.assertEqual(rows(e.collect()), [])           # half a line: wait
        e.write(line[30:])
        self.assertEqual(rows(e.collect())[0]["cells"][1], "1")
        e.write(et_line(ts=T0 + 7))
        self.assertEqual(rows(e.collect())[0]["cells"][1], "2")

    def test_rotation_reads_old_end_then_new(self):
        e = Eve(self, et_line())
        e.collect()
        e.write(et_line(ts=T0 + 6))                     # written before the rename
        os.rename(e.path, e.path + ".1")
        e.write(et_line(ts=T0 + 7, src="198.51.100.10"), "wb")    # the new file
        r = {x["cells"][4]: x["cells"][1] for x in rows(e.collect())}
        self.assertEqual(r, {"198.51.100.9": "2", "198.51.100.10": "1"})

    def test_truncate_starts_over(self):
        e = Eve(self, et_line() + et_line(ts=T0 + 6))
        e.collect()
        e.write(et_line(ts=T0 + 7, src="198.51.100.10"), "wb")    # shorter: truncated
        r = {x["cells"][4]: x["cells"][1] for x in rows(e.collect())}
        self.assertEqual(r, {"198.51.100.9": "2", "198.51.100.10": "1"})

    def test_missing_then_created(self):
        e = Eve(self, None)
        snap = e.collect()
        self.assertEqual(snap["summary"], ids.NOTE_MISSING)
        self.assertEqual(snap["status"], "info")
        self.assertEqual(snap["checks"], [])
        e.write(et_line(), "wb")
        snap = e.collect()
        self.assertEqual(len(rows(snap)), 1)            # a new file: read from its start
        self.assertTrue(snap["summary"].startswith("24 h:"))

    @unittest.skipIf(os.geteuid() == 0, "root reads a 0000 file")
    def test_no_access(self):
        e = Eve(self, et_line())
        os.chmod(e.path, 0)
        snap = e.collect()
        self.assertEqual(snap["status"], "warn")
        self.assertEqual(snap["summary"], ids.NOTE_DENIED)
        self.assertEqual([c["key"] for c in snap["checks"]], ["ids:no_access"])

    def test_backlog_only_last_bytes(self):
        old = ids.START_BYTES
        self.addCleanup(setattr, ids, "START_BYTES", old)
        line = et_line(src="198.51.100.1")
        ids.START_BYTES = len(line) + 10                # mid-line seek: the cut line goes
        e = Eve(self, line * 3 + et_line(src="198.51.100.2"))
        r = {x["cells"][4]: x["cells"][1] for x in rows(e.collect())}
        self.assertEqual(r, {"198.51.100.2": "1"})

    def test_bad_lines_skipped(self):
        big = b'{"event_type":"alert","x":"' + b"a" * (ids.LINE_MAX + 1) + b'"}\n'
        e = Eve(self, b"not json\n[1]\n" + big + b'{"event_type":"anomaly"}\n' + et_line())
        snap = e.collect()
        self.assertEqual(len(rows(snap)), 1)
        self.assertEqual(e.st.skipped, 3)
        self.assertIn("anomaly 1", snap["summary"])

    def test_old_groups_go(self):
        e = Eve(self, et_line())
        e.collect()
        e.now = T0 + ids.KEEP + 60
        self.assertEqual(rows(e.collect()), [])

    def test_symlink_refused(self):
        e = Eve(self, None)
        target = os.path.join(e.d.name, "other.json")
        with open(target, "wb") as f:
            f.write(et_line())
        os.symlink(target, e.path)
        snap = e.collect()
        self.assertEqual(rows(snap), [])
        self.assertIn("eve.json:", snap["summary"])


if __name__ == "__main__":
    unittest.main()
