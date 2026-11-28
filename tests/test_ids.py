import json
import os
import tempfile
import unittest

import modules.ids as ids
from core import alerts, eve, idsd, statefile
from core.module import Context, check_module, validate
from core.screens import SCREENS, find

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# real eve lines (2026-11-25): the hardening's made-up capture (tests/ids_pcap.py,
# documentation addresses) through Suricata 8.0.8 with its ids/suricata.yaml + local.rules
SAMPLE = os.path.join(ROOT, "tests", "fixtures", "ids", "eve-local-rules.json")
T0 = eve.parse_ts("2026-01-01T03:00:00.000000+0300")
CTX = Context((), False, "")


def sample():
    with open(SAMPLE, "rb") as f:
        return f.read()


def stamp(ts):
    """eve timestamp for epoch seconds (UTC+3, as the host writes it)."""
    import datetime
    tz = datetime.timezone(datetime.timedelta(hours=3))
    return datetime.datetime.fromtimestamp(ts, tz).strftime("%Y-%m-%dT%H:%M:%S.%f%z")


def et_line(ts=T0 + 5, sid=2001219, sev=2, sigsev="Major", src="198.51.100.9",
            sig="ET SCAN Potential SSH Scan", category="Attempted Information Leak"):
    """An ET Open alert line as Suricata 8 writes it (rule metadata on)."""
    return json.dumps({
        "timestamp": stamp(ts), "flow_id": 1,
        "event_type": "alert", "src_ip": src, "src_port": 50000, "dest_ip": "192.0.2.10",
        "dest_port": 22, "proto": "TCP", "pkt_src": "wire/pcap",
        "alert": {"action": "allowed", "gid": 1, "signature_id": sid, "rev": 20,
                  "signature": sig, "category": category,
                  "severity": sev, "metadata": {"signature_severity": [sigsev],
                                                "attack_target": ["Server"],
                                                "confidence": ["High"]}},
    }).encode() + b"\n"


def cc_line(ts=T0 + 5):
    """sid 2027758 as the host saw it (admin 78, 2026-11-27; documentation addresses)."""
    return et_line(ts=ts, sid=2027758, sev=2, sigsev="Informational", src="192.0.2.15",
                   sig="ET DNS Query for .cc TLD", category="Potentially Bad Traffic")


class Pipe:
    """eve.json -> the helper (core/idsd.py) -> summary.json -> the module, fake clock."""

    def __init__(self, tc, data=b""):
        self.d = tempfile.TemporaryDirectory()
        tc.addCleanup(self.d.cleanup)
        self.path = os.path.join(self.d.name, "eve.json")
        self.out = os.path.join(self.d.name, "summary.json")
        if data is not None:
            self.write(data, "wb")
        self.now = T0 + 10
        self.counts = idsd.Counts()
        self.reader = None
        self.st = ids.State(path=self.out, wall=lambda: self.now, owner=os.getuid(),
                            stamp=lambda ts: f"T{ts:.0f}")
        tc.addCleanup(lambda: self.reader and self.reader.close())

    def write(self, data, mode="ab", path=None):
        with open(path or self.path, mode) as f:
            f.write(data)

    def helper(self):
        clock = lambda: self.now        # noqa: E731
        if self.reader is None:
            self.reader = idsd.start(self.path, self.counts, clock)
        else:
            idsd.catch_up(self.reader, self.counts, clock)
        self.counts.prune(self.now)
        doc = self.counts.doc(self.now, self.reader.note, self.reader.skipped, T0)
        statefile.write(self.out, doc, 0o640)
        return doc

    def collect(self, helper=True):
        if helper:
            self.helper()
        self.st.mtime = None            # same mtime within a test: read again
        return validate(ids.collect(self.st, CTX))


def rows(snap, box="ids"):
    p = next(p for p in snap["panels"] if p["id"] == box)
    return p["rows"] if "rows" in p else p["items"]


def detail(row):
    return {it["k"]: it["v"] for it in row["detail"]}


COL = {c: i for i, c in enumerate(ids.COLUMNS)}


class ModuleTest(unittest.TestCase):
    def test_interface_and_screen(self):
        check_module(ids)
        self.assertIn("ids", SCREENS[find("firewall")].modules)
        self.assertEqual(SCREENS[find("1")].name, "firewall")
        self.assertEqual(ids.OWNER, idsd.OWNER)
        self.assertEqual(ids.SUMMARY, os.path.join(idsd.RUN_DIR, idsd.FILE))
        self.assertEqual(ids.VERSION, idsd.VERSION)
        self.assertLessEqual(idsd.ALIVE * 2, ids.MAX_AGE)

    def test_init_options(self):
        self.assertEqual(ids.init({}).path, ids.SUMMARY)
        self.assertEqual(ids.init({"path": "/tmp/x.json"}).path, "/tmp/x.json")
        with self.assertRaises(ValueError):
            ids.init({"path": "rel.json"})
        with self.assertRaises(ValueError):
            ids.init({"bogus": 1})


class SampleTest(unittest.TestCase):
    def test_groups_worst_first(self):
        p = Pipe(self, sample())
        snap = p.collect()
        r = rows(snap)
        self.assertEqual(len(r), 9)                       # 9 rules, one source each
        sevs = [x["sev"] for x in r]
        self.assertEqual(sevs, sorted(sevs, key=lambda s: -ids.RANK[s]))
        types = {x["cells"][COL["type"]]: x["sev"] for x in r}
        self.assertEqual(types["tunnel leak"], "crit")
        self.assertEqual(types["scan of this laptop"], "crit")
        self.assertEqual(types["probe of this laptop"], "warn")
        self.assertEqual(types["VM to the LAN"], "warn")
        self.assertEqual(types["VM probing the host"], "warn")
        # newest first within crit: the TLS leak (flow timeout line) is the last crit line
        self.assertIn("TLS outside the tunnel", r[0]["cells"][COL["signature"]])
        dns = next(x for x in r if "DNS outside" in x["cells"][COL["signature"]])
        self.assertEqual(dns["cells"][COL["from"]:], ["192.0.2.10", "198.51.100.53:53"])
        self.assertEqual(dns["cells"][COL["rule"]], "local")
        self.assertEqual(dns["cells"][COL["sev"]], "p1")
        self.assertEqual(dns["ip"], "192.0.2.10")
        d = detail(dns)
        self.assertEqual(d["sid"], "9200010")
        self.assertEqual(d["kind"], "leak")
        self.assertEqual(d["proto"], "UDP / dns")
        self.assertTrue(d["rule"].startswith("local rule"))
        self.assertEqual(d["colour"], "red: act now")
        self.assertEqual(d["key"], "all colours, counts and rule groups: ? (help)")
        self.assertEqual(len(rows(snap, "eve")), 9)
        self.assertEqual(snap["summary"], "24 h: crit 5 | warn 4 | info 0")

    def test_checks_crit_and_warn_once_held_an_hour(self):
        p = Pipe(self, sample())
        snap = p.collect()
        keys = {c["key"]: c for c in snap["checks"]}
        self.assertEqual(len(keys), 9)
        self.assertEqual(keys["ids:9200010:192.0.2.10"]["sev"], "crit")
        self.assertEqual(keys["ids:9200003:192.0.2.53"]["sev"], "warn")
        self.assertEqual(keys["ids:9200010:192.0.2.10"]["n"], 1)
        self.assertEqual({c["hold"] for c in keys.values()}, {3600.0})
        self.assertEqual(p.collect()["checks"], [])      # nothing new: no check again

    def test_alert_engine_opens_new_not_backlog(self):
        p = Pipe(self, sample())
        p.now = T0 + 30
        st = alerts.step(alerts.empty(), "ids", p.collect()["checks"], p.now)
        opened = {a["key"] for a in alerts.active(st, p.now, [])}
        self.assertIn("ids/ids:9200010:192.0.2.10", opened)
        # a collector restart two hours later: the same lines are old, nothing opens
        p2 = Pipe(self, sample())
        p2.now = T0 + 7200
        st2 = alerts.step(alerts.empty(), "ids", p2.collect()["checks"], p2.now)
        self.assertEqual(alerts.active(st2, p2.now, []), [])


class RateTest(unittest.TestCase):
    def test_et_severity(self):
        self.assertEqual(ids.rate("", 1, []), "crit")
        self.assertEqual(ids.rate("", 3, ["Critical"]), "crit")
        self.assertEqual(ids.rate("", 2, []), "warn")
        self.assertEqual(ids.rate("", 3, ["Major"]), "warn")
        self.assertEqual(ids.rate("", 3, ["Minor"]), "info")
        self.assertEqual(ids.rate("", None, []), "info")
        self.assertEqual(ids.rate("probe", 1, []), "warn")      # the kind wins
        self.assertEqual(ids.rate("leak", 3, []), "crit")

    def test_low_only_without_danger(self):
        """Decision 2026-11-27: low (Informational / Minor) = info only when the type
        carries no danger; danger stays yellow."""
        cc = ("ET DNS Query for .cc TLD", "Potentially Bad Traffic")
        self.assertEqual(ids.rate("", 2, ["Informational"], cc[1], cc[0]), "info")
        self.assertEqual(ids.rate("", 2, ["Informational"], "A Network Trojan was detected",
                                  "ET INFO x"), "warn")
        self.assertEqual(ids.rate("", 3, ["Minor"], "Misc activity", "ET MALWARE x"), "warn")
        self.assertEqual(ids.rate("", 3, ["Minor"], "Domain Observed Used for C2 Detected",
                                  "ET INFO x"), "warn")
        self.assertEqual(ids.rate("", 3, ["Informational"], "Misc Attack", "ET DROP x"), "warn")
        # priority 1 marked low: not red, not white
        self.assertEqual(ids.rate("", 1, ["Informational"], "Potential Corporate Privacy "
                                  "Violation", "ET POLICY x"), "warn")
        self.assertEqual(ids.et_group("ET DNS Query for .cc TLD"), "DNS")
        self.assertEqual(ids.et_group("HARDEN scan"), "")
        self.assertEqual(ids.et_group("ET"), "")

    def test_cc_rule_from_the_host_is_info(self):
        p = Pipe(self, cc_line() + cc_line(ts=T0 + 6))
        snap = p.collect()
        r = rows(snap)[0]
        self.assertEqual(r["sev"], "info")
        self.assertEqual(r["cells"][COL["rule"]:COL["signature"]],
                         ["ET Open", "Informational p2", "Potentially Bad Traffic"])
        self.assertEqual(snap["checks"], [])
        d = detail(r)
        self.assertTrue(d["ET group"].startswith("DNS: DNS lookups"))
        self.assertEqual(d["colour"], "white: info, no alert")
        self.assertEqual((d["target"], d["confidence"]), ("Server", "High"))


class CountTest(unittest.TestCase):
    def test_grouped_by_source(self):
        p = Pipe(self, et_line() + et_line(ts=T0 + 6) + et_line(ts=T0 + 7, src="198.51.100.10"))
        r = rows(p.collect())
        self.assertEqual([(x["cells"][COL["24 h"]], x["cells"][COL["from"]], x["sev"]) for x in r],
                         [("1", "198.51.100.10", "warn"), ("2", "198.51.100.9", "warn")])
        d = detail(r[1])
        self.assertEqual(d["rule severity"], "Major p2")
        self.assertEqual(d["rule"], "ET Open")
        self.assertEqual(d["type"], "Attempted Information Leak")

    def test_exact_counts_every_line(self):
        p = Pipe(self, b"".join(et_line(ts=T0 + 1 + i / 1000) for i in range(1500)))
        r = rows(p.collect())
        self.assertEqual(r[0]["cells"][COL["24 h"]], "1500")

    def test_hours(self):
        h0 = idsd.hour(T0)
        p = Pipe(self, et_line(ts=h0 - 600) + et_line(ts=h0 + 60) + et_line(ts=h0 + 120))
        p.now = h0 + 300
        r = rows(p.collect())[0]
        self.assertEqual((r["cells"][COL["24 h"]], r["cells"][COL["hour"]]), ("3", "2"))
        p.now = h0 + 3600 + 5                                  # next clock hour
        r = rows(p.collect())[0]
        self.assertEqual((r["cells"][COL["24 h"]], r["cells"][COL["hour"]]), ("3", "0"))
        p.now = h0 + 23 * 3600 + 5                             # the hour before h0 drops out
        r = rows(p.collect())[0]
        self.assertEqual(r["cells"][COL["24 h"]], "2")
        p.now = h0 + 24 * 3600 + 5
        self.assertEqual(rows(p.collect()), [])

    def test_one_alert_an_hour_count_grows(self):
        p = Pipe(self, et_line(ts=T0 + 1))
        p.now = T0 + 2
        st = alerts.step(alerts.empty(), "ids", p.collect()["checks"], p.now)
        for i in range(2, 6):
            p.write(et_line(ts=T0 + i * 600))
            p.now = T0 + i * 600 + 1
            checks = p.collect()["checks"]
            self.assertEqual([c["n"] for c in checks], [1])
            st = alerts.step(st, "ids", checks, p.now)
        act = alerts.active(st, p.now, [])
        self.assertEqual(len(act), 1)
        self.assertEqual(act[0]["count"], 5)

    def test_group_cap_keeps_crit(self):
        old = idsd.MAX_GROUPS
        self.addCleanup(setattr, idsd, "MAX_GROUPS", old)
        idsd.MAX_GROUPS = 3
        lines = b"".join(et_line(ts=T0 + i, src=f"198.51.100.{i}", sev=3, sigsev="Minor")
                         for i in range(1, 6))
        p = Pipe(self, sample()[:sample().index(b"\n") + 1] + lines)
        doc = p.helper()
        self.assertEqual(len(doc["groups"]), 3)
        self.assertEqual(doc["dropped"], 3)
        self.assertIn(9200001, [g["sid"] for g in doc["groups"]])   # the scan stays


class FileTest(unittest.TestCase):
    def test_tail_follows_appends_and_partial_lines(self):
        p = Pipe(self, b"")
        self.assertEqual(rows(p.collect()), [])
        line = et_line()
        p.write(line[:30])
        self.assertEqual(rows(p.collect()), [])           # half a line: wait
        p.write(line[30:])
        self.assertEqual(rows(p.collect())[0]["cells"][COL["24 h"]], "1")
        p.write(et_line(ts=T0 + 7))
        self.assertEqual(rows(p.collect())[0]["cells"][COL["24 h"]], "2")

    def test_rotation_reads_old_end_then_new(self):
        p = Pipe(self, et_line())
        p.collect()
        p.write(et_line(ts=T0 + 6))                     # written before the rename
        os.rename(p.path, p.path + ".1")
        p.write(et_line(ts=T0 + 7, src="198.51.100.10"), "wb")    # the new file
        r = {x["cells"][COL["from"]]: x["cells"][COL["24 h"]] for x in rows(p.collect())}
        self.assertEqual(r, {"198.51.100.9": "2", "198.51.100.10": "1"})

    def test_start_reads_yesterdays_file_too(self):
        p = Pipe(self, et_line(ts=T0 + 7, src="198.51.100.10"))
        p.write(et_line() + et_line(ts=T0 + 6), "wb", path=p.path + ".1")
        r = {x["cells"][COL["from"]]: x["cells"][COL["24 h"]] for x in rows(p.collect())}
        self.assertEqual(r, {"198.51.100.9": "2", "198.51.100.10": "1"})

    def test_truncate_starts_over(self):
        p = Pipe(self, et_line() + et_line(ts=T0 + 6))
        p.collect()
        p.write(et_line(ts=T0 + 7, src="198.51.100.10"), "wb")    # shorter: truncated
        r = {x["cells"][COL["from"]]: x["cells"][COL["24 h"]] for x in rows(p.collect())}
        self.assertEqual(r, {"198.51.100.9": "2", "198.51.100.10": "1"})

    def test_missing_then_created(self):
        p = Pipe(self, None)
        snap = p.collect()
        self.assertEqual(snap["summary"], eve.NOTE_MISSING)
        self.assertEqual(snap["status"], "info")
        self.assertEqual(snap["checks"], [])
        p.write(et_line(), "wb")
        snap = p.collect()
        self.assertEqual(len(rows(snap)), 1)            # a new file: read from its start
        self.assertTrue(snap["summary"].startswith("24 h:"))

    @unittest.skipIf(os.geteuid() == 0, "root reads a 0000 file")
    def test_no_access(self):
        p = Pipe(self, et_line())
        os.chmod(p.path, 0)
        snap = p.collect()
        self.assertEqual(snap["status"], "warn")
        self.assertEqual(snap["summary"], eve.NOTE_DENIED)
        self.assertEqual([c["key"] for c in snap["checks"]], ["ids:no_access"])

    def test_backlog_only_last_bytes(self):
        old = idsd.START_BYTES
        self.addCleanup(setattr, idsd, "START_BYTES", old)
        line = et_line(src="198.51.100.1")
        idsd.START_BYTES = len(line) + 10               # mid-line seek: the cut line goes
        p = Pipe(self, line * 3 + et_line(src="198.51.100.2"))
        r = {x["cells"][COL["from"]]: x["cells"][COL["24 h"]] for x in rows(p.collect())}
        self.assertEqual(r, {"198.51.100.2": "1"})

    def test_small_budget_catches_up(self):
        old = idsd.BUDGET
        self.addCleanup(setattr, idsd, "BUDGET", old)
        idsd.BUDGET = 100                               # many reads at start
        p = Pipe(self, b"".join(et_line(ts=T0 + i) for i in range(1, 9)))
        self.assertEqual(rows(p.collect())[0]["cells"][COL["24 h"]], "8")

    def test_bad_lines_skipped(self):
        big = b'{"event_type":"alert","x":"' + b"a" * (eve.LINE_MAX + 1) + b'"}\n'
        p = Pipe(self, b"not json\n[1]\n" + big + b'{"event_type":"anomaly"}\n' + et_line())
        snap = p.collect()
        self.assertEqual(len(rows(snap)), 1)
        self.assertEqual(p.helper()["skipped"], 3)
        self.assertIn("anomaly 1", snap["summary"])

    def test_symlink_refused(self):
        p = Pipe(self, None)
        target = os.path.join(p.d.name, "other.json")
        with open(target, "wb") as f:
            f.write(et_line())
        os.symlink(target, p.path)
        snap = p.collect()
        self.assertEqual(rows(snap), [])
        self.assertIn("eve.json:", snap["summary"])


class SummaryTest(unittest.TestCase):
    def doc(self, **kw):
        c = idsd.Counts()
        c.add([et_line()], T0 + 10)
        d = c.doc(T0 + 10, "", 0, T0)
        d.update(kw)
        return d

    def test_checked(self):
        d = ids.check_summary(self.doc())
        self.assertEqual(d["groups"][0]["n24"], 1)
        bad = [{"v": 2}, {"groups": "x"}, {"tail": [1]}, {"other": {"A B": 1}},
               {"skipped": -1}, {"ts": float("nan")}]
        for b in bad:
            with self.assertRaises(ValueError, msg=b):
                ids.check_summary(self.doc(**b))
        for field, v in (("sid", "1"), ("src", "x"), ("n24", -1), ("sig", "a" * 201),
                         ("severity", 0), ("sigsev", ["a"] * 4), ("kind", "Bad"),
                         ("dsts", ["x"] * 6), ("last", "now")):
            d = self.doc()
            d["groups"][0][field] = v
            with self.assertRaises(ValueError, msg=field):
                ids.check_summary(d)
        d = self.doc()
        d["groups"][0]["sig"] = "ET x\x1b[31m"
        self.assertEqual(ids.check_summary(d)["groups"][0]["sig"], "ET x?[31m")

    def test_missing_stale_wrong_owner(self):
        p = Pipe(self, et_line())
        snap = p.collect(helper=False)                  # helper not run yet
        self.assertEqual((snap["status"], snap["summary"]), ("info", ids.NOTE_NONE))
        p.collect()
        p.now += ids.MAX_AGE + 5
        snap = p.collect(helper=False)
        self.assertEqual(snap["status"], "warn")
        self.assertIn("ids:stale", [c["key"] for c in snap["checks"]])
        p.st.owner = os.getuid() + 1
        snap = p.collect(helper=False)
        self.assertIn("ids summary:", snap["summary"])
        self.assertEqual(rows(snap), [])

    def test_boxes(self):
        p = Pipe(self, et_line(ts=T0 - 7200) + et_line())
        snap = p.collect()
        titles = {x["id"]: x["title"] for x in snap["panels"]}
        self.assertEqual(titles["ids"], "ids  alerts last 24 h, per rule + source: 2 in 1 group(s)")
        self.assertEqual(titles["eve"], "eve  last 2 alert lines (any age, oldest 2 h ago)")
        panel = next(x for x in snap["panels"] if x["id"] == "ids_key")
        self.assertEqual(panel["width"], "help")           # in the help (?), not a box
        key = {it["k"]: it for it in rows(snap, "ids_key")}
        self.assertEqual((key["red"]["sev"], key["yellow"]["sev"], key["white"]["sev"]),
                         ("crit", "warn", "info"))
        self.assertIn("ET danger", key)
        self.assertTrue(all(len(it["v"]) <= 50 for it in key.values()))


class HelperTest(unittest.TestCase):
    def test_loop_writes_and_keeps_alive(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        path = os.path.join(d.name, "eve.json")
        with open(path, "wb") as f:
            f.write(et_line())
        writes, logs, clock = [], [], [T0 + 10]
        ticks = iter(range(40))

        def write(out, doc, mode):
            writes.append(doc)

        def sleep(s):
            clock[0] += s

        idsd.loop(path, "x", write=write, wall=lambda: clock[0], sleep=sleep,
                  log=logs.append, stop=lambda: next(ticks) >= 20)
        # first write at once, then the same content again only every ALIVE seconds
        self.assertEqual(len(writes), 1 + int(20 * idsd.INTERVAL // idsd.ALIVE))
        self.assertEqual(writes[0]["groups"][0]["n24"], 1)

        def broken(out, doc, mode):
            raise OSError(13, "Permission denied")
        ticks = iter(range(40))
        idsd.loop(path, "x", write=broken, wall=lambda: clock[0], sleep=sleep,
                  log=logs.append, stop=lambda: next(ticks) >= 3)
        self.assertEqual(len(logs), 1)                  # logged once, not every tick
        self.assertIn("Permission denied", logs[0])

    def test_main_refuses(self):
        import contextlib
        import io
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(idsd.main(["x"]), 2)
            self.assertEqual(idsd.main([]), 2)          # root, or not user sectop-ids
        self.assertIn("usage: sectop-ids", err.getvalue())


if __name__ == "__main__":
    unittest.main()
