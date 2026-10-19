import contextlib
import io
import ipaddress
import json
import os
import tempfile
import unittest
import urllib.error

from core import lookup, rdap
from core.run import Result

BOOT4 = {"services": [
    [["41.0.0.0/8"], ["https://rdap.afrinic.net/rdap/", "http://rdap.afrinic.net/rdap/"]],
    [["8.0.0.0/8", "160.0.0.0/8"], ["http://rdap.arin.net/registry/",
                                    "https://rdap.arin.net/registry/"]],
    [["8.8.0.0/16"], ["https://more.example/rdap"]],              # more specific wins
    [["193.0.0.0/8"], ["http://rdap.db.ripe.net/"]],              # no https: skipped
    ["bad"], [["not a net"], ["https://x/"]],
]}

# ARIN style: registrant with a nested abuse entity, cidr0 extension
ARIN = {
    "handle": "NET-8-8-8-0-2", "startAddress": "8.8.8.0", "endAddress": "8.8.8.255",
    "name": "GOGL", "type": "DIRECT ALLOCATION", "parentHandle": "NET-8-0-0-0-0",
    "port43": "whois.arin.net", "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
    "events": [{"eventAction": "last changed", "eventDate": "2014-03-14T16:52:05-04:00"},
               {"eventAction": "registration", "eventDate": "2014-03-14T16:52:05-04:00"}],
    "entities": [{
        "handle": "GOGL", "roles": ["registrant"],
        "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                 ["fn", {}, "text", "Google LLC"], ["kind", {}, "text", "org"]]],
        "entities": [{"handle": "ABUSE5250-ARIN", "roles": ["abuse"],
                      "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"],
                                               ["email", {}, "text", "network-abuse@google.com"]]]}]}],
}

# RIPE style: country, remarks, abuse entity at the top level, no registrant fn first
RIPE = {
    "handle": "193.0.0.0 - 193.0.7.255", "name": "RIPE-NCC", "country": "NL",
    "type": "ASSIGNED PA", "port43": "whois.ripe.net",
    "remarks": [{"description": ["RIPE NCC network\n  second line", "x"]}],
    "entities": [
        {"handle": "ABUSE-1", "roles": ["abuse"],
         "vcardArray": ["vcard", [["fn", {}, "text", "Abuse-C Role"],
                                  ["email", {"type": "abuse"}, "text", "abuse@ripe.net"]]]},
        {"handle": "ORG-RIEN1-RIPE", "roles": ["registrant"],
         "vcardArray": ["vcard", [["fn", {}, "text", "RIPE Network Coordination Centre"]]]}],
}


class TestRdap(unittest.TestCase):
    def test_base_url(self):
        ip = ipaddress.ip_address
        self.assertEqual(rdap.base_url(BOOT4, ip("8.8.8.8")), "https://more.example/rdap")
        self.assertEqual(rdap.base_url(BOOT4, ip("8.1.2.3")), "https://rdap.arin.net/registry/")
        self.assertEqual(rdap.base_url(BOOT4, ip("41.1.1.1")), "https://rdap.afrinic.net/rdap/")
        self.assertIsNone(rdap.base_url(BOOT4, ip("193.0.6.139")))      # http only
        self.assertIsNone(rdap.base_url(BOOT4, ip("2607:6bc0::10")))    # other version
        self.assertIsNone(rdap.base_url({}, ip("8.8.8.8")))
        self.assertIsNone(rdap.base_url({"services": "x"}, ip("8.8.8.8")))

    def test_pick_arin(self):
        self.assertEqual(rdap.pick(ARIN), [
            ("name", "GOGL"), ("handle", "NET-8-8-8-0-2"), ("range", "8.8.8.0 - 8.8.8.255"),
            ("cidr", "8.8.8.0/24"), ("type", "DIRECT ALLOCATION"), ("parent", "NET-8-0-0-0-0"),
            ("org", "Google LLC"), ("abuse", "network-abuse@google.com"),
            ("changed", "2014-03-14"), ("registered", "2014-03-14"),
            ("whois server", "whois.arin.net")])

    def test_pick_ripe(self):
        got = dict(rdap.pick(RIPE))
        self.assertEqual(got["org"], "RIPE Network Coordination Centre")   # registrant first
        self.assertEqual(got["abuse"], "abuse@ripe.net")
        self.assertEqual(got["country"], "NL")
        self.assertEqual(got["remark"], "RIPE NCC network second line")    # whitespace folded

    def test_pick_junk(self):
        self.assertEqual(rdap.pick({}), [])
        doc = {"name": 5, "entities": ["x", {"roles": "abuse", "vcardArray": ["vcard", "x"]}],
               "events": [None, {"eventAction": "registration", "eventDate": 1}],
               "cidr0_cidrs": [{"v6prefix": "2001:db8::", "length": "32"}], "remarks": [1],
               "handle": "h" * 500}
        self.assertEqual(rdap.pick(doc), [("handle", "h" * rdap.MAX_VALUE)])
        fn_only = {"entities": [{"roles": ["technical"],
                                 "vcardArray": ["vcard", [["fn", {}, "text", "NOC"]]]}]}
        self.assertEqual(rdap.pick(fn_only), [("org", "NOC")])         # no registrant: any fn

    def run_main(self, ip, answers):
        calls = []

        def get(url):
            calls.append(url)
            res = answers[url]
            if isinstance(res, Exception):
                raise res
            return res
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(rdap.main([ip], get=get), 0)
        return json.loads(out.getvalue()), calls

    def test_main(self):
        doc, calls = self.run_main("8.8.8.8", {rdap.BOOT[4]: BOOT4,
                                               "https://more.example/rdap/ip/8.8.8.8": ARIN})
        self.assertTrue(doc["ok"])
        self.assertEqual(calls, [rdap.BOOT[4], "https://more.example/rdap/ip/8.8.8.8"])
        self.assertEqual(doc["fields"][0], ["name", "GOGL"])
        self.assertEqual(doc["fields"][-1], ["source", "https://more.example/rdap/ip/8.8.8.8"])

    def test_main_errors(self):
        doc, calls = self.run_main("10.2.0.1", {})
        self.assertEqual((doc, calls), ({"ok": False,
                                         "error": "ValueError: not a public address"}, []))
        doc, _ = self.run_main("x", {})
        self.assertFalse(doc["ok"])
        err = urllib.error.URLError("Tunnel connection failed")
        doc, _ = self.run_main("8.8.8.8", {rdap.BOOT[4]: err})
        self.assertEqual(doc["error"], "URLError: <urlopen error Tunnel connection failed>")
        doc, _ = self.run_main("193.0.6.139", {rdap.BOOT[4]: BOOT4})
        self.assertIn("no RDAP server", doc["error"])

    def test_https_only_redirect(self):
        h = rdap.HttpsOnly()
        with self.assertRaises(urllib.error.HTTPError):
            h.redirect_request(None, None, 302, "Found", {}, "http://rdap.example/ip/1")


class Run:
    def __init__(self, res):
        self.res, self.calls = res, []

    def __call__(self, argv, timeout):
        self.calls.append((argv, timeout))
        return self.res


def ok(doc):
    return Result(0, json.dumps(doc) + "\n", "", False, False)


class TestLookup(unittest.TestCase):
    def go(self, res, ip="8.8.8.8", **kw):
        run = Run(res)
        kw.setdefault("user_ids", lambda: (99, 99))
        return lookup.lookup(ip, run=run, **kw), run.calls

    def test_public(self):
        self.assertTrue(lookup.public("8.8.8.8"))
        self.assertTrue(lookup.public("2607:6bc0::10"))
        for ip in ("10.2.0.1", "100.85.0.1", "fe80::1", "fdeb:446c:912d:8da::2", "x", ""):
            self.assertFalse(lookup.public(ip), ip)

    def test_argv_and_result(self):
        pairs, calls = self.go(ok({"ok": True, "fields": [["name", "GOGL"], ["org", "Google"]]}))
        [(argv, timeout)] = calls
        self.assertEqual(timeout, lookup.TIMEOUT)
        self.assertEqual(argv[:9], ["/usr/bin/setpriv", "--reuid=99", "--regid=99",
                                    "--clear-groups", "--no-new-privs", "--", "/usr/bin/python3",
                                    "-I", "-c"])
        self.assertIn("def main(", argv[9])                          # rdap.py source, not a path
        self.assertEqual(argv[10], "8.8.8.8")
        self.assertEqual(pairs[:2], [("name", "GOGL"), ("org", "Google")])
        self.assertTrue(pairs[2][1].startswith("RDAP as nobody (uid 99)"))

    def test_private_not_run(self):
        pairs, calls = self.go(ok({}), ip="10.2.0.1")
        self.assertEqual((pairs, calls), ([("whois", "not a public address: no whois")], []))

    def test_errors(self):
        cases = (
            (Result(-9, "", "", True, False), "timeout after 12 s"),
            (Result(127, "", "not found", False, False), "/usr/bin/setpriv not found"),
            (Result(126, "", "refused", False, False), "/usr/bin/setpriv not trusted"),
            (Result(1, "", "setpriv: setresuid failed\n", False, False),
             "rc 1: setpriv: setresuid failed"),
            (Result(0, "garbage\n", "", False, False), "bad child output: "),
            (Result(0, "", "", False, False), "bad child output: no JSON object"),
            (ok({"ok": False, "error": "URLError: boom"}), "URLError: boom"),
            (ok({"ok": True, "fields": "x"}), "bad child output: fields: list required"),
            (ok({"ok": True, "fields": [["a", 1]]}), "bad child output: fields: [str, str]"),
        )
        for res, want in cases:
            pairs, _ = self.go(res)
            self.assertTrue(pairs[0][1].startswith(want), (pairs, want))
            self.assertEqual(pairs[0][0], "whois")

    def test_limits(self):
        fields = [[f"k{i}" + "x" * 50, "v" * 500] for i in range(30)]
        pairs, _ = self.go(ok({"ok": True, "fields": fields}))
        self.assertEqual(len(pairs), lookup.MAX_FIELDS + 1)          # + via
        self.assertEqual((len(pairs[0][0]), len(pairs[0][1])), (40, lookup.MAX_VALUE))

    def test_refuses_root_and_untrusted(self):
        pairs, calls = self.go(ok({}), user_ids=lambda: (0, 0))
        self.assertEqual((pairs[0][1], calls), ("user nobody maps to root: refused", []))
        with tempfile.TemporaryDirectory() as d:
            py = os.path.join(d, "python3")
            with open(py, "w") as f:
                f.write("x")
            os.chmod(py, 0o777)
            pairs, calls = self.go(ok({}), python=py)
            self.assertEqual(calls, [])
            self.assertIn("python3: ", pairs[0][1])
            pairs, _ = self.go(ok({}), python=os.path.join(d, "missing"))
            self.assertTrue(pairs[0][1].endswith("missing: not found"))
            child = os.path.join(d, "rdap.py")
            with open(child, "wb") as f:
                f.write("x = '\u00e9'\n".encode())
            pairs, calls = self.go(ok({}), child=child)
            self.assertEqual((pairs[0][1], calls), ("rdap.py: not a small ASCII file", []))

    def test_ids(self):
        self.assertEqual(lookup.ids("no-such-user-sectop"), (65534, 65534))
        uid, gid = lookup.ids("root")
        self.assertEqual((uid, gid), (0, 0))


if __name__ == "__main__":
    unittest.main()
