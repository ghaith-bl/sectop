import contextlib
import io
import ipaddress
import json
import os
import socket
import tempfile
import threading
import time
import unittest
import urllib.error

from core import lookup, rdap

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

    def test_main_closes_http_error(self):
        body = io.BytesIO(b"not found")
        err = urllib.error.HTTPError(rdap.BOOT[4], 404, "Not Found", {}, body)
        doc, _ = self.run_main("8.8.8.8", {rdap.BOOT[4]: err})
        self.assertEqual(doc["error"], "HTTPError: HTTP Error 404: Not Found")
        self.assertTrue(body.closed)

    def test_https_only_redirect(self):
        h = rdap.HttpsOnly()
        with self.assertRaises(urllib.error.HTTPError) as cm:
            h.redirect_request(None, None, 302, "Found", {}, "http://rdap.example/ip/1")
        cm.exception.close()                    # Python 3.14: ResourceWarning if left open


class Ask:
    def __init__(self, answer):
        self.answer, self.calls = answer, []

    def __call__(self, path, ip, timeout):
        self.calls.append((path, ip, timeout))
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer


def ok(doc):
    return json.dumps(doc) + "\n"


class TestLookup(unittest.TestCase):
    def go(self, answer, ip="8.8.8.8"):
        ask = Ask(answer)
        return lookup.lookup(ip, ask=ask), ask.calls

    def test_public(self):
        self.assertTrue(lookup.public("8.8.8.8"))
        self.assertTrue(lookup.public("2607:6bc0::10"))
        for ip in ("10.2.0.1", "100.85.0.1", "fe80::1", "fdeb:446c:912d:8da::2", "x", ""):
            self.assertFalse(lookup.public(ip), ip)

    def test_request_and_result(self):
        pairs, calls = self.go(ok({"ok": True, "fields": [["name", "GOGL"], ["org", "Google"]]}))
        self.assertEqual(calls, [("/run/sectop-whois.sock", "8.8.8.8", lookup.TIMEOUT)])
        self.assertEqual(pairs[:2], [("name", "GOGL"), ("org", "Google")])
        self.assertTrue(pairs[2][1].startswith("RDAP by sectop-whois.service"))

    def test_private_not_asked(self):
        pairs, calls = self.go(ok({}), ip="10.2.0.1")
        self.assertEqual((pairs, calls), ([("whois", "not a public address: no whois")], []))

    def test_errors(self):
        cases = (
            (FileNotFoundError(2, "No such file"), "/run/sectop-whois.sock missing"),
            (PermissionError(13, "Permission denied"), "/run/sectop-whois.sock: permission"),
            (TimeoutError("timed out"), "timeout after 12 s"),
            (ConnectionRefusedError(111, "Connection refused"), "/run/sectop-whois.sock: conn"),
            (OSError(5, "Input/output error"), "/run/sectop-whois.sock: Input/output error"),
            (ValueError("answer larger than 64 KiB"), "bad service answer: answer larger"),
            ("garbage\n", "bad service answer: "),
            ("", "bad service answer: no JSON object"),
            (ok({"ok": False, "error": "URLError: boom"}), "URLError: boom"),
            (ok({"ok": True, "fields": "x"}), "bad service answer: fields: list required"),
            (ok({"ok": True, "fields": [["a", 1]]}), "bad service answer: fields: [str, str]"),
        )
        for answer, want in cases:
            pairs, _ = self.go(answer)
            self.assertTrue(pairs[0][1].startswith(want), (pairs, want))
            self.assertEqual(pairs[0][0], "whois")

    def test_limits(self):
        fields = [[f"k{i}" + "x" * 50, "v" * 500] for i in range(30)]
        pairs, _ = self.go(ok({"ok": True, "fields": fields}))
        self.assertEqual(len(pairs), lookup.MAX_FIELDS + 1)          # + via
        self.assertEqual((len(pairs[0][0]), len(pairs[0][1])), (40, lookup.MAX_VALUE))


class TestSocket(unittest.TestCase):
    """ask() against a real unix socket, the service side played by rdap.main()."""

    def serve(self, handler):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "w.sock")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(srv.close)
        srv.bind(path)
        srv.listen(1)

        def run():
            conn, _ = srv.accept()
            with conn:
                handler(conn)

        t = threading.Thread(target=run, daemon=True)
        t.start()
        self.addCleanup(t.join, 5)
        return path

    def test_roundtrip_with_rdap_main(self):
        def handler(conn):
            stdin = conn.makefile("rb")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rdap.main([], get=lambda url: {rdap.BOOT[4]: BOOT4}.get(url, ARIN), stdin=stdin)
            conn.sendall(out.getvalue().encode())

        path = self.serve(handler)
        pairs = lookup.lookup("8.8.8.8", path=path)
        self.assertEqual(pairs[0], ("name", "GOGL"))
        self.assertEqual(pairs[-2][0], "source")

    def test_too_large_and_timeout(self):
        def big(conn):                                   # read the request first: a close
            conn.recv(64)                                # before ask() sent = EPIPE (race)
            conn.sendall(b"x" * (lookup.MAX_ANSWER + 10))

        path = self.serve(big)
        with self.assertRaises(ValueError):
            lookup.ask(path, "8.8.8.8", 5.0)
        ev = threading.Event()
        path = self.serve(lambda conn: ev.wait(5))
        self.addCleanup(ev.set)                          # runs before the join (LIFO)
        t0 = time.monotonic()
        with self.assertRaises(TimeoutError):
            lookup.ask(path, "8.8.8.8", 0.3)
        self.assertLess(time.monotonic() - t0, 2.0)

    def test_missing_socket(self):
        with self.assertRaises(FileNotFoundError):
            lookup.ask("/nonexistent/w.sock", "8.8.8.8", 1.0)


class TestRequest(unittest.TestCase):
    def test_request(self):
        self.assertEqual(rdap.request(io.BytesIO(b"8.8.8.8\n")), "8.8.8.8")
        self.assertEqual(rdap.request(io.BytesIO(b" 2607:6bc0::10 ")), "2607:6bc0::10")
        with self.assertRaises(ValueError):
            rdap.request(io.BytesIO(b"1" * 100 + b"\n"))
        with self.assertRaises(ValueError):                         # UnicodeDecodeError
            rdap.request(io.BytesIO(b"\xff\n"))

    def test_main_from_stdin(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rdap.main([], get=lambda url: {}, stdin=io.BytesIO(b"10.0.0.1\n"))
        self.assertEqual(json.loads(out.getvalue()),
                         {"ok": False, "error": "ValueError: not a public address"})


if __name__ == "__main__":
    unittest.main()
