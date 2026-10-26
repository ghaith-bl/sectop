import unittest

from core.sanitize import clean, display, mask_ips, mask_secrets, truncate

# Real hostfw kernel lines (public IPs are public DNS resolvers).
LEAK = ("HFW-OUT-LEAK: IN= OUT=wlo1 SRC=192.168.8.102 DST=149.112.112.11 LEN=60 "
        "PROTO=TCP SPT=46866 DPT=443 SYN UID=1000")
NOISE = ("HFW-IN-NOISE: IN=wlo1 OUT= MAC=ff:ff:ff:ff:ff:ff:02:00:00:00:00:09:08:00 "
         "SRC=192.168.8.227 DST=255.255.255.255 PROTO=UDP SPT=49152 DPT=25860")
LAN6 = ("HFW-OUT-LAN: IN= OUT=wlo1 SRC=fe80:0000:0000:0000:40ae:f0a0:e9b4:cc29 "
        "DST=ff02:0000:0000:0000:0000:0001:ff00:0001 PROTO=ICMPv6 TYPE=131")


class TestClean(unittest.TestCase):
    def test_plain_unchanged(self):
        self.assertEqual(clean("wg0-mullvad up"), "wg0-mullvad up")

    def test_non_ascii_kept(self):
        self.assertEqual(clean("caf\u00e9"), "caf\u00e9")

    def test_escape_sequence(self):
        self.assertEqual(clean("\x1b[31mred\x1b[0m"), "?[31mred?[0m")

    def test_c0_del_c1(self):
        self.assertEqual(clean("a\x00b\nc\rd\x7fe\x9bf"), "a?b?c?d?e?f")

    def test_spaces(self):
        self.assertEqual(clean("a\tb\u00a0c"), "a b c")

    def test_format_and_separators(self):
        # bidi override, zero-width space, line separator, BOM
        self.assertEqual(clean("a\u202eb\u200bc\u2028d\ufeff"), "a?b?c?d?")

    def test_surrogate(self):
        self.assertEqual(clean("x\udc80y"), "x?y")

    def test_non_str(self):
        self.assertEqual(clean(42), "42")
        self.assertEqual(clean(None), "None")


class TestMask(unittest.TestCase):
    def test_public_v4(self):
        self.assertEqual(mask_ips("DST=149.112.112.11 LEN=60"), "DST=149.112.x.x LEN=60")

    def test_v4_port(self):
        self.assertEqual(mask_ips("8.8.8.8:443"), "8.8.x.x:443")

    def test_v4_after_colon(self):
        self.assertEqual(mask_ips("src:8.8.8.8"), "src:8.8.x.x")

    def test_v4_sentence_end(self):
        self.assertEqual(mask_ips("to 8.8.8.8."), "to 8.8.x.x.")

    def test_non_public_v4_kept(self):
        s = "192.168.8.102 10.2.0.1 100.85.0.1 127.0.0.1 169.254.1.1 255.255.255.255 224.0.0.251 192.0.2.1"
        self.assertEqual(mask_ips(s), s)

    def test_invalid_v4_kept(self):
        for s in ("999.1.1.1", "1.2.3.4.5", "v8.8.8.8", "8.8.8.8a"):
            self.assertEqual(mask_ips(s), s, s)

    def test_public_v6(self):
        self.assertEqual(mask_ips("dst 2606:4700::1111 ok"), "dst 2606:4700::x ok")

    def test_v6_bracket_port(self):
        self.assertEqual(mask_ips("[2606:4700:4700::1111]:443"), "[2606:4700::x]:443")

    def test_v6_expanded(self):
        self.assertEqual(mask_ips("SRC=2a02:0000:0000:0000:0000:0000:0000:0001"),
                         "SRC=2a02:0::x")

    def test_v6_sentence_end(self):
        self.assertEqual(mask_ips("to 2606:4700::1111."), "to 2606:4700::x.")

    def test_v4_mapped(self):
        self.assertEqual(mask_ips("::ffff:8.8.8.8"), "::ffff:8.8.x.x")
        self.assertEqual(mask_ips("::ffff:192.168.1.1"), "::ffff:192.168.1.1")

    def test_non_public_v6_kept(self):
        s = "fe80::1 ff02::1:2 ::1 2001:db8::1 fd00::1"
        self.assertEqual(mask_ips(s), s)

    def test_mac_time_kept(self):
        for s in ("ff:ff:ff:ff:ff:ff:02:00:00:00:00:09:08:00", "13:26:30",
                  "2026-10-19T13:26:20+03:00", "02:00:00:00:00:09"):
            self.assertEqual(mask_ips(s), s, s)

    def test_real_lines(self):
        self.assertEqual(mask_ips(LEAK), LEAK.replace("149.112.112.11", "149.112.x.x"))
        self.assertEqual(mask_ips(NOISE), NOISE)
        self.assertEqual(mask_ips(LAN6), LAN6)


class TestSecrets(unittest.TestCase):
    def test_flags(self):
        for flag in ("--password", "--passwd", "--token", "--secret", "--api-key", "--TOKEN"):
            self.assertEqual(mask_secrets(f"x {flag} s3cr3t y"), f"x {flag} *** y")
            self.assertEqual(mask_secrets(f"x {flag}=s3cr3t y"), f"x {flag}=*** y")
        self.assertEqual(mask_secrets("--token-file /etc/t --passwords x"),
                         "--token-file /etc/t --passwords x")                 # other flags

    def test_url_userinfo(self):
        self.assertEqual(mask_secrets("git clone https://bob:pa55@host/r.git"),
                         "git clone https://bob:***@host/r.git")
        self.assertEqual(mask_secrets("ssh://bob@host https://host:443/x"),
                         "ssh://bob@host https://host:443/x")                 # no password

    def test_env(self):
        self.assertEqual(mask_secrets("env DB_PASSWORD=a GH_TOKEN=b AWS_SECRET=c X=d"),
                         "env DB_PASSWORD=*** GH_TOKEN=*** AWS_SECRET=*** X=d")
        self.assertEqual(mask_secrets("PASSWORD=a password=b"), "PASSWORD=*** password=b")

    def test_plain_unchanged(self):
        for s in ("sudo dnf upgrade", "rpm-ostree status", "", "--token"):
            self.assertEqual(mask_secrets(s), s)


class TestDisplay(unittest.TestCase):
    def test_clean_then_mask(self):
        self.assertEqual(display("\x1b]8.8.8.8"), "?]8.8.x.x")

    def test_no_mask(self):
        self.assertEqual(display("8.8.8.8", mask=False), "8.8.8.8")

    def test_mask_before_truncate(self):
        out = display("ip 149.112.112.11", width=12)
        self.assertEqual(out, "ip 149.112.~")

    def test_secrets(self):
        line = "curl https://me:hunter2@example.org/x --token abc API_TOKEN=xyz 8.8.8.8"
        self.assertEqual(display(line), "curl https://me:***@example.org/x --token *** "
                                        "API_TOKEN=*** 8.8.x.x")
        self.assertEqual(display(line, mask=False), line)                       # m: raw
        self.assertEqual(display(line, mask=False, secrets=True),
                         "curl https://me:***@example.org/x --token *** API_TOKEN=*** 8.8.8.8")
        self.assertEqual(display(line, secrets=False), line.replace("8.8.8.8", "8.8.x.x"))

    def test_truncate(self):
        self.assertEqual(truncate("abcdef", 6), "abcdef")
        self.assertEqual(truncate("abcdef", 4), "abc~")
        self.assertEqual(truncate("abcdef", 0), "")


if __name__ == "__main__":
    unittest.main()
