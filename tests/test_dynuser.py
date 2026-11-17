import unittest

from core import dynuser


class TestDynuser(unittest.TestCase):
    def test_siphash_vector(self):
        # SipHash paper, appendix A: key 00..0f, message 00..0e
        self.assertEqual(dynuser.siphash24(bytes(range(15)), bytes(range(16))),
                         0xa129ca6149be45e5)
        self.assertEqual(dynuser.siphash24(b"", bytes(range(16))), 0x726fdb47dd0e0e31)

    def test_sectop_whois(self):
        # host 2026-11-17: hostfw lines of the whois service had uid 65258
        self.assertEqual(dynuser.hashed_uid("sectop-whois"), 65258)

    def test_range(self):
        for name in ("a", "systemd-coredump", "x" * 64):
            self.assertTrue(dynuser.DYNAMIC_MIN <= dynuser.hashed_uid(name) <= dynuser.DYNAMIC_MAX)


if __name__ == "__main__":
    unittest.main()
