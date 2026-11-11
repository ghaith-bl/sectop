import os
import tempfile
import unittest

from core import oui

OUI = (os.path.join(os.path.dirname(__file__), "fixtures", "oui.txt"),)
NONE = ("/nonexistent/oui.txt",)


class TestOui(unittest.TestCase):
    def setUp(self):
        oui._cache.clear()

    def test_parts_of_the_kernel_field(self):
        self.assertEqual(oui.parts("ff:ff:ff:ff:ff:ff:00:00:01:aa:bb:cc:08:00"),
                         ("ff:ff:ff:ff:ff:ff", "00:00:01:aa:bb:cc", "0800"))
        self.assertEqual(oui.parts("ff:ff:ff:ff:ff:ff:00:00:01:aa:bb:cc:86:dd".upper())[1],
                         "00:00:01:aa:bb:cc")
        for bad in ("", "ff:ff", "ff:ff:ff:ff:ff:ff:00:00:01:aa:bb:cc:08:zz",
                    "ff:ff:ff:ff:ff:ff:00:00:01:aa:bb:cc:08:00:00"):
            self.assertIsNone(oui.parts(bad), bad)

    def test_kind(self):
        self.assertEqual(oui.kind("ff:ff:ff:ff:ff:ff"), "broadcast")
        self.assertEqual(oui.kind("01:00:5e:00:00:fb"), "multicast")   # mDNS group
        self.assertEqual(oui.kind("33:33:00:00:00:01"), "multicast")   # IPv6 group
        self.assertEqual(oui.kind("52:54:00:12:34:56"), "local")       # KVM guest
        self.assertEqual(oui.kind("02:00:00:00:00:01"), "local")       # random wifi MAC
        self.assertEqual(oui.kind("00:00:01:aa:bb:cc"), "global")
        self.assertIsNone(oui.kind("00:00:01:aa:bb"))
        self.assertIsNone(oui.kind("00-00-01-aa-bb-cc"))

    def test_maker_from_the_list(self):
        self.assertEqual(oui.maker("00:00:01:aa:bb:cc", OUI), "Example Maker Co., Ltd.")
        self.assertEqual(oui.maker("00:00:03:00:00:01", OUI), "Test Devices Inc.")
        self.assertIsNone(oui.maker("00:00:09:00:00:01", OUI))      # not in the list
        self.assertIsNone(oui.maker("52:54:00:00:00:01", OUI))      # local: never looked up
        self.assertIsNone(oui.maker("00:00:01:aa:bb:cc", NONE))     # no list

    def test_describe(self):
        self.assertEqual(oui.describe("00:00:01:aa:bb:cc", OUI), "Example Maker Co., Ltd.")
        self.assertEqual(oui.describe("ff:ff:ff:ff:ff:ff", OUI),
                         "broadcast (every device on the LAN)")
        self.assertEqual(oui.describe("01:00:5e:00:00:fb", OUI),
                         "multicast (a group address, no single device)")
        self.assertEqual(oui.describe("52:54:00:00:00:01", OUI),
                         "local address (random or virtual): no maker")
        self.assertEqual(oui.describe("00:00:09:00:00:01", OUI), "maker not in the list")
        self.assertEqual(oui.describe("00:00:01:aa:bb:cc", NONE),
                         "maker unknown: no OUI list (package hwdata or ieee-data)")
        self.assertEqual(oui.describe("nope", OUI), "-")

    def test_second_path_used_when_the_first_is_missing(self):
        self.assertEqual(oui.maker("00:00:01:aa:bb:cc", NONE + OUI), "Example Maker Co., Ltd.")

    def test_short_cell(self):
        self.assertEqual(oui.short("Example Maker Co., Ltd."), "Example Maker")
        self.assertEqual(oui.short("SAMPLE WIRELESS ELECTRONIC CO.,LTD"),
                         "SAMPLE WIRELESS ELECTRONIC")
        self.assertEqual(oui.short("Test Devices Inc."), "Test Devices")
        self.assertEqual(oui.short(None), "-")
        self.assertEqual(oui.cell("00:00:01:aa:bb:cc", OUI), "Example Maker")
        self.assertEqual(oui.cell("00:00:09:00:00:01", OUI), "?")
        self.assertEqual(oui.cell("52:54:00:00:00:01", OUI), "local mac")
        self.assertEqual(oui.cell(None, OUI), "-")

    def test_names_are_plain_ascii(self):
        """A maker name is untrusted text from a file: ASCII, no controls, capped."""
        name = "Gr\u00fc\u00dfe Ger\u00e4te\x1b[31m GmbH" + "x" * 100
        with tempfile.NamedTemporaryFile("wb", suffix=".txt", delete=False) as f:
            f.write(("\n00-00-07   (hex)\t\t" + name + "\n").encode())
        self.addCleanup(os.unlink, f.name)
        got = oui.maker("00:00:07:00:00:01", (f.name,))
        self.assertTrue(got.startswith("Grue Gerate [31m GmbH"), got)
        self.assertTrue(got.isascii() and got.isprintable())
        self.assertEqual(len(got), oui.NAME_MAX)

    def test_cached(self):
        oui.maker("00:00:01:aa:bb:cc", OUI)
        self.assertEqual(oui.maker("00:00:01:00:00:00", NONE + ()), None)
        self.assertEqual(oui.maker("00:00:01:00:00:00", OUI), "Example Maker Co., Ltd.")
        self.assertIn(("00:00:01", OUI), oui._cache)


if __name__ == "__main__":
    unittest.main()
