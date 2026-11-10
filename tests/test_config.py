import os
import tempfile
import unittest

from core.config import Config, ConfigError, ModuleConfig, load, parse

UID = os.getuid()

GOOD = b"""
[core]
mask_public_ips = false

[modules.firewall]
enabled = true
interval = 3
journal_backlog = 50
"""


class TmpConf(unittest.TestCase):
    """Each test gets a private dir (0700) with config.toml (0644)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = os.path.join(self._tmp.name, "sectop")
        os.mkdir(self.dir, 0o700)
        self.path = os.path.join(self.dir, "config.toml")

    def tearDown(self):
        os.chmod(self.dir, 0o700)
        self._tmp.cleanup()

    def write(self, data: bytes, mode: int = 0o644) -> None:
        with open(self.path, "wb") as f:
            f.write(data)
        os.chmod(self.path, mode)

    def assertRefused(self, uid: int = UID):
        with self.assertRaises(ConfigError):
            load(self.path, owner_uid=uid)


class TestLoad(TmpConf):
    def test_missing_file(self):
        self.assertEqual(load(self.path, owner_uid=UID), Config())

    def test_missing_dir(self):
        self.assertEqual(load("/nonexistent-sectop/config.toml", owner_uid=UID), Config())

    def test_good(self):
        self.write(GOOD)
        c = load(self.path, owner_uid=UID)
        self.assertFalse(c.mask_public_ips)
        self.assertTrue(c.console_palette)                   # default
        fw = c.module("firewall")
        self.assertEqual(fw, ModuleConfig(True, 3.0, {"journal_backlog": 50}))
        self.assertIsInstance(fw.interval, float)

    def test_console_palette_off(self):
        self.write(b"[core]\nconsole_palette = false\n")
        self.assertFalse(load(self.path, owner_uid=UID).console_palette)

    def test_unknown_module_defaults(self):
        self.write(GOOD)
        self.assertEqual(load(self.path, owner_uid=UID).module("other"), ModuleConfig())

    def test_file_group_or_other_writable(self):
        for mode in (0o664, 0o646):
            self.write(GOOD, mode)
            self.assertRefused()

    def test_dir_writable(self):
        self.write(GOOD)
        os.chmod(self.dir, 0o777)
        self.assertRefused()

    def test_wrong_owner(self):
        self.write(GOOD)
        self.assertRefused(uid=UID + 1)

    def test_file_symlink(self):
        real = os.path.join(self.dir, "real.toml")
        with open(real, "wb") as f:
            f.write(GOOD)
        os.symlink(real, self.path)
        self.assertRefused()

    def test_dir_symlink(self):
        link = os.path.join(self._tmp.name, "link")
        os.symlink(self.dir, link)
        self.write(GOOD)
        with self.assertRaises(ConfigError):
            load(os.path.join(link, "config.toml"), owner_uid=UID)

    def test_not_regular(self):
        os.mkdir(self.path)
        self.assertRefused()

    def test_fifo_no_block(self):
        os.mkfifo(self.path, 0o644)
        self.assertRefused()

    def test_too_big(self):
        self.write(b"# " + b"x" * (64 * 1024) + b"\n")
        self.assertRefused()


class TestParse(unittest.TestCase):
    def bad(self, data: bytes):
        with self.assertRaises(ConfigError, msg=data):
            parse(data)

    def test_empty(self):
        self.assertEqual(parse(b""), Config())

    def test_syntax_and_encoding(self):
        self.bad(b"[core\n")
        self.bad(b"\xff\xfe")

    def test_unknown(self):
        self.bad(b"[colors]\n")
        self.bad(b"[core]\nmask_public_ip = true\n")    # typo

    def test_types(self):
        self.bad(b'[core]\nmask_public_ips = "yes"\n')
        self.bad(b"[core]\nconsole_palette = 1\n")
        self.bad(b"core = 1\n")
        self.bad(b"modules = 1\n")
        self.bad(b"[modules]\nfirewall = 1\n")
        self.bad(b"[modules.firewall]\nenabled = 1\n")

    def test_interval(self):
        for v in (b"0.5", b"true", b'"2"', b"inf", b"nan", b"-3"):
            self.bad(b"[modules.firewall]\ninterval = " + v + b"\n")
        c = parse(b"[modules.firewall]\ninterval = 1\n")
        self.assertEqual(c.module("firewall").interval, 1.0)

    def test_module_name(self):
        self.bad(b'[modules."Fire-Wall"]\n')

    def test_disabled(self):
        c = parse(b"[modules.firewall]\nenabled = false\n")
        self.assertFalse(c.module("firewall").enabled)


if __name__ == "__main__":
    unittest.main()
