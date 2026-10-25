import os
import tempfile
import unittest

from core.config import ConfigError
from modules.security import watch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULTS = os.path.join(ROOT, "deploy", "watch.toml")


def rule(cmd, sev="warn", rid="r", why="w"):
    return f'[[rule]]\nid = "{rid}"\nsev = "{sev}"\ncmd = "{cmd}"\nwhy = "{why}"\n'


def rules(*texts) -> tuple:
    return watch.parse("".join(texts).encode())


def sev(rs, exe, argv):
    r = watch.rate(rs, exe, argv)
    return r.sev if r else "ok"


class TestParse(unittest.TestCase):
    def test_rule(self):
        [r] = rules(rule("setenforce 0|[Pp]ermissive !-v", "crit", "selinux-permissive"))
        self.assertEqual((r.id, r.sev, r.prog, r.need, r.deny),
                         ("selinux-permissive", "crit", ("setenforce",),
                          (("0", "[Pp]ermissive"),), (("-v",),)))
        self.assertEqual(rules(), ())

    def test_errors(self):
        bad = [
            "[core]\n",                                               # unknown table
            "rule = 1\n",                                             # not tables
            rule("a").replace('why = "w"', 'why = "w"\nx = 1'),       # unknown key
            rule("a", rid="Bad"), rule("a", rid="-a"), rule("a", rid="a" * 33),
            rule("a") + rule("b"),                                    # duplicate id
            rule("a", sev="ok"), rule("a", sev="high"),
            rule(""), rule("   "), rule("!a b"), rule("a !"), rule("a b||c"), rule("a|"),
            rule("a " + " ".join("w" * 17)),                          # 17 words
            rule("a " + "b" * 200),
            rule("a", why=""), rule("a", why="x" * 121),
            rule("a\\u00e9"), rule("a", why="\\u00e9"),               # not ASCII
            "[[rule]\n",                                              # TOML error
        ]
        for text in bad:
            with self.subTest(text=text), self.assertRaises(ConfigError):
                watch.parse(text.encode())
        with self.assertRaises(ConfigError):
            watch.parse(b"\xff")
        with self.assertRaises(ConfigError):
            watch.parse("".join(rule("a", rid=f"r{i}") for i in range(201)).encode())

    def test_load(self):
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d, 0o755)
            path = os.path.join(d, "watch.toml")
            self.assertIsNone(watch.load(path, os.getuid()))            # missing: no rules
            with open(path, "w", encoding="ascii") as f:
                f.write(rule("a"))
            os.chmod(path, 0o644)
            self.assertEqual(len(watch.load(path, os.getuid())), 1)
            os.chmod(path, 0o664)
            with self.assertRaises(ConfigError):                         # group writable
                watch.load(path, os.getuid())
            os.chmod(path, 0o644)
            with self.assertRaises(ConfigError):                         # not root-owned
                watch.load(path, os.getuid() + 1)


class TestMatch(unittest.TestCase):
    def test_programs(self):
        self.assertEqual(watch.programs("/usr/bin/kmod", ["modprobe", "nvidia"]),
                         {"kmod", "modprobe"})
        self.assertEqual(watch.programs("/usr/bin/env", ["/usr/bin/env", "bash",
                                                         "/usr/local/sbin/hostfw", "observe"]),
                         {"env", "bash", "hostfw"})
        self.assertEqual(watch.programs("/usr/bin/bash", ["/bin/bash", "-e", "./hostfw.sh",
                                                          "apply"]),
                         {"bash", "hostfw.sh"})
        self.assertEqual(watch.programs("/usr/bin/env", ["env", "LC_ALL=C", "sysctl", "-a"]),
                         {"env", "sysctl"})
        self.assertEqual(watch.command("/usr/bin/env", ["/usr/bin/env", "bash",
                                                        "/usr/local/sbin/hostfw", "observe"]),
                         ["/usr/local/sbin/hostfw", "observe"])
        self.assertEqual(watch.command("/usr/bin/id", ["id"]), ["id"])
        self.assertEqual(watch.command("/usr/bin/bash", ["bash"]), ["bash"])

    def test_words(self):
        rs = rules(rule("systemctl stop|mask auditd|auditd.service !--dry-run", "crit"))
        argv = ["systemctl", "mask", "--now", "auditd.service"]
        self.assertEqual(sev(rs, "/usr/bin/systemctl", argv), "crit")
        self.assertEqual(sev(rs, "/usr/bin/systemctl", ["systemctl", "auditd", "stop"]),
                         "crit")                                                  # any order
        self.assertEqual(sev(rs, "/usr/bin/systemctl", argv + ["--dry-run"]), "ok")  # !word
        self.assertEqual(sev(rs, "/usr/bin/systemctl", ["systemctl", "stop", "sshd"]), "ok")
        self.assertEqual(sev(rs, "/usr/bin/systemd", ["systemd", "stop", "auditd"]), "ok")
        rs = rules(rule("usermod *wheel*", "crit"))
        self.assertEqual(sev(rs, "/usr/bin/usermod", ["usermod", "-aG", "wheel,video", "u"]),
                         "crit")                                                  # glob
        self.assertEqual(sev(rs, "/usr/bin/usermod", ["usermod", "-aG", "WHEEL", "u"]), "ok")
        rs = rules(rule("chmod ?*"))                                              # needs an arg
        self.assertEqual(sev(rs, "/usr/bin/chmod", ["chmod"]), "ok")

    def test_highest_wins_then_first(self):
        rs = rules(rule("systemctl ?*", "info", "a"), rule("systemctl stop", "warn", "b"),
                   rule("systemctl stop", "warn", "c"), rule("systemctl stop auditd", "crit", "d"))
        self.assertEqual(watch.rate(rs, "", ["systemctl", "stop", "x"]).id, "b")
        self.assertEqual(watch.rate(rs, "", ["systemctl", "stop", "auditd"]).id, "d")
        self.assertEqual(watch.rate(rs, "", ["systemctl", "status"]).id, "a")
        self.assertIsNone(watch.rate((), "", ["systemctl", "stop"]))


class TestDefaults(unittest.TestCase):
    """deploy/watch.toml: what install.sh puts in /etc/sectop/watch.toml."""

    @classmethod
    def setUpClass(cls):
        with open(DEFAULTS, "rb") as f:
            data = f.read()
        data.decode("ascii")                                       # ASCII only
        cls.rules = watch.parse(data, DEFAULTS)

    def test_examples(self):
        cases = [
            # host 2026-10-25, sudo ./install.sh
            ("/usr/bin/install", ["install", "-m", "0644", "-o", "root", "-g", "root",
                                  "a", "/etc/systemd/system/sectop.service"], "info"),
            ("/usr/bin/systemctl", ["systemctl", "restart", "sectop-net.service"], "info"),
            ("/usr/bin/systemctl", ["systemctl", "daemon-reload"], "info"),
            ("/usr/bin/systemctl", ["systemctl", "is-active", "--quiet", "sectop.service"],
             "ok"),
            ("/usr/bin/restorecon", ["restorecon", "-R", "/usr/local/lib/sectop"], "info"),
            ("/usr/bin/chmod", ["chmod", "0644", "/etc/sectop/config.toml"], "info"),
            ("/usr/bin/systemd-sysusers", ["systemd-sysusers", "/etc/sysusers.d/sectop.conf"],
             "info"),
            ("/usr/bin/sudo", ["sudo", "-u", "null", "git", "-C", "/x", "log", "-1"], "ok"),
            ("/usr/bin/id", ["id", "sectop"], "ok"),
            ("/usr/bin/python3.14", ["/usr/bin/python3", "-I", "-m", "compileall", "-q", "x"],
             "ok"),
            # host 2026-10-25, nvidia-modprobe
            ("/usr/bin/kmod", ["modprobe", "nvidia"], "warn"),
            ("/usr/bin/nvidia-modprobe", ["/usr/bin/nvidia-modprobe"], "ok"),
            ("/usr/bin/kmod", ["modprobe", "-c"], "ok"),
            # SELinux, audit
            ("/usr/bin/setenforce", ["setenforce", "0"], "crit"),
            ("/usr/bin/setenforce", ["setenforce", "Permissive"], "crit"),
            ("/usr/bin/setenforce", ["setenforce", "1"], "ok"),
            ("/usr/bin/semanage", ["semanage", "permissive", "-a", "httpd_t"], "crit"),
            ("/usr/bin/semanage", ["semanage", "boolean", "-l"], "ok"),
            ("/usr/bin/setsebool", ["setsebool", "-P", "x", "on"], "warn"),
            ("/usr/bin/auditctl", ["auditctl", "-e", "0"], "crit"),
            ("/usr/bin/auditctl", ["auditctl", "-D"], "crit"),
            ("/usr/bin/auditctl", ["auditctl", "-w", "/etc/x", "-p", "wa"], "warn"),
            ("/usr/bin/auditctl", ["auditctl", "-l"], "ok"),
            ("/usr/bin/bash", ["/bin/sh", "/usr/sbin/service", "auditd", "stop"], "crit"),
            ("/usr/bin/rpm-ostree", ["rpm-ostree", "kargs", "--append=selinux=0"], "crit"),
            ("/usr/bin/rpm-ostree", ["rpm-ostree", "kargs", "--delete=audit=0"], "warn"),
            ("/usr/bin/rpm-ostree", ["rpm-ostree", "kargs"], "ok"),
            ("/usr/bin/rpm-ostree", ["rpm-ostree", "install", "htop"], "warn"),
            ("/usr/bin/rpm-ostree", ["rpm-ostree", "upgrade"], "info"),
            ("/usr/bin/rpm-ostree", ["rpm-ostree", "status"], "ok"),
            # firewall
            ("/usr/bin/systemctl", ["systemctl", "disable", "--now", "hostfw.service"], "crit"),
            ("/usr/bin/systemctl", ["systemctl", "stop", "firewalld"], "crit"),
            ("/usr/bin/systemctl", ["systemctl", "mask", "nftables.service"], "warn"),
            ("/usr/bin/systemctl", ["systemctl", "stop", "hostfw-rollback.timer",
                                    "hostfw-rollback.service"], "ok"),       # hostfw confirm
            ("/usr/bin/env", ["/usr/bin/env", "bash", "/usr/local/sbin/hostfw", "observe"],
             "crit"),
            ("/usr/bin/bash", ["bash", "/usr/local/sbin/hostfw", "enforce"], "info"),
            ("/usr/bin/bash", ["/bin/bash", "./hostfw.sh", "router-open", "10"], "warn"),
            ("/usr/bin/bash", ["bash", "/usr/local/sbin/hostfw", "status"], "ok"),
            ("/usr/bin/nft", ["nft", "delete", "table", "inet", "hostfw"], "crit"),
            ("/usr/bin/nft", ["nft", "flush", "ruleset"], "crit"),
            ("/usr/bin/nft", ["nft", "flush", "chain", "inet", "hostfw", "enforce"], "warn"),
            ("/usr/bin/nft", ["nft", "-c", "-f", "/etc/hostfw/hostfw.nft"], "ok"),
            ("/usr/bin/nft", ["nft", "-j", "list", "set", "inet", "hostfw", "wg_fwmark"], "ok"),
            ("/usr/bin/firewall-cmd", ["firewall-cmd", "--set-default-zone=public"], "crit"),
            ("/usr/bin/firewall-cmd", ["firewall-cmd", "--set-default-zone=drop"], "warn"),
            ("/usr/bin/firewall-cmd", ["firewall-cmd", "--zone=drop", "--list-all"], "ok"),
            ("/usr/bin/firewall-cmd", ["firewall-cmd", "--state"], "ok"),
            ("/usr/bin/firewall-cmd", ["firewall-cmd", "--zone=drop", "--remove-rich-rule=x"],
             "warn"),
            # accounts, sudo
            ("/usr/bin/usermod", ["usermod", "-aG", "wheel", "bob"], "crit"),
            ("/usr/bin/gpasswd", ["gpasswd", "-d", "bob", "wheel"], "warn"),
            ("/usr/bin/usermod", ["usermod", "-s", "/bin/zsh", "bob"], "warn"),
            ("/usr/bin/passwd", ["passwd"], "warn"),
            ("/usr/bin/chage", ["chage", "-l", "null"], "ok"),
            ("/usr/bin/visudo", ["visudo", "-c"], "ok"),
            ("/usr/bin/tee", ["tee", "/etc/sudoers.d/x"], "warn"),
            ("/usr/bin/sed", ["sed", "-i", "s/a/b/", "/etc/pam.d/sudo"], "warn"),
            ("/usr/bin/sed", ["sed", "-n", "p", "/etc/passwd"], "ok"),
            ("/usr/bin/cat", ["cat", "/etc/shadow"], "ok"),
            # files
            ("/usr/bin/chmod", ["chmod", "4755", "/tmp/x"], "warn"),
            ("/usr/bin/chmod", ["chmod", "u+s", "/tmp/x"], "warn"),
            ("/usr/bin/chmod", ["chmod", "0755", "/tmp/x"], "info"),
            ("/usr/bin/rm", ["rm", "-f", "/var/log/audit/audit.log"], "warn"),
            ("/usr/bin/rm", ["rm", "-rf", "/usr/local/lib/sectop.old"], "info"),
            ("/usr/bin/journalctl", ["journalctl", "--vacuum-time=1d"], "warn"),
            ("/usr/bin/journalctl", ["journalctl", "-b", "-u", "sectop"], "ok"),
            ("/usr/bin/sysctl", ["sysctl", "-w", "net.ipv4.ip_forward=1"], "warn"),
            ("/usr/bin/sysctl", ["sysctl", "--system"], "info"),
            ("/usr/bin/sysctl", ["sysctl", "net.ipv4.ip_forward"], "ok"),
            ("/usr/bin/mount", ["mount"], "ok"),
            ("/usr/bin/mount", ["mount", "/dev/sdb1", "/mnt"], "warn"),
        ]
        for exe, argv, want in cases:
            with self.subTest(argv=argv):
                self.assertEqual(sev(self.rules, exe, argv), want)

    def test_levels(self):
        count = {s: sum(r.sev == s for r in self.rules) for s in watch.SEVS}
        self.assertEqual(count, {"crit": 15, "warn": 33, "info": 9})
