"""deploy/, bin/ and install.sh agree with the code (users, paths, rights)."""

import os
import shutil
import subprocess
import sys
import unittest

from core import app, collector, lookup, netd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEPLOY = os.path.join(ROOT, "deploy")
PREFIX = "/usr/local/lib/sectop/"
SERVICES = ("sectop.service", "sectop-net.service", "sectop-whois@.service")


def unit(name: str) -> dict:
    """systemd unit file -> {section: {key: [values]}} (repeated keys kept)."""
    out, sec = {}, None
    with open(os.path.join(DEPLOY, name), encoding="ascii") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("["):
                sec = out.setdefault(line.strip("[]"), {})
                continue
            key, _, value = line.partition("=")
            sec.setdefault(key, []).append(value)
    return out


def svc(name: str) -> dict:
    return {k: v[-1] for k, v in unit(name)["Service"].items()}


class TestUnits(unittest.TestCase):
    def test_users_match_code(self):
        with open(os.path.join(DEPLOY, "sectop.sysusers"), encoding="ascii") as f:
            lines = [ln.split() for ln in f if ln.strip() and not ln.startswith("#")]
        self.assertIn(["g", "sectop", "-"], lines)
        users = {ln[1]: ln[2] for ln in lines if ln[0] == "u"}
        self.assertEqual(users, {"sectop": "-:sectop", "sectop-net": "-:sectop"})
        self.assertEqual((app.COLLECTOR_USER, netd.NET_USER), ("sectop", "sectop-net"))
        c, n = svc("sectop.service"), svc("sectop-net.service")
        self.assertEqual((c["User"], c["Group"], n["User"], n["Group"]),
                         ("sectop", "sectop", "sectop-net", "sectop"))
        self.assertEqual(c["SupplementaryGroups"], "systemd-journal")
        self.assertNotIn("SupplementaryGroups", n)
        self.assertEqual(svc("sectop-whois@.service")["DynamicUser"], "yes")

    def test_paths_match_code(self):
        c, n = svc("sectop.service"), svc("sectop-net.service")
        self.assertEqual(os.path.dirname(collector.STATE_PATH), "/run/" + c["RuntimeDirectory"])
        self.assertEqual(app.STATE_PATH, collector.STATE_PATH)
        self.assertEqual(netd.NET_DIR, "/run/" + n["RuntimeDirectory"])
        for s in (c, n):
            self.assertEqual((s["RuntimeDirectoryMode"], s["UMask"]), ("0750", "0027"))
        sock = {k: v[-1] for k, v in unit("sectop-whois.socket")["Socket"].items()}
        self.assertEqual(sock["ListenStream"], lookup.SOCKET)
        self.assertEqual((sock["SocketUser"], sock["SocketGroup"], sock["SocketMode"],
                          sock["Accept"]), ("root", "sectop", "0660", "yes"))

    def test_exec_targets_exist(self):
        for name in SERVICES:
            argv = svc(name)["ExecStart"].split()
            self.assertEqual(argv[:3], ["/usr/bin/python3", "-I", "-B"], name)
            self.assertTrue(argv[3].startswith(PREFIX), name)
            self.assertTrue(os.path.isfile(os.path.join(ROOT, argv[3][len(PREFIX):])), name)

    def test_capabilities(self):
        n = svc("sectop-net.service")
        self.assertEqual((n["AmbientCapabilities"], n["CapabilityBoundingSet"]),
                         ("CAP_NET_ADMIN", "CAP_NET_ADMIN"))
        for name in ("sectop.service", "sectop-whois@.service"):
            s = svc(name)
            self.assertEqual((s["AmbientCapabilities"], s["CapabilityBoundingSet"]), ("", ""),
                             name)

    def test_sandbox_common(self):
        want = {"NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "yes",
                "PrivateTmp": "yes", "PrivateDevices": "yes", "ProtectKernelModules": "yes",
                "ProtectKernelTunables": "yes", "ProtectKernelLogs": "yes",
                "ProtectControlGroups": "yes", "RestrictSUIDSGID": "yes",
                "MemoryDenyWriteExecute": "yes", "SystemCallArchitectures": "native",
                "SystemCallErrorNumber": "EPERM", "LockPersonality": "yes"}
        for name in SERVICES:
            s = svc(name)
            for k, v in want.items():
                self.assertEqual(s.get(k), v, f"{name} {k}")
            self.assertEqual(unit(name)["Service"]["SystemCallFilter"][0], "@system-service")

    def test_network(self):
        for name in ("sectop.service", "sectop-net.service"):
            s = svc(name)
            self.assertEqual((s["IPAddressDeny"], s["RestrictAddressFamilies"]),
                             ("any", "AF_UNIX AF_NETLINK"), name)
            self.assertNotIn("DynamicUser", s)
            self.assertNotIn("PrivateNetwork", s)           # ss / nft need the host netns
        w = svc("sectop-whois@.service")
        self.assertNotIn("IPAddressDeny", w)
        self.assertEqual(w["RestrictAddressFamilies"], "AF_UNIX AF_INET AF_INET6")
        self.assertEqual((w["StandardInput"], w["StandardOutput"]), ("socket", "socket"))


class TestLaunchers(unittest.TestCase):
    def run_bin(self, name, *args):
        return subprocess.run([sys.executable, "-I", "-B", os.path.join(ROOT, "bin", name),
                               *args], capture_output=True, text=True, timeout=30,
                              cwd="/")

    def test_entry_points(self):
        r = self.run_bin("sectop", "--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("usage: sectop [SCREEN]", r.stdout)
        for name in ("sectop-collector", "sectop-net"):
            r = self.run_bin(name, "x")                         # args refused before anything
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn(f"usage: {name}", r.stderr)

    def test_executable_and_shebang(self):
        for name in ("sectop", "sectop-collector", "sectop-net"):
            p = os.path.join(ROOT, "bin", name)
            self.assertTrue(os.access(p, os.X_OK), name)
            with open(p, encoding="ascii") as f:
                self.assertEqual(f.readline(), "#!/usr/bin/python3 -IB\n")


class TestInstallScript(unittest.TestCase):
    def test_bash_syntax(self):
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("no bash")
        p = os.path.join(ROOT, "install.sh")
        r = subprocess.run([bash, "-n", p], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.access(p, os.X_OK))

    def test_creates_dirs_it_writes_to(self):
        """Silverblue has no /etc/sysusers.d (2026-10-20 install: 'No such file')."""
        with open(os.path.join(ROOT, "install.sh"), encoding="ascii") as f:
            text = f.read()
        for var, write in (("SYSUSERS", '> "$SYSUSERS.tmp"'), ("BIN", 'ln -sfn')):
            mkdir = f'install -d -m 0755 "$(dirname "${var}")"'
            self.assertIn(mkdir, text, var)
            self.assertLess(text.index(mkdir), text.index(write), var)

    def test_installs_every_unit(self):
        with open(os.path.join(ROOT, "install.sh"), encoding="ascii") as f:
            text = f.read()
        units = sorted(n for n in os.listdir(DEPLOY) if n.endswith((".service", ".socket")))
        line = next(ln for ln in text.splitlines() if ln.startswith("UNITS=("))
        self.assertEqual(sorted(line[len("UNITS=("):-1].split()), units)


if __name__ == "__main__":
    unittest.main()
