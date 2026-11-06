"""deploy/, bin/ and install.sh agree with the code (users, paths, rights)."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from core import app, collector, lookup, netd, userd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEPLOY = os.path.join(ROOT, "deploy")
PREFIX = "/usr/local/lib/sectop/"
SERVICES = ("sectop.service", "sectop-net.service", "sectop-whois@.service",
            "sectop-user@.service")


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
        self.assertIn(["g", "sectop-feed", "-"], lines)
        self.assertNotIn("m", {ln[0] for ln in lines})        # members: install.sh only
        users = {ln[1]: ln[2] for ln in lines if ln[0] == "u"}
        self.assertEqual(users, {"sectop": "-:sectop", "sectop-net": "-:sectop"})
        self.assertEqual((app.COLLECTOR_USER, netd.NET_USER), ("sectop", "sectop-net"))
        c, n = svc("sectop.service"), svc("sectop-net.service")
        self.assertEqual((c["User"], c["Group"], n["User"], n["Group"]),
                         ("sectop", "sectop", "sectop-net", "sectop"))
        self.assertEqual(c["SupplementaryGroups"], f"systemd-journal {userd.GROUP}")
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
        for name in ("sectop.service", "sectop-whois@.service", "sectop-user@.service"):
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

    def test_proc_view(self):
        """Only the collector sees other users' processes (program card, 2026-10-26); the
        user helper sees its own user's (fd of the shared cgroup, 2026-11-03)."""
        self.assertEqual(svc("sectop.service")["ProtectProc"], "default")
        self.assertEqual(svc("sectop-user@.service")["ProtectProc"], "default")
        for name in ("sectop-net.service", "sectop-whois@.service"):
            self.assertEqual(svc(name)["ProtectProc"], "invisible", name)
        self.assertNotIn("CAP_SYS_PTRACE", svc("sectop.service").get("CapabilityBoundingSet",
                                                                      ""))

    def test_network(self):
        for name in ("sectop.service", "sectop-net.service"):
            s = svc(name)
            self.assertEqual((s["IPAddressDeny"], s["RestrictAddressFamilies"]),
                             ("any", "AF_UNIX AF_NETLINK"), name)
            self.assertNotIn("DynamicUser", s)
            self.assertNotIn("PrivateNetwork", s)           # ss / nft need the host netns
        h = svc("sectop-user@.service")
        self.assertEqual((h["IPAddressDeny"], h["RestrictAddressFamilies"], h["PrivateNetwork"]),
                         ("any", "AF_UNIX", "yes"))           # reads /proc only
        w = svc("sectop-whois@.service")
        self.assertNotIn("IPAddressDeny", w)
        self.assertEqual(w["RestrictAddressFamilies"], "AF_UNIX AF_INET AF_INET6")
        self.assertEqual((w["StandardInput"], w["StandardOutput"]), ("socket", "socket"))


    def test_user_helper(self):
        """sectop-user@<user>.service: runs as that user, its own runtime dir, and never
        RemoveIPC= (it would remove the login user's IPC objects on stop)."""
        h = svc("sectop-user@.service")
        self.assertEqual((h["User"], h["RuntimeDirectory"], h["RuntimeDirectoryMode"],
                          h["UMask"]), ("%i", "sectop-user/%i", "0750", "0027"))
        self.assertEqual(userd.USER_DIR, "/run/sectop-user")
        self.assertNotIn("RemoveIPC", h)
        self.assertEqual((h["Group"], userd.GROUP), ("sectop-feed", "sectop-feed"))
        self.assertNotIn("SupplementaryGroups", h)           # never group sectop
        self.assertEqual(svc("sectop.service")["RemoveIPC"], "yes")

    def test_restart_backoff(self):
        """2026-11-06: a helper that can never start was restarted every 5 s (169 times
        in 30 min). Long-running units back off to 5 min instead of giving up."""
        for name in ("sectop.service", "sectop-net.service", "sectop-user@.service"):
            s = svc(name)
            self.assertEqual((s["Restart"], s["RestartSec"], s["RestartSteps"],
                              s["RestartMaxDelaySec"]),
                             ("on-failure", "5s", "5", "5min"), name)

    def test_user_helper_hides_reader_paths(self):
        """2026-11-05 account split: the helper runs as the desktop user, who must not
        read the collector's state. Never a socket file in InaccessiblePaths=: SELinux
        refuses the bind mount over it (init_t mounton sock_file, 2026-11-06) and the
        unit fails with 226/NAMESPACE; the whois socket is guarded by its mode."""
        h = svc("sectop-user@.service")
        hidden = h["InaccessiblePaths"].split()
        self.assertEqual(hidden, ["-" + os.path.dirname(collector.STATE_PATH)])
        self.assertNotIn(lookup.SOCKET, " ".join(hidden))
        after = unit("sectop-user@.service")["Unit"]["After"][-1].split()
        self.assertEqual(after, ["sectop.service"])
        sock = {k: v[-1] for k, v in unit("sectop-whois.socket")["Socket"].items()}
        self.assertEqual((sock["SocketUser"], sock["SocketGroup"], sock["SocketMode"]),
                         ("root", "sectop", "0660"))


class TestLaunchers(unittest.TestCase):
    def run_bin(self, name, *args):
        return subprocess.run([sys.executable, "-I", "-B", os.path.join(ROOT, "bin", name),
                               *args], capture_output=True, text=True, timeout=30,
                              cwd="/")

    def test_entry_points(self):
        r = self.run_bin("sectop", "--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("usage: sectop [SCREEN]", r.stdout)
        for name in ("sectop-collector", "sectop-net", "sectop-user"):
            r = self.run_bin(name, "x")                         # args refused before anything
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn(f"usage: {name}", r.stderr)

    def test_executable_and_shebang(self):
        for name in ("sectop", "sectop-collector", "sectop-net", "sectop-user"):
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

    def test_defaults_only_when_missing(self):
        """deploy/{watch,posture}.toml -> /etc/sectop once; my edits are never replaced."""
        with open(os.path.join(ROOT, "install.sh"), encoding="ascii") as f:
            text = f.read()
        self.assertIn("local file=$CONF/$name.toml defaults=$DEST/deploy/$name.toml", text)
        guard = 'if [[ ! -e $file && ! -L $file ]]; then'
        put = 'install -m 0644 -o root -g root "$defaults" "$file"'
        self.assertIn(guard, text)
        self.assertLess(text.index(guard), text.index(put))
        writes = [ln.strip() for ln in text.splitlines()
                  if '"$file"' in ln and not ln.strip().startswith(("relabel", "elif"))]
        self.assertEqual(writes, [put])                             # the only write
        for name in ("watch", "posture"):
            self.assertIn(f"  put_default {name}\n", text)
            self.assertTrue(os.path.isfile(os.path.join(DEPLOY, f"{name}.toml")))
        self.assertLess(text.index("  install_code "), text.index("  check_conf"))   # DEST first

    def test_posture_admin_from_install_user(self):
        """deploy/posture.toml names no user: "@admin" in want lists, install.sh puts the
        sudo (admin) user there (2026-11-05). Comments keep the placeholder."""
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("no bash")
        from modules.posture import policy
        with open(os.path.join(DEPLOY, "posture.toml"), "rb") as f:
            raw = f.read()
        want = {c.id: c.want for c in policy.parse(raw, "posture.toml") if c.kind == "group"}
        for cid in ("wheel", "sectop-group", "mullvad-group"):
            self.assertEqual(want[cid], ("@admin",), cid)
        self.assertEqual(want["sectop-feed"], ())
        with open(os.path.join(ROOT, "install.sh"), encoding="ascii") as f:
            text = f.read()
        self.assertLess(text.index('  rm -rf "$TMP/new/tests"'),
                        text.index('  render_defaults "$TMP/new" "$user"'))
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, "deploy"))
            path = os.path.join(d, "deploy", "posture.toml")
            with open(path, "wb") as f:
                f.write(raw)
            script = ('die() { echo "$*"; exit 1; }\n'
                      + text[text.index("render_defaults() {"):].split("\n}\n", 1)[0]
                      + '\n}\nrender_defaults "$1" "$2"\n')
            r = subprocess.run([bash, "-c", script, "x", d, "admin"], capture_output=True,
                               text=True, timeout=30)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            with open(path, "rb") as f:
                done = f.read()
        want = {c.id: c.want for c in policy.parse(done, "posture.toml") if c.kind == "group"}
        for cid in ("wheel", "sectop-group", "mullvad-group"):
            self.assertEqual(want[cid], ("admin",), cid)
        self.assertIn(b'# "@admin": install.sh', done)                # comment untouched
        self.assertEqual(done.replace(b'"admin"', b'"@admin"'), raw)  # nothing else

    def test_desktop_user_option(self):
        """--desktop-user NAME: helper instance for NAME, admin (sudo user) in sectop."""
        with open(os.path.join(ROOT, "install.sh"), encoding="ascii") as f:
            text = f.read()
        self.assertIn('  install_users "$user"\n', text)          # admin: m <admin> sectop
        self.assertIn('  install_units "$desktop"\n', text)       # desktop: helper only
        self.assertIn('  check_desktop "$desktop" "$user"\n', text)
        self.assertLess(text.index('  check_desktop "$desktop"'), text.index("  preflight\n"))
        self.assertIn("printf 'm %s sectop\\n' \"$1\"", text)

    def test_installs_every_unit(self):
        with open(os.path.join(ROOT, "install.sh"), encoding="ascii") as f:
            text = f.read()
        units = sorted(n for n in os.listdir(DEPLOY) if n.endswith((".service", ".socket")))
        line = next(ln for ln in text.splitlines() if ln.startswith("UNITS=("))
        self.assertEqual(sorted(line[len("UNITS=("):-1].split()), units)


if __name__ == "__main__":
    unittest.main()
