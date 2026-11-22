import json
import os
import stat
import tempfile
import unittest

import modules.posture as pos
from core import journal as corejournal
from core.config import ConfigError
from core.module import Context, check_module, validate
from core.run import Result
from core.screens import SCREENS, find
from modules.posture import checks as kinds
from modules.posture import policy

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEPLOY = os.path.join(ROOT, "deploy", "posture.toml")
DAY = 86400.0
NOW = 1792900000.0                       # 2026-10-26
BOOTED = 1792828294.0                    # host 2026-10-26: rpm-ostree booted timestamp

# /proc/net of my host 2026-10-26 (ss -Htuln): libvirt dnsmasq 192.168.122.1:53 tcp + udp
# and 0.0.0.0:67 (bound to virbr0), resolved 127.0.0.53 / .54:53, chronyd 127.0.0.1 / ::1
# :323, WireGuard (VPN tunnel) 0.0.0.0 / [::]:51250 (a kernel socket, but with an inode: 51638,
# checked 2026-10-26); plus one connected UDP socket (not a listener) and an established
# TCP connection.
HEAD = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
ROW = "  {}: {} {} {} 00000000:00000000 00:00000000 00000000 {:>5}        0 {}\n"
Z4, Z6 = "00000000:0000", "00000000000000000000000000000000:0000"
TCP = HEAD + "".join(ROW.format(i, a, Z4, st, uid, ino) for i, (a, st, uid, ino) in enumerate((
    ("3600007F:0035", "0A", 193, 4101), ("3500007F:0035", "0A", 193, 4102),
    ("017AA8C0:0035", "0A", 0, 4103), ("6600A8C0:B7E2", "01", 1000, 4104))))
TCP6 = HEAD
UDP = HEAD + "".join(ROW.format(i, a, r, st, uid, ino) for i, (a, r, st, uid, ino) in enumerate((
    ("017AA8C0:0035", Z4, "07", 0, 4201), ("3600007F:0035", Z4, "07", 193, 4202),
    ("3500007F:0035", Z4, "07", 193, 4203), ("00000000:0043", Z4, "07", 0, 4204),
    ("0100007F:0143", Z4, "07", 994, 4205), ("00000000:C832", Z4, "07", 0, 51638),
    ("6600A8C0:9C40", "0100A8C0:0035", "01", 1000, 4206))))
UDP6 = HEAD + "".join(ROW.format(i, a, Z6, "07", uid, ino) for i, (a, uid, ino) in enumerate((
    ("00000000000000000000000001000000:0143", 994, 4301),
    ("00000000000000000000000000000000:C832", 0, 51639))))
# ss -Htuln --cgroup of the same sockets (format of my host 2026-10-30, ss -Htulnp; the
# cgroup column as in tests/fixtures/firewall/ss-cgroup.txt). WireGuard lines without
# a cgroup here (owner of a kernel WireGuard socket not checked on the host).
SS = ("udp   UNCONN 0      0       192.168.122.1%virbr0:53        0.0.0.0:*    "
      "cgroup:/system.slice/virtnetworkd.service\n"
      "udp   UNCONN 0      0          127.0.0.54:53        0.0.0.0:*    "
      "cgroup:/system.slice/systemd-resolved.service\n"
      "udp   UNCONN 0      0        0.0.0.0%virbr0:67        0.0.0.0:*    "
      "cgroup:/system.slice/virtnetworkd.service\n"
      "udp   UNCONN 0      0             0.0.0.0:51250      0.0.0.0:*\n"
      "udp   UNCONN 0      0                   *:51250            *:*\n"
      "tcp   LISTEN 0      32      192.168.122.1%virbr0:53        0.0.0.0:*    "
      "cgroup:/system.slice/virtnetworkd.service\n")
# Mullvad with DAITA (host 2026-10-30): WireGuard in userspace, the socket is the daemon's
SS_DAITA = SS.replace("0.0.0.0:51250      0.0.0.0:*", "0.0.0.0:51250      0.0.0.0:*    "
                      "cgroup:/system.slice/mullvad-daemon.service").replace(
    "*:51250            *:*", "*:51250            *:*    "
                              "cgroup:/system.slice/mullvad-daemon.service")
# resolvectl status, format of my host 2026-10-31 after netprivacy (no DNS on the uplink).
# Fake names and addresses.
RESOLVED = """Global
         Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
  resolv.conf mode: stub

Link 2 (eth0)
    Current Scopes: none
         Protocols: -DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
     Default Route: no

Link 3 (wlan0)
    Current Scopes: none
         Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
     Default Route: yes

Link 4 (wg0-mullvad)
    Current Scopes: DNS
         Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
Current DNS Server: 10.2.0.1
       DNS Servers: 10.2.0.1
        DNS Domain: ~.
     Default Route: yes
"""
# journalctl -o json --output-fields=MESSAGE lines of one unit (review 2026-11-17 L-2 / L-4).
# auditd texts from auditd 4 (auditd.c, auditd-event.c); augenrules / auditctl lines as
# auditctl prints them (the host's boot lines: admin script 46 shows them).
def jl(*msgs, t0=1792899000):
    return "".join(json.dumps({"__CURSOR": f"s={i}", "__REALTIME_TIMESTAMP": str((t0 + i) * 10**6),
                               "MESSAGE": m}) + "\n" for i, m in enumerate(msgs))


JOURNAL_ARGS = "journalctl -b -q --no-pager -o json --output-fields=MESSAGE -n 400 _SYSTEMD_UNIT="
LOAD_OK = jl("No rules", "enabled 1", "failure 1", "pid 0", "rate_limit 0",
             "backlog_limit 8192", "lost 0", "backlog 0", "enabled 2", "failure 1")
AUDITD_OK = jl("No plugins found, not dispatching events",
               "Init complete, auditd 4.1.2 listening for events (startup state enable)")
MOUNTINFO = ("1 0 0:30 / / ro,relatime shared:1 - overlay composefs ro,lowerdir=x\n"
             "60 1 0:39 /var /var rw,relatime shared:4 - btrfs /dev/mapper/luks-1234 rw\n"
             "61 1 0:40 /boot /boot rw shared:5 - ext4 /dev/nvme0n1p2 rw\n")


class FakeHost(kinds.Host):
    """Files, stats and command answers of a host like mine (2026-10-26 checks)."""

    def __init__(self):
        self.files = {
            "/sys/fs/selinux/enforce": "1",
            "/etc/selinux/config": "# c\nSELINUX=enforcing\nSELINUXTYPE=targeted\n",
            "/proc/cmdline": "BOOT_IMAGE=x rhgb audit=1 audit_backlog_limit=8192 quiet "
                             "SYSTEMD_DEFAULT_HOSTNAME=localhost "
                             "initcall_blacklist=af_alg_init page_alloc.shuffle=1 rd.shell=0 "
                             "rd.emergency=halt init_on_free=1 iommu.strict=1 "
                             "hash_pointers=always proc_mem.force_override=never "
                             "module.sig_enforce=1 intel_iommu=on debugfs=off "
                             "bdev_allow_write_mounted=0\n",
            "/etc/security/faillock.conf": "# deny = 3\ndeny = 5\nunlock_time = 900\n",
            "/etc/security/pwquality.conf": "minlen = 15\nminclass = 4\nenforce_for_root\n",
            "/etc/login.defs": "#\tPASS_MIN_DAYS\tMinimum number of days allowed\n"
                               "PASS_MAX_DAYS\t365\nPASS_MIN_DAYS\t1\nPASS_WARN_AGE\t14\n",
            "/proc/sys/kernel/tainted": "12288\n",
            "/proc/self/mountinfo": MOUNTINFO,
            "/sys/block/dm-0/dm/name": "luks-1234\n",
            "/sys/block/dm-0/dm/uuid": "CRYPT-LUKS2-1234abcd-luks-1234\n",
            "/sys/kernel/security/lockdown": "[none] integrity confidentiality\n",
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nnull:x:1000:1000::/home/null:/bin/bash\n",
            "/etc/group": "wheel:x:10:null\nsugroup:x:1001:\n",
            "/etc/pam.d/su": "auth\t\tsufficient\tpam_rootok.so\nauth            required"
                             "        pam_wheel.so use_uid group=sugroup\n#auth required x\n",
            "/etc/ostree/remotes.d/fedora.conf": '[remote "fedora"]\nurl=x\ngpg-verify=true\n',
            "/etc/crypto-policies/config": "# comment\nDEFAULT\n",
            "/proc/net/tcp": TCP, "/proc/net/tcp6": TCP6, "/proc/net/udp": UDP,
            "/proc/net/udp6": UDP6,
            "/run/ostree-booted": "",
            # netprivacy (2026-10-27): Wi-Fi up with a random MAC, cable down with its
            # hardware MAC. Fake names and addresses (02:00:00 local, 00:00:5e:00:53
            # documentation, RFC 7042).
            "/sys/class/net/wlan0/type": "1\n", "/sys/class/net/wlan0/operstate": "up\n",
            "/sys/class/net/wlan0/address": "02:00:00:00:00:01\n",
            "/sys/class/net/eth0/type": "1\n", "/sys/class/net/eth0/operstate": "down\n",
            "/sys/class/net/eth0/address": "00:00:5e:00:53:01\n",
        }
        self.blobs = {kinds.SECUREBOOT: bytes([6, 0, 0, 0, 0])}
        self.dirs = {"/sys/block": ["dm-0", "nvme0n1"], "/sys/block/dm-0/slaves": ["nvme0n1p3"],
                     "/etc/ostree/remotes.d": ["fedora.conf", "README"],
                     "/sys/class/net": ["eth0", "lo", "virbr0", "wg0-mullvad", "wlan0"],
                     "/sys/class/net/eth0/device": [], "/sys/class/net/wlan0/device": []}
        self.stats = {"/etc/shadow": (0o100000, 0, 0), "/etc/passwd": (0o100644, 0, 0)}
        self.setuid = [f"/usr/bin/s{i:02d}" for i in range(27)]   # host 2026-11-16: 27
        self.setuid_unread = 0
        self.denied = {"/proc/sys/net/core/bpf_jit_harden"}
        self.sysctl = {"kernel.kptr_restrict": "2", "kernel.dmesg_restrict": "1",
                       "net.ipv4.conf.all.rp_filter": "2"}
        self.answers = {
            "systemctl show": Result(0, "Id=auditd.service\nLoadState=loaded\nActiveState=active"
                                        "\nUnitFileState=enabled\n\nId=sshd.service\nLoadState="
                                        "masked\nActiveState=inactive\nUnitFileState=masked\n", ""),
            "systemctl list-units": Result(0, "", ""),
            "firewall-cmd --get-default-zone": Result(0, "drop\n", ""),
            "nmcli -g UUID,TYPE": Result(0, "0a0a0a0a-0000-4000-8000-000000000001:802-11-wireless\n"
                                            "0b0b0b0b-0000-4000-8000-000000000002:802-11-wireless\n"
                                            "11111111-2222-3333-4444-555555555555:wireguard\n", ""),
            "nmcli -g ipv6.method": Result(0, "disabled\n", ""),
            "nmcli -g ipv4.dhcp-send-hostname,ipv6.dhcp-send-hostname": Result(0, "0\n0\n", ""),
            "nmcli -g ipv4.dns,ipv6.dns,ipv4.ignore-auto-dns,ipv6.ignore-auto-dns":
                Result(0, "\n\nyes\nyes\n", ""),
            "resolvectl status": Result(0, RESOLVED, ""),
            "hostnamectl --json=short": Result(0, json.dumps({   # host 2026-10-27, trimmed
                "Hostname": "localhost", "StaticHostname": "localhost", "PrettyHostname": None,
                "DefaultHostname": "localhost", "HostnameSource": "static"}), ""),
            "ss -Htuln --cgroup": Result(0, SS, ""),
            "systemctl show --no-pager -p Result,": Result(0, "Result=success\nExecMainStatus=0\n"
                                                    "ExecMainStartTimestampMonotonic=8123456\n", ""),
            JOURNAL_ARGS + "audit-rules.service": Result(0, LOAD_OK, ""),
            JOURNAL_ARGS + "auditd.service": Result(0, AUDITD_OK, ""),
            "rpm-ostree status": Result(0, json.dumps({"deployments": [
                {"booted": False, "timestamp": 1}, {"booted": True, "timestamp": BOOTED}]}), ""),
        }
        self.wg = {"wg0-mullvad": Result(0, "51250\n", "")}
        self.vfs = {"/var/log/audit": (4096, 12 * 2**18, 60 * 2**18)}   # frsize, free, size
        self.owned = {"/etc/sectop/setuid-known.txt": "# seen\n" + "".join(
            f"{p}\n" for p in self.setuid)}
        self.calls = []

    def read(self, path):
        if path in self.denied:
            raise PermissionError(13, "Permission denied")
        if path.startswith("/proc/sys/") and path != "/proc/sys/kernel/tainted":
            key = path[len("/proc/sys/"):].replace("/", ".")
            if key in self.sysctl:
                return self.sysctl[key] + "\n"
        if path not in self.files:
            raise FileNotFoundError(2, "No such file or directory")
        return self.files[path]

    def read_bytes(self, path):
        if path not in self.blobs:
            raise FileNotFoundError(2, "No such file or directory")
        return self.blobs[path]

    def stat(self, path):
        if path not in self.stats:
            raise FileNotFoundError(2, "No such file or directory")
        mode, uid, gid = self.stats[path]
        return os.stat_result((mode, 0, 0, 1, uid, gid, 0, 0, 0, 0))

    def exists(self, path):
        return path in self.files or path in self.dirs or path in self.blobs \
            or path == "/sys/firmware/efi"

    def listdir(self, path):
        if path not in self.dirs:
            raise FileNotFoundError(2, "No such file or directory")
        return list(self.dirs[path])

    def setuid_files(self, root=kinds.SETUID_ROOT):
        self.calls.append(["setuid_files", root])
        if isinstance(self.setuid, OSError):
            raise self.setuid
        return list(self.setuid), self.setuid_unread

    def read_owned(self, path):
        v = self.owned.get(path)
        if isinstance(v, Exception):
            raise v
        return v

    def statvfs(self, path):
        if path not in self.vfs:
            raise FileNotFoundError(2, "No such file or directory")
        frsize, free, size = self.vfs[path]
        return os.statvfs_result((frsize, frsize, size, free + 100, free, 0, 0, 0, 0, 255))

    def run(self, argv, timeout=kinds.TIMEOUT):
        self.calls.append(argv)
        line = " ".join(os.path.basename(a) if i == 0 else a for i, a in enumerate(argv))
        for k, v in sorted(self.answers.items(), key=lambda kv: -len(kv[0])):   # most exact
            if line.startswith(k):
                return v(argv) if callable(v) else v
        return Result(127, "", f"not found: {argv[0]}")

    def wg_listen_port(self, tunnel):
        self.calls.append(["wg", "show", tunnel, "listen-port"])
        return self.wg.get(tunnel, Result(1, "", "/run/sectop-net/listen_port.json missing: "
                                                 "is sectop-net.service running?"))

    def user(self, uid):
        return {0: "root", 1000: "null"}.get(uid, str(uid))

    def group(self, gid):
        return {v: k for k, v in GIDS.items()}.get(gid, str(gid))


GIDS = {"root": 0, "null": 1000, "mullvad": 975}


def chk(**kw):
    base = {"id": "x", "kind": "file", "sev": "warn", "why": "w"}
    base.update(kw)
    return policy.Check(**base)


def cx(host=None, now=NOW, audit=None, ostree=None, setuid=None):
    return kinds.Cx(host or FakeHost(), now, audit=audit, ostree={} if ostree is None else ostree,
                    setuid=setuid)


def res(c, host=None, **kw):
    x = cx(host, **kw)
    names = sorted({u for u, _ in c.units})
    r = kinds.check(c, x, names)
    return r.status, r.have


class TestKinds(unittest.TestCase):
    def test_file(self):
        self.assertEqual(res(chk(path="/sys/fs/selinux/enforce", want="1")), ("pass", "1"))
        self.assertEqual(res(chk(path="/etc/selinux/config", key="SELINUX", want="enforcing")),
                         ("pass", "enforcing"))
        self.assertEqual(res(chk(path="/etc/security/faillock.conf", key="deny", op="<=",
                                 want="5")), ("pass", "5"))           # commented deny = 3 skipped
        self.assertEqual(res(chk(path="/etc/security/faillock.conf", key="deny", op="<=",
                                 want="4")), ("fail", "5"))
        self.assertEqual(res(chk(path="/etc/security/pwquality.conf", key="minlen", op=">=",
                                 want="15")), ("pass", "15"))
        self.assertEqual(res(chk(path="/etc/crypto-policies/config", op="!=", want="LEGACY")),
                         ("pass", "DEFAULT"))
        self.assertEqual(res(chk(path="/etc/crypto-policies/config", op="in",
                                 want="FUTURE|FIPS")), ("fail", "DEFAULT"))
        self.assertEqual(res(chk(path="/etc/nope", want="1")), ("fail", "missing"))
        self.assertEqual(res(chk(path="/etc/selinux/config", key="NOPE", want="1")),
                         ("fail", "not set"))
        h = FakeHost()
        h.denied.add("/etc/selinux/config")
        self.assertEqual(res(chk(path="/etc/selinux/config", key="SELINUX", want="x"), h),
                         ("unknown", "Permission denied"))

    def test_file_sep_space(self):
        """login.defs: KEY, spaces / tabs, value (2026-11-18, pwage min age)."""
        c = chk(path="/etc/login.defs", key="PASS_MIN_DAYS", sep="space", op=">=", want="1")
        self.assertEqual(res(c), ("pass", "1"))                         # comment line skipped
        self.assertEqual(res(chk(path="/etc/login.defs", key="PASS_MIN_DAYS", op=">=",
                                 want="1")), ("fail", "not set"))       # sep "=": no match
        h = FakeHost()
        h.files["/etc/login.defs"] = "PASS_MIN_DAYS 1\nPASS_MIN_DAYS   0\n"
        self.assertEqual(res(c, h), ("fail", "0"))                       # last one wins
        h.files["/etc/login.defs"] = "PASS_MIN_DAYS = 1\n"
        self.assertEqual(res(c, h), ("fail", "= 1"))                     # not login.defs syntax
        h.files["/etc/login.defs"] = "PASS_MIN_DAYSX\t1\nPASS_MIN_DAYS\n"
        self.assertEqual(res(c, h), ("fail", "not set"))
        self.assertEqual(res(chk(path="/etc/security/pwquality.conf", key="minlen", sep="space",
                                 want="15")), ("fail", "= 15"))         # `=` file: fail

    def test_compare(self):
        self.assertTrue(kinds.compare("5", "<=", "5"))
        self.assertFalse(kinds.compare("x", ">=", "1"))                  # not a number: fail

    def test_lines(self):
        c = chk(kind="lines", path="/etc/pam.d/su",
                want=("auth required pam_wheel.so use_uid group=sugroup",))
        self.assertEqual(res(c), ("pass", "1 of 1"))                     # spaces / tabs: same
        h = FakeHost()
        h.files["/etc/pam.d/su"] = "#auth required pam_wheel.so use_uid group=sugroup\n"
        self.assertEqual(res(c, h), ("fail", "0 of 1"))                  # commented out

    def test_sysctl(self):
        c = chk(kind="sysctl", values=(("kernel.kptr_restrict", "2"),
                                       ("net.ipv4.conf.all.rp_filter", "2")))
        self.assertEqual(res(c), ("pass", "2 of 2"))
        c = chk(kind="sysctl", values=(("kernel.kptr_restrict", "1"),
                                       ("net.core.bpf_jit_harden", "2")))
        r = kinds.check(c, cx(), [])
        self.assertEqual((r.status, r.have), ("fail", "0 of 2"))
        self.assertEqual(r.lines, [("differs", "kernel.kptr_restrict = 2 (want 1)"),
                                   ("unread", "net.core.bpf_jit_harden: Permission denied")])
        c = chk(kind="sysctl", values=(("net.core.bpf_jit_harden", "2"),))
        self.assertEqual(res(c), ("unknown", "0 of 1"))                  # root-only file

    def test_cmdline(self):
        self.assertEqual(res(chk(kind="cmdline", want=("audit=1", "audit_backlog_limit=8192"))),
                         ("pass", "audit=1 audit_backlog_limit=8192"))
        self.assertEqual(res(chk(kind="cmdline", want=("audit=1", "lockdown=integrity"))),
                         ("fail", "missing lockdown=integrity"))
        h = FakeHost()
        h.files["/proc/cmdline"] = "BOOT_IMAGE=x audit=1 initcall_blacklist=af_alg_init_x\n"
        self.assertEqual(res(chk(kind="cmdline", want=("initcall_blacklist=af_alg_init",)), h),
                         ("fail", "missing initcall_blacklist=af_alg_init"))   # whole words

    def test_taint(self):
        self.assertEqual(res(chk(kind="taint", want="O E")), ("pass", "O E"))
        self.assertEqual(res(chk(kind="taint", want="")), ("fail", "O E"))
        h = FakeHost()
        h.files["/proc/sys/kernel/tainted"] = "0\n"
        self.assertEqual(res(chk(kind="taint", want="O E"), h), ("pass", "none"))

    def test_luks(self):
        c = chk(kind="luks", path="/var")
        r = kinds.check(c, cx(), [])
        self.assertEqual((r.status, r.have, r.lines), ("pass", "LUKS2", [("fs", "btrfs on dm-0")]))
        self.assertNotIn("1234", repr(r))                                 # no uuid shown
        self.assertEqual(res(chk(kind="luks", path="/boot")),
                         ("fail", "ext4 on /dev/nvme0n1p2: not device-mapper"))
        self.assertEqual(res(chk(kind="luks", path="/srv")), ("unknown", "/srv not mounted"))
        h = FakeHost()                                                    # LVM on LUKS
        h.files.update({"/sys/block/dm-0/dm/uuid": "LVM-abc\n",
                        "/sys/block/dm-1/dm/uuid": "CRYPT-LUKS2-x\n"})
        h.dirs["/sys/block/dm-0/slaves"] = ["dm-1"]
        self.assertEqual(res(chk(kind="luks", path="/var"), h), ("pass", "LUKS2"))
        h.files["/sys/block/dm-1/dm/uuid"] = "LVM-def\n"
        self.assertEqual(res(chk(kind="luks", path="/var"), h), ("fail", "LVM"))

    def test_secureboot_and_lockdown(self):
        self.assertEqual(res(chk(kind="secureboot")), ("fail", "off"))  # host 2026-10-26
        h = FakeHost()
        h.blobs[kinds.SECUREBOOT] = bytes([6, 0, 0, 0, 1])
        self.assertEqual(res(chk(kind="secureboot"), h), ("pass", "on"))
        del h.blobs[kinds.SECUREBOOT]
        self.assertEqual(res(chk(kind="secureboot"), h), ("fail", "no SecureBoot variable"))
        c = chk(kind="lockdown", want="integrity|confidentiality")
        self.assertEqual(res(c), ("fail", "none"))
        h.files[kinds.LOCKDOWN] = "none [integrity] confidentiality\n"
        self.assertEqual(res(c, h), ("pass", "integrity"))

    def test_accounts(self):
        self.assertEqual(res(chk(kind="uid0", want=("root",))), ("pass", "root"))
        h = FakeHost()
        h.files["/etc/passwd"] += "toor:x:0:0::/root:/bin/bash\n"
        self.assertEqual(res(chk(kind="uid0", want=("root",)), h), ("fail", "root toor"))
        self.assertEqual(res(chk(kind="group", group="wheel", want=("null",))), ("pass", "null"))
        self.assertEqual(res(chk(kind="group", group="sugroup", want=())), ("pass", "empty"))
        h.files["/etc/group"] = "wheel:x:10:null,eve\nsugroup:x:1001:bob\n"
        r = kinds.check(chk(kind="group", group="wheel", want=("null",)), cx(h), [])
        self.assertEqual((r.status, r.have, r.lines), ("fail", "null eve", [("not allowed", "eve")]))
        self.assertEqual(res(chk(kind="group", group="sugroup", want=()), h), ("fail", "bob"))
        self.assertEqual(res(chk(kind="group", group="nope", want=())), ("fail", "no group nope"))

    def test_perms(self):
        c = chk(kind="perms", path="/etc/shadow", mode=0, owner="root:root")
        self.assertEqual(res(c), ("pass", "0 root:root"))
        c = chk(kind="perms", path="/etc/passwd", mode=0o644, owner="root:root")
        self.assertEqual(res(c), ("pass", "644 root:root"))
        h = FakeHost()
        h.stats["/etc/shadow"] = (0o100640, 0, 1000)
        self.assertEqual(res(chk(kind="perms", path="/etc/shadow", mode=0, owner="root:root"), h),
                         ("fail", "640 root:null"))
        self.assertEqual(res(chk(kind="perms", path="/etc/nope", mode=0, owner="root:root")),
                         ("fail", "missing"))
        sock = chk(kind="perms", path="/run/mullvad-vpn", mode=0o760, owner="root:mullvad")
        h.stats["/run/mullvad-vpn"] = (0o140760, 0, GIDS["mullvad"])     # host 2026-11-02
        self.assertEqual(res(sock, h), ("pass", "760 root:mullvad"))
        h.stats["/run/mullvad-vpn"] = (0o140766, 0, 0)                   # Mullvad's default
        self.assertEqual(res(sock, h), ("fail", "766 root:root"))

    def test_ostree(self):
        self.assertEqual(res(chk(kind="ostree-unlocked")), ("pass", "locked"))
        h = FakeHost()
        h.files["/proc/self/mountinfo"] += "70 1 0:50 / /usr rw - overlay overlay rw\n"
        self.assertEqual(res(chk(kind="ostree-unlocked"), h), ("fail", "unlocked: overlay on /usr"))
        self.assertEqual(res(chk(kind="ostree-staged")), ("pass", "none"))
        h.files[kinds.STAGED] = ""
        self.assertEqual(res(chk(kind="ostree-staged"), h), ("fail", "staged, reboot to use it"))
        del h.files["/run/ostree-booted"]
        self.assertEqual(res(chk(kind="ostree-staged"), h), ("unknown", "not an ostree system"))
        self.assertEqual(res(chk(kind="ostree-gpg")), ("pass", "1 of 1 verify"))
        h = FakeHost()
        h.files["/etc/ostree/remotes.d/x.conf"] = '[remote "x"]\ngpg-verify=false\n[remote "y"]\n'
        h.dirs["/etc/ostree/remotes.d"].append("x.conf")
        r = kinds.check(chk(kind="ostree-gpg"), cx(h), [])
        self.assertEqual((r.status, r.have, r.lines),
                         ("fail", "2 of 3 verify", [("gpg-verify off", "x")]))   # y: default on

    def test_ostree_age_once_a_day(self):
        h, cache = FakeHost(), {}
        c = chk(kind="ostree-age", max_days=14)
        self.assertEqual(res(c, h, ostree=cache), ("pass", "0 days"))
        self.assertEqual(res(c, h, now=NOW + 3600, ostree=cache), ("pass", "0 days"))
        self.assertEqual(sum(a[1] == "status" for a in h.calls), 1)       # cached
        self.assertEqual(res(c, h, now=BOOTED + 15 * DAY + 10, ostree=cache), ("fail", "15 days"))
        self.assertEqual(sum(a[1] == "status" for a in h.calls), 2)       # a day later: again
        self.assertEqual(res(c, h, now=BOOTED + DAY + 10, ostree={}), ("pass", "1 day"))
        h.answers["rpm-ostree status"] = Result(1, "", "error: connection refused\n")
        self.assertEqual(res(c, h, ostree={}), ("unknown", "error: connection refused"))

    def test_commands(self):
        self.assertEqual(res(chk(kind="firewalld-zone", want="drop")), ("pass", "drop"))
        h = FakeHost()
        h.answers["firewall-cmd --get-default-zone"] = Result(0, "public\n", "")
        self.assertEqual(res(chk(kind="firewalld-zone", want="drop"), h), ("fail", "public"))
        self.assertEqual(res(chk(kind="failed-units")), ("pass", "0 failed"))
        h.answers["systemctl list-units"] = Result(0, "x.service loaded failed failed X\n", "")
        r = kinds.check(chk(kind="failed-units"), cx(h), [])
        self.assertEqual((r.status, r.lines), ("fail", [("failed", "x.service")]))

    def test_wifi_ipv6(self):
        h = FakeHost()
        c = chk(kind="wifi-ipv6", want="disabled")
        self.assertEqual(res(c, h), ("pass", "2 of 2 disabled"))         # wireguard: not wifi
        h.answers = {"nmcli -g ipv6.method connection show 0a0a": Result(0, "auto\n", ""),
                     **h.answers}
        r = kinds.check(c, cx(h), [])
        self.assertEqual((r.status, r.have), ("fail", "1 of 2 disabled"))
        self.assertEqual(r.lines, [("not disabled", "0a0a0a0a-0000-4000-8000-000000000001 auto")])

    def test_nm_props(self):
        props = (("ipv4.dhcp-send-hostname", "0"), ("ipv6.dhcp-send-hostname", "0"))
        c = chk(kind="nm-props", types=("802-11-wireless", "802-3-ethernet"), props=props)
        h = FakeHost()
        self.assertEqual(res(c, h), ("pass", "2 of 2 profiles"))         # wireguard: not listed
        self.assertEqual(h.calls[1][1:4], ["-g", "ipv4.dhcp-send-hostname,ipv6.dhcp-send-hostname",
                                           "connection"])
        h.answers = {"nmcli -g ipv4.dhcp-send-hostname,ipv6.dhcp-send-hostname connection show "
                     "0b0b": Result(0, "-1\n-1\n", ""), **h.answers}     # a new network
        r = kinds.check(c, cx(h), [])
        self.assertEqual((r.status, r.have), ("fail", "1 of 2 profiles"))
        self.assertEqual(r.lines, [
            ("differs", "0b0b0b0b-0000-4000-8000-000000000002 ipv4.dhcp-send-hostname=-1"),
            ("differs", "0b0b0b0b-0000-4000-8000-000000000002 ipv6.dhcp-send-hostname=-1")])
        h = FakeHost()
        h.answers["nmcli -g ipv4.dhcp-send-hostname,ipv6.dhcp-send-hostname"] = Result(0, "0\n", "")
        self.assertEqual(res(c, h), ("unknown", "0 of 2 profiles"))      # one value missing
        h.answers["nmcli -g UUID,TYPE"] = Result(8, "", "Error: NetworkManager is not running.\n")
        self.assertEqual(res(c, h), ("unknown", "Error: NetworkManager is not running."))

    def test_nm_props_empty(self):
        props = (("ipv4.dns", ""), ("ipv6.dns", ""), ("ipv4.ignore-auto-dns", "yes"),
                 ("ipv6.ignore-auto-dns", "yes"))
        c = chk(kind="nm-props", types=("802-11-wireless", "802-3-ethernet"), props=props)
        self.assertEqual(res(c), ("pass", "2 of 2 profiles"))
        self.assertEqual(kinds.want_text(c), "ipv4.dns=- ipv6.dns=- ipv4.ignore-auto-dns=yes "
                                             "ipv6.ignore-auto-dns=yes")
        h = FakeHost()
        h.answers = {"nmcli -g ipv4.dns,ipv6.dns,ipv4.ignore-auto-dns,ipv6.ignore-auto-dns "
                     "connection show 0a0a": Result(0, "192.0.2.53,192.0.2.54\n\nyes\nyes\n", ""),
                     "nmcli -g ipv4.dns,ipv6.dns,ipv4.ignore-auto-dns,ipv6.ignore-auto-dns "
                     "connection show 0b0b": Result(0, "\n\nno\nno\n", ""),     # a new network
                     **h.answers}
        r = kinds.check(c, cx(h), [])
        self.assertEqual((r.status, r.have), ("fail", "0 of 2 profiles"))
        self.assertEqual(r.lines, [
            ("differs", "0a0a0a0a-0000-4000-8000-000000000001 ipv4.dns=192.0.2.53,192.0.2.54"),
            ("differs", "0b0b0b0b-0000-4000-8000-000000000002 ipv4.ignore-auto-dns=no"),
            ("differs", "0b0b0b0b-0000-4000-8000-000000000002 ipv6.ignore-auto-dns=no")])

    def test_dns_servers(self):
        c = chk(kind="dns-servers", allow=("wg0-mullvad",))
        r = kinds.check(c, cx(), [])
        self.assertEqual((r.status, r.have, r.lines),
                         ("pass", "only wg0-mullvad", [("allowed", "wg0-mullvad 10.2.0.1")]))
        self.assertEqual(kinds.want_text(c), "only wg0-mullvad")
        # before netprivacy (host 2026-10-31): static resolver in the wifi profile
        h = FakeHost()
        h.answers["resolvectl status"] = Result(0, RESOLVED.replace(
            "     Default Route: yes\n\nLink 4",
            "Current DNS Server: 192.0.2.53\n       DNS Servers: 192.0.2.53 192.0.2.54\n"
            "     Default Route: yes\n\nLink 4"), "")
        r = kinds.check(c, cx(h), [])
        self.assertEqual((r.status, r.have), ("fail", "DNS on wlan0"))
        self.assertEqual(r.lines, [("not allowed", "wlan0 192.0.2.53 192.0.2.54"),
                                   ("allowed", "wg0-mullvad 10.2.0.1")])
        # global and fallback servers, servers on the lines under the key, IPv6
        h.answers["resolvectl status"] = Result(0, RESOLVED.replace(
            "  resolv.conf mode: stub\n",
            "  resolv.conf mode: stub\n       DNS Servers: 192.0.2.1\n"
            "Fallback DNS Servers: 192.0.2.2#dns.example\n                      2001:db8::53\n"), "")
        r = kinds.check(c, cx(h), [])
        self.assertEqual((r.status, r.have), ("fail", "DNS on global fallback"))
        self.assertEqual(r.lines[:2], [("global", "192.0.2.1"),
                                       ("fallback", "192.0.2.2#dns.example 2001:db8::53")])
        # tunnel down: no server anywhere, nothing leaves
        h.answers["resolvectl status"] = Result(0, RESOLVED.replace(
            "Current DNS Server: 10.2.0.1\n       DNS Servers: 10.2.0.1\n", ""), "")
        self.assertEqual(res(c, h), ("pass", "no DNS server"))
        self.assertEqual(res(chk(kind="dns-servers", allow=()), FakeHost()),
                         ("fail", "DNS on wg0-mullvad"))
        h.answers["resolvectl status"] = Result(0, "something else\n", "")
        self.assertEqual(res(c, h), ("unknown", "resolvectl: no Global section"))
        h.answers["resolvectl status"] = Result(1, "", "Failed to get global data: Access denied\n")
        self.assertEqual(res(c, h), ("unknown", "Failed to get global data: Access denied"))
        self.assertEqual(FakeHost().run(["/usr/bin/resolvectl", "status", "--no-pager"]).rc, 0)

    def test_mac_local(self):
        c = chk(kind="mac-local")
        r = kinds.check(c, cx(), [])
        self.assertEqual((r.status, r.have, r.lines),
                         ("pass", "1 up, all local", [("local", "wlan0")]))
        self.assertNotIn("02:00", repr(r))                                # never the address
        h = FakeHost()
        h.files["/sys/class/net/eth0/operstate"] = "up\n"                # cable up, hardware MAC
        r = kinds.check(c, cx(h), [])
        self.assertEqual((r.status, r.have), ("fail", "hardware MAC: eth0"))
        self.assertNotIn("00:53", repr(r))
        h = FakeHost()
        h.files["/sys/class/net/wlan0/operstate"] = "down\n"
        self.assertEqual(res(c, h), ("pass", "no link up"))
        h = FakeHost()
        del h.files["/sys/class/net/wlan0/address"]
        self.assertEqual(res(c, h), ("unknown", "unread: wlan0"))
        h = FakeHost()
        h.files["/sys/class/net/wlan0/type"] = "801\n"                   # not Ethernet: skipped
        self.assertEqual(res(c, h), ("pass", "no link up"))
        h = FakeHost()
        del h.dirs["/sys/class/net"]
        self.assertEqual(res(c, h), ("unknown", "No such file or directory"))

    def test_hostname(self):
        c = chk(kind="hostname", want="localhost")
        self.assertEqual(res(c), ("pass", "localhost"))
        h = FakeHost()
        h.answers["hostnamectl --json=short"] = Result(0, json.dumps({
            "Hostname": "box1", "StaticHostname": "box1", "PrettyHostname": "Box 1",
            "DefaultHostname": "fedora"}), "")
        r = kinds.check(c, cx(h), [])
        self.assertEqual((r.status, r.have), ("fail", "box1"))
        self.assertEqual(r.lines, [("differs", "Hostname = box1"),
                                   ("differs", "StaticHostname = box1"),
                                   ("differs", "DefaultHostname = fedora"),
                                   ("differs", "PrettyHostname = Box 1")])
        h.answers["hostnamectl --json=short"] = Result(0, "[]", "")
        self.assertEqual(res(c, h), ("unknown", "hostnamectl: no JSON object"))
        h.answers["hostnamectl --json=short"] = Result(1, "", "Failed to connect to bus\n")
        self.assertEqual(res(c, h), ("unknown", "Failed to connect to bus"))

    def test_units_one_call(self):
        h = FakeHost()
        x = cx(h)
        names = ["auditd.service", "sshd.service"]
        a = kinds.check(chk(kind="units", units=(("auditd.service", "active"),)), x, names)
        b = kinds.check(chk(kind="units", units=(("sshd.service", "masked"),)), x, names)
        self.assertEqual(((a.status, a.have), (b.status, b.have)),
                         (("pass", "active"), ("pass", "masked")))
        self.assertEqual(len(h.calls), 1)                                 # one systemctl show
        self.assertEqual(h.calls[0][-3:], ["--", "auditd.service", "sshd.service"])
        c = chk(kind="units", units=(("auditd.service", "inactive"),))
        r = kinds.check(c, x, names)
        self.assertEqual((r.status, r.lines), ("fail", [("differs",
                                                         "auditd.service: active (want inactive)")]))

    def test_listeners(self):
        self.assertEqual(kinds.listening(cx()), [
            "tcp 192.168.122.1:53", "udp 0.0.0.0:51250", "udp 0.0.0.0:67",
            "udp 192.168.122.1:53", "udp [::]:51250"])                  # loopback left out
        allow = ("udp 192.168.122.1:53", "tcp 192.168.122.1:53", "udp 0.0.0.0:67")
        c = chk(kind="listeners", allow=allow, wireguard="wg0-mullvad")
        r = kinds.check(c, cx(), [])
        self.assertEqual((r.status, r.have), ("pass", "5 listening, all allowed"))
        self.assertIn(("wireguard", "wg0-mullvad listen-port 51250"), r.lines)
        self.assertIn(("allowed", "udp [::]:51250 (wg0-mullvad)"), r.lines)
        r = kinds.check(chk(kind="listeners", allow=allow), cx(), [])  # no wireguard key
        self.assertEqual((r.status, r.have), ("fail", "2 not allowed"))
        self.assertEqual(r.lines[:2], [("not allowed", "udp 0.0.0.0:51250"),
                                       ("not allowed", "udp [::]:51250")])
        h = FakeHost()                                                  # reconnected: new port
        h.wg["wg0-mullvad"] = Result(0, "40000\n", "")
        r = kinds.check(c, cx(h), [])
        self.assertEqual((r.status, r.have), ("fail", "2 not allowed"))
        h = FakeHost()                                                  # net unit down
        del h.wg["wg0-mullvad"]
        r = kinds.check(c, cx(h), [])
        self.assertEqual(r.status, "fail")
        self.assertIn(("wireguard", "wg0-mullvad: /run/sectop-net/listen_port.json missing: is "
                                    "sectop-net.service running?"), r.lines)
        h = FakeHost()                                                  # a program on 0.0.0.0
        h.files["/proc/net/tcp"] += ROW.format(9, "00000000:0016", Z4, "0A", 0, 4998)
        r = kinds.check(c, cx(h), [])
        self.assertEqual((r.status, r.lines[0]), ("fail", ("not allowed", "tcp 0.0.0.0:22")))

    def test_listeners_programs(self):
        allow = ("udp 192.168.122.1:53", "tcp 192.168.122.1:53")
        r = kinds.check(chk(kind="listeners", allow=allow, wireguard="wg0-mullvad"), cx(), [])
        self.assertEqual(r.status, "fail")
        self.assertEqual(r.lines[0], ("not allowed", "udp 0.0.0.0:67  virtnetworkd"))
        self.assertIn(("allowed", "udp 192.168.122.1:53  virtnetworkd"), r.lines)
        self.assertIn(("allowed", "udp 0.0.0.0:51250 (wg0-mullvad)"), r.lines)
        self.assertIn("ss --cgroup", r.source)
        h = FakeHost()
        h.answers["ss -Htuln --cgroup"] = Result(1, "", "Cannot open netlink socket\n")
        r = kinds.check(chk(kind="listeners", allow=allow), cx(h), [])
        self.assertEqual(r.lines[0], ("not allowed", "udp 0.0.0.0:51250"))   # no names
        self.assertIn(("programs", "ss: Cannot open netlink socket"), r.lines)

    def test_listeners_userspace_tunnel(self):
        allow = ("udp 192.168.122.1:53", "tcp 192.168.122.1:53", "udp 0.0.0.0:67")
        c = chk(kind="listeners", allow=allow, wireguard="wg0-mullvad",
                tunnel_owner="mullvad-daemon")
        h = FakeHost()
        del h.wg["wg0-mullvad"]                         # wg show: no kernel device
        h.wg["wg0-mullvad"] = Result(1, "", "Unable to access interface: No such device")
        h.answers["ss -Htuln --cgroup"] = Result(0, SS_DAITA, "")
        h.dirs["/sys/class/net/wg0-mullvad"] = ["flags", "tun_flags"]
        r = kinds.check(c, cx(h), [])
        self.assertEqual((r.status, r.have), ("pass", "5 listening, all allowed"))
        self.assertIn(("allowed", "udp [::]:51250 (wg0-mullvad, mullvad-daemon)"), r.lines)
        self.assertIn(("wireguard", "wg0-mullvad present, no kernel port: udp 0.0.0.0 / [::] "
                                    "of mullvad-daemon allowed (userspace tunnel)"), r.lines)
        # no tunnel_owner key: the daemon's sockets are not allowed, named
        r = kinds.check(chk(kind="listeners", allow=allow, wireguard="wg0-mullvad"), cx(h), [])
        self.assertEqual(r.lines[:2], [("not allowed", "udp 0.0.0.0:51250  mullvad-daemon"),
                                       ("not allowed", "udp [::]:51250  mullvad-daemon")])
        # another program on the port: not the tunnel
        h.answers["ss -Htuln --cgroup"] = Result(0, SS_DAITA.replace(
            "mullvad-daemon.service", "app-flatpak-com.valvesoftware.Steam-1234.scope"), "")
        r = kinds.check(c, cx(h), [])
        self.assertEqual(r.lines[0], ("not allowed",
                                      "udp 0.0.0.0:51250  com.valvesoftware.Steam"))
        # tunnel interface gone: nothing allowed for the daemon
        h.answers["ss -Htuln --cgroup"] = Result(0, SS_DAITA, "")
        del h.dirs["/sys/class/net/wg0-mullvad"]
        r = kinds.check(c, cx(h), [])
        self.assertEqual((r.status, r.have), ("fail", "2 not allowed"))
        # kernel port known: the kernel rule wins, the owner rule is not used
        h = FakeHost()
        h.answers["ss -Htuln --cgroup"] = Result(0, SS_DAITA, "")
        r = kinds.check(c, cx(h), [])
        self.assertIn(("allowed", "udp 0.0.0.0:51250 (wg0-mullvad)"), r.lines)

    def test_ss_key(self):
        for local, want in (("0.0.0.0%virbr0:67", "udp 0.0.0.0:67"),
                            ("*:52880", "udp [::]:52880"),
                            ("[::]:22", "udp [::]:22"),
                            ("[fe80::1]%wlo1:546", "udp [fe80::1]:546"),
                            ("[fe80:0:0:0:0:0:0:1%wlo1]:546", "udp [fe80::1]:546"),
                            ("[::ffff:192.0.2.1]:80", "udp [::ffff:192.0.2.1]:80"),
                            ("0.0.0.0:*", None), ("noport", None), ("x:1", None)):
            self.assertEqual(kinds._ss_key("udp", local), want, local)

    def test_wg_port_from_net_unit(self):
        """Host.wg_listen_port asks core/netd.py Reader for the net unit's command."""
        from core import netd
        self.assertEqual(netd.commands("wg0-mullvad")["listen_port"],
                         ((netd.bin_path("wg"), "show", "wg0-mullvad", "listen-port"), netd.FAST))
        self.assertEqual(kinds.Host().wg_listen_port("a b").rc, 1)      # bad name: no raise

    def test_audit(self):
        a = pos.Audit()
        self.assertEqual(res(chk(kind="audit-rules", want=70), audit=a), ("fail", "0 rules"))
        a.added, a.removed = 72, 1
        self.assertEqual(res(chk(kind="audit-rules", want=70), audit=a), ("pass", "71 rules"))
        self.assertEqual(res(chk(kind="audit-enabled"), audit=a), ("pass", "not changed this boot"))
        a.enabled = "0"
        self.assertEqual(res(chk(kind="audit-enabled"), audit=a), ("fail", "audit_enabled=0"))
        a.err = "journal scan: x"
        self.assertEqual(res(chk(kind="audit-enabled"), audit=a), ("unknown", "journal scan: x"))

    def test_audit_setuid_key(self):
        """2026-11-16: 47 rules of other keys + one "privileged" rule per setuid program."""
        c = chk(kind="audit-rules", want=47, setuid_key="privileged")
        a = pos.Audit()
        a.added, a.keys["privileged"] = 74, 27
        h = FakeHost()
        cache = {}
        r = kinds.check(c, cx(h, audit=a, setuid=cache), [])
        self.assertEqual((r.status, r.have), ("pass", "74 rules, setuid 27/27"))
        self.assertEqual(r.lines[:3], [("other rules", "47 (want >= 47)"),
                                       ("privileged rules", "27"), ("setuid files", "27")])
        self.assertEqual(r.lines[3], ("setuid", "/usr/bin/s00"))
        self.assertEqual(len(r.lines), kinds.MAX_LINES)
        kinds.check(c, cx(h, audit=a, setuid=cache), [])                 # cached: one scan
        self.assertEqual([x for x in h.calls if x[0] == "setuid_files"], [["setuid_files", "/usr"]])
        # userhelper gone from the image, old rules file still loaded: 28 rules, 27 programs
        a.added, a.keys["privileged"] = 75, 28
        r = kinds.check(c, cx(h, audit=a), [])
        self.assertEqual((r.status, r.have), ("fail", "75 rules, setuid 28/27"))
        self.assertIn(("fix", "rules for programs no longer here: reboot "
                              "(audit-privileged-sync.service writes the list at boot)"), r.lines)
        # a new setuid program without a rule
        h.setuid.append("/usr/bin/new")
        a.added, a.keys["privileged"] = 74, 27
        r = kinds.check(c, cx(h, audit=a), [])
        self.assertEqual((r.status, r.have), ("fail", "74 rules, setuid 27/28"))
        self.assertEqual(r.lines[3][0], "fix")
        # other keys short
        h.setuid.pop()
        a.added = 73
        self.assertEqual(res(c, h, audit=a), ("fail", "73 rules, setuid 27/27"))
        # dirs not readable: shown; /usr not readable: unknown
        a.added, h.setuid_unread = 74, 2
        r = kinds.check(c, cx(h, audit=a), [])
        self.assertEqual(r.lines[2], ("setuid files", "27 (2 dirs not readable)"))
        h.setuid = PermissionError(13, "Permission denied")
        self.assertEqual(res(c, h, audit=a), ("unknown", "/usr: Permission denied"))
        self.assertEqual(kinds.want_text(c), ">= 47 + 1 per setuid file")
        self.assertEqual(kinds.want_text(chk(kind="audit-rules", want=70)), ">= 70")

    def test_audit_setuid_rules_per_arch(self):
        """2026-11-21: path rules once per arch: 53 other rules + two per setuid program."""
        c = chk(kind="audit-rules", want=53, setuid_key="privileged", setuid_rules=2)
        a = pos.Audit()
        h = FakeHost()
        a.added, a.keys["privileged"] = 53 + 54, 54
        r = kinds.check(c, cx(h, audit=a), [])
        self.assertEqual((r.status, r.have), ("pass", "107 rules, setuid 54/54"))
        self.assertEqual(r.lines[:3], [("other rules", "53 (want >= 53)"),
                                       ("privileged rules", "54 (2 per file)"),
                                       ("setuid files", "27")])
        # rules.d rewritten, the old rules (one per program, 47 others) still loaded
        a.added, a.keys["privileged"] = 47 + 27, 27
        r = kinds.check(c, cx(h, audit=a), [])
        self.assertEqual((r.status, r.have), ("fail", "74 rules, setuid 27/54"))
        self.assertEqual(r.lines[3], ("fix", "a setuid program has no rule: reboot "
                                             "(audit-privileged-sync.service writes the list at boot)"))
        # one arch only for one program
        a.added, a.keys["privileged"] = 53 + 53, 53
        self.assertEqual(res(c, h, audit=a), ("fail", "106 rules, setuid 53/54"))
        self.assertEqual(kinds.want_text(c), ">= 53 + 2 per setuid file")

    def test_setuid_files_real(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "bin", "sub"))
            paths = {n: os.path.join(d, "bin", n) for n in ("su", "plain", "grp")}
            paths["deep"] = os.path.join(d, "bin", "sub", "deep")
            for n, p in paths.items():
                with open(p, "w"):
                    pass
            os.chmod(paths["su"], 0o4755)
            os.chmod(paths["grp"], 0o2755)
            os.chmod(paths["deep"], 0o4711)
            os.symlink(paths["su"], os.path.join(d, "bin", "link"))     # links: not counted
            files, unread = kinds.Host().setuid_files(d)
            self.assertEqual(files, sorted([paths["deep"], paths["grp"], paths["su"]]))
            self.assertEqual(unread, 0)
            if os.geteuid() != 0:                                    # root reads 000 dirs
                os.chmod(os.path.join(d, "bin", "sub"), 0)
                try:
                    files, unread = kinds.Host().setuid_files(d)
                finally:
                    os.chmod(os.path.join(d, "bin", "sub"), 0o755)
                self.assertEqual((len(files), unread), (2, 1))
        with self.assertRaises(OSError):
            kinds.Host().setuid_files("/nonexistent-sectop-test")

    def test_fwupd_reports(self):
        c = chk(kind="fwupd-reports", path="/etc/fwupd/remotes.d")
        h = FakeHost()
        self.assertEqual(res(c, h), ("pass", "no fwupd remotes"))           # no fwupd at all
        on = ("[fwupd Remote]\nEnabled=true\nReportURI=https://fwupd.org/lvfs/firmware/report\n"
              "AutomaticReports=true\nAutomaticSecurityReports=true\n")
        off = ("[fwupd Remote]\nEnabled=true\n#ReportURI=https://fwupd.org/lvfs/firmware/report\n"
               "AutomaticReports=false\nAutomaticSecurityReports=false\n")
        h.dirs["/etc/fwupd/remotes.d"] = ["lvfs.conf", "vendor-directory.conf", "README"]
        h.files["/etc/fwupd/remotes.d/lvfs.conf"] = off
        h.files["/etc/fwupd/remotes.d/vendor-directory.conf"] = "[fwupd Remote]\nKind=directory\n"
        self.assertEqual(res(c, h), ("pass", "2 remotes, no report address"))
        h.files["/etc/fwupd/remotes.d/lvfs.conf"] = on
        r = kinds.check(c, cx(h), [])
        self.assertEqual((r.status, r.have), ("fail", "3 report settings on"))
        self.assertEqual(r.lines, [("on", "lvfs.conf: ReportURI set"),
                                   ("on", "lvfs.conf: AutomaticReports=true"),
                                   ("on", "lvfs.conf: AutomaticSecurityReports=true")])
        h.files["/etc/fwupd/remotes.d/lvfs.conf"] = off.replace("#ReportURI", "ReportURI")
        self.assertEqual(res(c, h), ("fail", "1 report settings on"))   # address alone: fail
        h.files["/etc/fwupd/remotes.d/lvfs.conf"] = off
        h.denied.add("/etc/fwupd/remotes.d/vendor-directory.conf")
        self.assertEqual(res(c, h)[0], "unknown")
        self.assertEqual(kinds.want_text(c), "no report address")

    def test_audit_locked(self):
        a = pos.Audit()
        self.assertEqual(res(chk(kind="audit-locked"), audit=a), ("fail", "not locked this boot"))
        a.enabled = "1"
        self.assertEqual(res(chk(kind="audit-locked"), audit=a), ("fail", "audit_enabled=1"))
        a.enabled = "2"
        self.assertEqual(res(chk(kind="audit-locked"), audit=a), ("pass", "audit_enabled=2"))
        self.assertEqual(res(chk(kind="audit-enabled"), audit=a), ("pass", "audit_enabled=2"))
        a.err = "journal scan: x"
        self.assertEqual(res(chk(kind="audit-locked"), audit=a), ("unknown", "journal scan: x"))

    def test_audit_load(self):
        """audit-rules.service: ran, success, no error line (review 2026-11-17 L-2)."""
        c = chk(kind="audit-load")
        h = FakeHost()
        r = kinds.check(c, cx(h), [])
        self.assertEqual((r.status, r.have), ("pass", "loaded, no error"))
        self.assertIn(["/usr/bin/journalctl", "-b", "-q", "--no-pager", "-o", "json",
                       "--output-fields=MESSAGE", "-n", "400", "_SYSTEMD_UNIT=audit-rules.service"],
                      h.calls)
        # -c: one rule refused, the others loaded, auditctl exits 1, the unit fails
        h.answers[JOURNAL_ARGS + "audit-rules.service"] = Result(0, jl(
            "No rules", "Error sending add rule data request (No such file or directory)",
            "There was an error in line 61 of /etc/audit/audit.rules", "enabled 2"), "")
        h.answers["systemctl show --no-pager -p Result,"] = Result(
            0, "Result=exit-code\nExecMainStatus=1\nExecMainStartTimestampMonotonic=8123456\n", "")
        r = kinds.check(c, cx(h), [])
        self.assertEqual((r.status, r.have), ("fail", "exit-code, exit 1, 1 rule(s) not loaded"))
        self.assertEqual([k for k, _ in r.lines], ["result", "error", "error", "fix"])
        self.assertTrue(r.lines[2][1].endswith("There was an error in line 61 of "
                                               "/etc/audit/audit.rules"))
        # an error line, unit still success (e.g. a later restart): fail
        h.answers["systemctl show --no-pager -p Result,"] = Result(
            0, "Result=success\nExecMainStatus=0\nExecMainStartTimestampMonotonic=9\n", "")
        self.assertEqual(res(c, h)[0], "fail")
        # not run this boot
        h.answers[JOURNAL_ARGS + "audit-rules.service"] = Result(1, "", "")   # no entries
        h.answers["systemctl show --no-pager -p Result,"] = Result(
            0, "Result=success\nExecMainStatus=0\nExecMainStartTimestampMonotonic=0\n", "")
        self.assertEqual(res(c, h), ("fail", "not run this boot"))
        h.answers[JOURNAL_ARGS + "audit-rules.service"] = Result(1, "", "Permission denied\n")
        self.assertEqual(res(c, h), ("unknown", "journal: Permission denied"))
        self.assertEqual(kinds.want_text(c), "loaded, no error")

    def test_auditd_logging(self):
        """auditd's own lines: suspended until a resume or a new start (L-4)."""
        c = chk(kind="auditd-logging", sev="crit")
        h = FakeHost()
        self.assertEqual(res(c, h), ("pass", "logging"))
        start = "Init complete, auditd 4.1.2 listening for events (startup state enable)"
        low = "Audit daemon is low on disk space for logging. The audit daemon will SUSPEND"
        susp = "Audit daemon is suspending logging due to low disk space."
        h.answers[JOURNAL_ARGS + "auditd.service"] = Result(0, jl(start, low, susp), "")
        r = kinds.check(c, cx(h), [])
        self.assertEqual(r.status, "fail")
        self.assertTrue(r.have.startswith("suspended since "))
        self.assertEqual([k for k, _ in r.lines], ["line", "line", "fix"])
        st = pos.State(checks=(c,), host=h, wall=lambda: NOW, stamp=lambda ts: "12:00:00")
        snap = validate(pos.collect(st, Context((), True, "")))
        self.assertEqual([a["key"] for a in snap["checks"]], ["x"])       # crit: an alert
        resume = "Audit daemon is attempting to resume logging."
        h.answers[JOURNAL_ARGS + "auditd.service"] = Result(0, jl(start, susp, resume), "")
        self.assertEqual(res(c, h), ("pass", "logging, 2 space line(s)"))
        h.answers[JOURNAL_ARGS + "auditd.service"] = Result(0, jl(start, susp, start), "")
        self.assertEqual(res(c, h), ("pass", "logging"))                  # restarted
        full = ("Audit daemon is suspending logging due to no space left on logging "
                "partition.")
        h.answers[JOURNAL_ARGS + "auditd.service"] = Result(0, jl(start, resume, full), "")
        self.assertEqual(res(c, h)[0], "fail")
        # a forged line in another unit is not read: the match is _SYSTEMD_UNIT
        self.assertTrue(all(a[-1] == "_SYSTEMD_UNIT=auditd.service"
                            for a in h.calls if "journalctl" in a[0] and "auditd" in a[-1]))
        h.answers[JOURNAL_ARGS + "auditd.service"] = Result(-9, "", "", timed_out=True)
        self.assertEqual(res(c, h), ("unknown", "timed out"))
        self.assertEqual(kinds.want_text(c), "not suspended")

    def test_setuid_known(self):
        """A setuid program not on my list: yellow until accepted (review 2026-11-22)."""
        c = chk(kind="setuid-known", path="/etc/sectop/setuid-known.txt")
        h = FakeHost()
        self.assertEqual(res(c, h), ("pass", "27 known"))
        h.setuid.append("/usr/bin/zz-new")
        r = kinds.check(c, cx(h), [])
        self.assertEqual((r.status, r.have), ("fail", "1 new: /usr/bin/zz-new"))
        self.assertEqual(r.lines[0], ("new", "/usr/bin/zz-new"))
        self.assertEqual(r.lines[-1][0], "fix")
        self.assertIn("--setuid-accept", r.lines[-1][1])
        # accepted: on the list; a program that left is a detail line, not a fail
        h.owned[c.path] += "/usr/bin/zz-new\n/usr/bin/old-one\n"
        r = kinds.check(c, cx(h), [])
        self.assertEqual((r.status, r.have), ("pass", "28 known, 1 gone"))
        self.assertEqual(r.lines, [("gone", "/usr/bin/old-one")])
        # many new ones: the fix line stays
        h.setuid += [f"/usr/bin/n{i:02d}" for i in range(20)]
        r = kinds.check(c, cx(h), [])
        self.assertEqual((r.status, r.have), ("fail", "20 new: /usr/bin/n00 ..."))
        self.assertEqual(len(r.lines), kinds.MAX_LINES)
        self.assertEqual(r.lines[-1][0], "fix")
        del h.owned[c.path]
        self.assertEqual(res(c, h), ("fail", "no list"))
        h.owned[c.path] = ConfigError("/etc/sectop/setuid-known.txt: group/other writable")
        self.assertEqual(res(c, h)[0], "unknown")
        h.owned[c.path] = ""
        h.setuid = PermissionError(13, "Permission denied")
        self.assertEqual(res(c, h), ("unknown", "/usr: Permission denied"))
        self.assertEqual(kinds.want_text(c), "none new")

    def test_real_read_owned(self):
        h = kinds.Host()
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(h.read_owned(os.path.join(d, "no-dir", "none.txt")))
            if os.getuid() != 0:                       # not root-owned: refused
                p = os.path.join(d, "l.txt")
                with open(p, "w") as f:
                    f.write("/usr/bin/su\n")
                with self.assertRaises(ConfigError):
                    h.read_owned(p)

    def test_free_space(self):
        c = chk(kind="free-space", path="/var/log/audit", min_mb=2048)
        h = FakeHost()
        r = kinds.check(c, cx(h), [])
        self.assertEqual((r.status, r.have), ("pass", "12.0 GiB free"))
        self.assertEqual(r.lines, [("free", "12288 MiB of 61440 MiB"), ("want", ">= 2048 MiB")])
        h.vfs["/var/log/audit"] = (4096, 300 * 256, 60 * 2**18)          # 300 MiB
        self.assertEqual(res(c, h), ("fail", "300 MiB free"))
        self.assertEqual(res(chk(kind="free-space", path="/nope", min_mb=1), h),
                         ("unknown", "No such file or directory"))
        self.assertEqual(kinds.want_text(c), ">= 2.0 GiB free")


def change(cursor, msg):
    return {"__CURSOR": cursor, "_TRANSPORT": "audit", "_AUDIT_TYPE": "1305", "MESSAGE": msg}


ADD = ('CONFIG_CHANGE auid=4294967295 ses=4294967295 subj=system_u:system_r:auditctl_t:s0 '
       'op=add_rule key="identity" list=4 res=1')
REMOVE = 'CONFIG_CHANGE auid=1000 ses=3 op=remove_rule key="identity" list=4 res=1'
FAILED = 'CONFIG_CHANGE auid=1000 ses=3 op=add_rule key="x" list=4 res=0'
OFF = "CONFIG_CHANGE op=set audit_enabled=0 old=1 auid=1000 ses=3 res=1"
LOCK = ("CONFIG_CHANGE op=set audit_enabled=2 old=1 auid=4294967295 ses=4294967295 "
        "subj=system_u:system_r:unconfined_service_t:s0 res=1")
OFF_REFUSED = "CONFIG_CHANGE op=set audit_enabled=0 old=2 auid=1000 ses=3 res=0"


class TestAuditJournal(unittest.TestCase):
    def test_scan_then_follow_no_double_count(self):
        st = pos.State(checks=(), wall=lambda: NOW)
        out = "\n".join(json.dumps(change(f"c{i}", ADD)) for i in range(3)) + "\nnot json\n"
        calls = []

        def run(argv, timeout):
            calls.append(argv)
            return Result(0, out, "")
        pos.boot_scan(st, run)
        self.assertEqual((st.audit.added, st.audit.until), (3, NOW + pos.SCAN_KEEP))
        self.assertIn("_AUDIT_TYPE=1305", calls[0])
        self.assertIn("-b", calls[0])
        pos.follow(st, [change("c2", ADD), change("c3", REMOVE), change("c4", FAILED),
                        change("c5", OFF), {"_TRANSPORT": "kernel", "MESSAGE": ADD}], NOW + 1)
        self.assertEqual((st.audit.added, st.audit.removed, st.audit.enabled), (3, 1, "0"))
        self.assertEqual(st.audit.keys, {"identity": 2})                 # 3 added, 1 removed
        pos.follow(st, [], NOW + pos.SCAN_KEEP + 1)
        self.assertEqual(st.audit.cursors, set())                       # overlap over

    def test_lock_then_refused_off(self):
        """-e 2 at boot, then `auditctl -e 0`: refused (res=0), still locked."""
        st = pos.State(checks=(), wall=lambda: NOW)
        pos.boot_scan(st, lambda argv, timeout: Result(0, json.dumps(change("c1", LOCK)), ""))
        pos.follow(st, [change("c2", OFF_REFUSED)], NOW + 1)
        self.assertEqual(st.audit.enabled, "2")

    def test_scan_failed(self):
        st = pos.State(checks=(), wall=lambda: NOW)
        pos.boot_scan(st, lambda argv, timeout: Result(1, "", "Failed to open journal\n"))
        self.assertEqual(st.audit.err, "journal scan: Failed to open journal")

    def test_follower_gives_it(self):
        want = corejournal.wants(corejournal.spec(pos.JOURNAL).groups)
        self.assertTrue(corejournal.matches(change("c", ADD), want))
        self.assertFalse(corejournal.matches({**change("c", ADD), "_AUDIT_TYPE": "1300"}, want))


class TestModule(unittest.TestCase):
    def test_api(self):
        check_module(pos)
        self.assertEqual(pos.INTERVAL, 300.0)
        s = SCREENS[find("security")]
        self.assertEqual(s.modules, ("security", "posture"))

    def test_deploy_policy_parses(self):
        with open(DEPLOY, "rb") as f:
            checks = policy.parse(f.read(), DEPLOY)
        ids = [c.id for c in checks]
        self.assertEqual(len(ids), len(set(ids)))
        crit = {c.id for c in checks if c.sev == "crit"}
        self.assertEqual(crit, {"selinux-enforcing", "audit-boot", "audit-enabled",
                                "auditd-active", "firewalld-active", "firewalld-zone", "uid0",
                                "wheel", "luks-var", "ostree-locked", "ostree-gpg", "listeners",
                                "secure-boot", "mac-random", "hostname", "fwupd-no-reports",
                                "auditd-logging"})
        refs = {c.id for c in checks if c.ref}
        self.assertEqual(refs, set())                                    # step 9 done
        self.assertEqual(set(policy.KINDS) - {c.kind for c in checks}, set())   # all used

    def test_host_like_mine(self):
        """Deploy policy as install.sh writes it (admin "admin") on a host like mine after
        step 9 (2026-10-26) and the account split (2026-11-05): all pass."""
        with open(DEPLOY, "rb") as f:
            checks = policy.parse(f.read().replace(b'"@admin"', b'"admin"'), DEPLOY)
        h = FakeHost()
        h.files["/etc/group"] = ("wheel:x:10:admin\nsugroup:x:1001:\nmullvad:x:953:admin\n"
                                 "sectop:x:954:admin\nsectop-feed:x:955:\n")
        h.blobs[kinds.SECUREBOOT] = bytes([6, 0, 0, 0, 1])               # mokutil: enabled
        h.files["/sys/kernel/security/lockdown"] = "none [integrity] confidentiality\n"
        h.files["/proc/sys/kernel/tainted"] = "0\n"
        want = {u: s for c in checks if c.kind == "units" for u, s in c.units}
        h.answers["systemctl show"] = lambda argv: Result(0, "\n\n".join(   # in argv order
            f"Id={u}\nLoadState=loaded\nActiveState={want[u] if want[u] == 'active' else 'inactive'}"
            f"\nUnitFileState={want[u] if want[u] != 'active' else 'enabled'}"
            for u in argv[argv.index("--") + 1:]), "")
        by_lines = set()
        for c in checks:
            if c.kind == "sysctl":
                h.sysctl.update(dict(c.values))
            if c.kind == "lines" and (c.path not in h.files or c.path in by_lines):
                h.files[c.path] = h.files.get(c.path, "") + "\n".join(c.want) + "\n"
                by_lines.add(c.path)                # 90-privacy.conf: two checks
            if c.kind == "perms":
                h.stats[c.path] = (0o100000 | c.mode, 0, GIDS[c.owner.split(":")[1]])
            if c.kind == "listeners":
                allow = c.allow
        h.files.update({"/etc/systemd/coredump.conf.d/90-cis.conf": "[Coredump]\nStorage=none\n"
                                                                    "ProcessSizeMax=0\n",
                        "/etc/systemd/journald.conf.d/90-cis.conf": "[Journal]\n"
                                                                    "Storage=persistent\n",
})
        self.assertTrue(allow)
        st = pos.State(checks=checks, host=h, wall=lambda: NOW, stamp=lambda ts: "12:00:00")
        st.audit.added = 107  # 2026-11-21: 53 + two per setuid program (27, one per arch)
        st.audit.keys["privileged"] = 54
        h.dirs["/etc/fwupd/remotes.d"] = ["lvfs.conf", "lvfs-testing.conf"]
        for n in h.dirs["/etc/fwupd/remotes.d"]:
            h.files[f"/etc/fwupd/remotes.d/{n}"] = (
                "[fwupd Remote]\n#ReportURI=https://fwupd.org/lvfs/firmware/report\n"
                "AutomaticReports=false\nAutomaticSecurityReports=false\n")
        h.files["/etc/systemd/system/fwupd-refresh.timer.d/50-schedule.conf"] = (
            "# x\n[Timer]\nOnCalendar=\nOnCalendar=*-*-1/2\n")
        st.audit.enabled = "2"   # -e 2 at boot
        snap = validate(pos.collect(st, Context((), True, "")))
        got = {r["cells"][0]: r["cells"][1] for r in snap["panels"][0]["rows"]}
        self.assertEqual({k: v for k, v in got.items() if v != "pass"}, {})
        self.assertEqual(snap["checks"], [])
        self.assertEqual(snap["summary"], f"pass {len(checks)} | fail 0 | unknown 0 | "
                                          "accepted 0")
        self.assertEqual((got["secure-boot"], got["lockdown"], got["taint"]),
                         ("pass", "pass", "pass"))

    def test_host_secure_boot_off_again(self):
        """After step 9 Secure Boot off is crit + alert; lockdown none is warn, no alert."""
        with open(DEPLOY, "rb") as f:
            checks = [c for c in policy.parse(f.read(), DEPLOY)
                      if c.id in ("secure-boot", "lockdown")]
        st = pos.State(checks=checks, host=FakeHost(), wall=lambda: NOW,
                       stamp=lambda ts: "12:00:00")
        snap = validate(pos.collect(st, Context((), True, "")))
        rows = {r["cells"][0]: (r["cells"][1], r["sev"]) for r in snap["panels"][0]["rows"]}
        self.assertEqual(rows, {"secure-boot": ("fail", "crit"), "lockdown": ("fail", "warn")})
        self.assertEqual([c["key"] for c in snap["checks"]], ["secure-boot"])

    def test_rows_order_and_alerts(self):
        h = FakeHost()
        h.files["/sys/fs/selinux/enforce"] = "0"
        checks = (chk(id="a", path="/etc/selinux/config", key="SELINUX", want="enforcing"),
                  chk(id="b", kind="secureboot", ref="later"),
                  chk(id="c", path="/etc/nope", want="1", sev="warn"),
                  chk(id="d", path="/sys/fs/selinux/enforce", want="1", sev="crit",
                      why="SELinux enforcing now"),
                  chk(id="e", kind="sysctl", values=(("net.core.bpf_jit_harden", "2"),)),
                  chk(id="f", kind="secureboot", sev="crit"))
        st = pos.State(checks=checks, host=h, wall=lambda: NOW, stamp=lambda ts: "12:00:00")
        snap = validate(pos.collect(st, Context((), True, "")))
        rows = snap["panels"][0]["rows"]
        self.assertEqual([(r["cells"][0], r["cells"][1], r["sev"]) for r in rows],
                         [("d", "fail", "crit"), ("f", "fail", "crit"), ("c", "fail", "warn"),
                          ("e", "unknown", "warn"), ("b", "accepted", "ok"), ("a", "pass", "ok")])
        self.assertEqual(sorted((c["key"], c["title"]) for c in snap["checks"]),
                         [("d", "SELinux enforcing now: 0"), ("f", "w: off")])  # crit, no ref
        p = snap["panels"][0]
        self.assertEqual(p["title"], "posture 6  (3 fail, 1 unknown, 1 accepted; every 5 min, "
                                     "last 12:00:00)")
        d = {it["k"]: it["v"] for it in rows[4]["detail"]}
        self.assertEqual((d["ref"], d["kind"], d["checked"]), ("later", "secureboot", "12:00:00"))

    def test_no_policy_file(self):
        with PolicyFile(None):
            st = pos.init({})
        self.assertEqual((st.checks, st.policy_file), ((), False))
        snap = validate(pos.collect(st, Context((), True, "")))
        self.assertEqual((snap["summary"], snap["panels"][0]["rows"]), ("no posture.toml", []))
        with self.assertRaises(ValueError):
            pos.init({"x": 1})

    def test_bad_policy_file(self):
        bad = [b'[[check]]\nid = "x"\nkind = "nope"\nsev = "warn"\nwhy = "w"\n',
               b'[[check]]\nid = "x"\nkind = "file"\nsev = "warn"\nwhy = "w"\npath = "/a"\n',
               b'[[check]]\nid = "x"\nkind = "file"\nsev = "warn"\nwhy = "w"\npath = "/a"\n'
               b'want = "1"\ncmd = "rm"\n',
               b'[[check]]\nid = "x"\nkind = "file"\nsev = "bad"\nwhy = "w"\npath = "/a"\n'
               b'want = "1"\n',
               b'[[check]]\nid = "x"\nkind = "file"\nsev = "warn"\nwhy = "w"\npath = "a"\n'
               b'want = "1"\n',
               b'[[check]]\nid = "x"\nkind = "file"\nsev = "warn"\nwhy = "w"\npath = "/a/../b"\n'
               b'want = "1"\n',
               b'[[check]]\nid = "x"\nkind = "file"\nsev = "warn"\nwhy = "w"\npath = "/a"\n'
               b'want = "x"\nop = ">="\n',
               b'[[check]]\nid = "x"\nkind = "units"\nsev = "warn"\nwhy = "w"\n'
               b'units = { "-x" = "active" }\n',
               b'[[check]]\nid = "x"\nkind = "listeners"\nsev = "warn"\nwhy = "w"\n'
               b'allow = ["0.0.0.0:22"]\n',
               b'[[check]]\nid = "x"\nkind = "listeners"\nsev = "warn"\nwhy = "w"\n'
               b'allow = []\nwireguard = "a b"\n',
               b'[[check]]\nid = "x"\nkind = "listeners"\nsev = "warn"\nwhy = "w"\n'
               b'allow = []\ntunnel_owner = "mullvad-daemon"\n',
               b'[[check]]\nid = "x"\nkind = "listeners"\nsev = "warn"\nwhy = "w"\n'
               b'allow = []\nwireguard = "wg0"\ntunnel_owner = "a b"\n',
               b'[[check]]\nid = "x"\nkind = "taint"\nsev = "warn"\nwhy = "w"\nwant = "O"\n'
               b'[[check]]\nid = "x"\nkind = "taint"\nsev = "warn"\nwhy = "w"\nwant = "O"\n',
               b'[[check]]\nid = "x"\nkind = "hostname"\nsev = "warn"\nwhy = "w"\n'
               b'want = "-bad"\n',
               b'[[check]]\nid = "x"\nkind = "nm-props"\nsev = "warn"\nwhy = "w"\n'
               b'types = []\nprops = { "ipv4.method" = "disabled" }\n',
               b'[[check]]\nid = "x"\nkind = "nm-props"\nsev = "warn"\nwhy = "w"\n'
               b'types = ["802-11-wireless"]\nprops = { "method" = "disabled" }\n',
               b'[[check]]\nid = "x"\nkind = "mac-local"\nsev = "warn"\nwhy = "w"\nwant = "x"\n',
               b'[[check]]\nid = "x"\nkind = "dns-servers"\nsev = "warn"\nwhy = "w"\n',
               b'[[check]]\nid = "x"\nkind = "dns-servers"\nsev = "warn"\nwhy = "w"\n'
               b'allow = ["wg0 mullvad"]\n',
               b'[[check]]\nid = "x"\nkind = "nm-props"\nsev = "warn"\nwhy = "w"\n'
               b'types = ["802-11-wireless"]\nprops = { "ipv4.dns" = "\\u00e9" }\n',
               b'[[check]]\nid = "x"\nkind = "audit-rules"\nsev = "warn"\nwhy = "w"\nwant = 47\n'
               b'setuid_key = "a b"\n',
               b'[[check]]\nid = "x"\nkind = "audit-rules"\nsev = "warn"\nwhy = "w"\nwant = 47\n'
               b'setuid_key = 1\n',
               b'[[check]]\nid = "x"\nkind = "audit-rules"\nsev = "warn"\nwhy = "w"\nwant = 53\n'
               b'setuid_key = "privileged"\nsetuid_rules = 3\n',
               b'[[check]]\nid = "x"\nkind = "audit-rules"\nsev = "warn"\nwhy = "w"\nwant = 53\n'
               b'setuid_key = "privileged"\nsetuid_rules = "2"\n',
               b'[[check]]\nid = "x"\nkind = "audit-rules"\nsev = "warn"\nwhy = "w"\nwant = 53\n'
               b'setuid_rules = 2\n',
               b'[[check]]\nid = "x"\nkind = "fwupd-reports"\nsev = "warn"\nwhy = "w"\n',
               b'[[check]]\nid = "x"\nkind = "free-space"\nsev = "warn"\nwhy = "w"\npath = "/a"\n',
               b'[[check]]\nid = "x"\nkind = "free-space"\nsev = "warn"\nwhy = "w"\npath = "/a"\n'
               b'min_mb = "2048"\n',
               b'[[check]]\nid = "x"\nkind = "free-space"\nsev = "warn"\nwhy = "w"\npath = "/a"\n'
               b'min_mb = 0\n',
               b'[[check]]\nid = "x"\nkind = "audit-load"\nsev = "warn"\nwhy = "w"\n'
               b'path = "/a"\n',
               b'[[check]]\nid = "x"\nkind = "setuid-known"\nsev = "warn"\nwhy = "w"\n',
               b'[[check]]\nid = "x"\nkind = "file"\nsev = "warn"\nwhy = "w"\npath = "/a"\n'
               b'want = "1"\nsetuid_key = "privileged"\n',
               b'[[check]]\nid = "x"\nkind = "file"\nsev = "warn"\nwhy = "w"\npath = "/a"\n'
               b'want = "1"\nkey = "K"\nsep = "tab"\n',
               b'[[check]]\nid = "x"\nkind = "file"\nsev = "warn"\nwhy = "w"\npath = "/a"\n'
               b'want = "1"\nsep = "space"\n',
               b'[[check]]\nid = "x"\nkind = "lines"\nsev = "warn"\nwhy = "w"\npath = "/a"\n'
               b'want = ["a"]\nsep = "space"\n',
               b'[[nope]]\n']
        for data in bad:
            with self.subTest(data=data), self.assertRaises(ConfigError):
                policy.parse(data)
        with PolicyFile(bad[0]), self.assertRaises(ConfigError):
            pos.init({})

    def test_one_bad_kind_only_its_row(self):
        h = FakeHost()

        def boom(path):
            raise ValueError("bug")
        h.read = boom
        st = pos.State(checks=(chk(id="a", path="/x", want="1"),
                               chk(id="b", kind="secureboot", sev="warn")),
                       host=h, wall=lambda: NOW)
        snap = validate(pos.collect(st, Context((), True, "")))
        got = {r["cells"][0]: (r["cells"][1], r["cells"][2]) for r in snap["panels"][0]["rows"]}
        self.assertEqual(got, {"a": ("unknown", "ValueError: bug"), "b": ("fail", "off")})

    def test_real_host_class(self):
        """kinds.Host on this machine: files and stat work, nothing raises unexpectedly."""
        h = kinds.Host()
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "f")
            with open(p, "w", encoding="ascii") as f:
                f.write("deny = 5\n")
            self.assertEqual(h.read(p), "deny = 5\n")
            self.assertTrue(stat.S_ISREG(h.stat(p).st_mode))
            self.assertGreater(h.statvfs(d).f_frsize, 0)
            self.assertEqual(h.listdir(d), ["f"])
            self.assertEqual(h.user(os.getuid()), h.user(os.getuid()))


class PolicyFile:
    """pos.POLICY_PATH -> a file with this content (None: missing), owned by me."""

    def __init__(self, data):
        self.data = data

    def __enter__(self):
        self.dir = tempfile.TemporaryDirectory()
        os.chmod(self.dir.name, 0o755)
        path = os.path.join(self.dir.name, "posture.toml")
        if self.data is not None:
            with open(path, "wb") as f:
                f.write(self.data)
            os.chmod(path, 0o644)
        self.saved = (pos.POLICY_PATH, pos.POLICY_OWNER)
        pos.POLICY_PATH, pos.POLICY_OWNER = path, os.getuid()
        return self

    def __exit__(self, *exc):
        pos.POLICY_PATH, pos.POLICY_OWNER = self.saved
        self.dir.cleanup()


if __name__ == "__main__":
    unittest.main()
