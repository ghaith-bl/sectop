"""Posture check kinds (docs/modules/posture.md, Kinds). One function per kind.

Each takes the check (policy.Check) and the collect context (Cx: host access, the
audit counts, per-collect caches) and returns a Res: pass / fail / unknown, what was
found (`have`, one short line) and detail lines. Reads files where a file exists;
commands only where there is no file (systemctl, firewall-cmd, nmcli, rpm-ostree,
hostnamectl, ss for socket owners, resolvectl, journalctl for two units' own lines),
fixed argv, run as user sectop. Nothing here changes the host.
"""

import fnmatch
import grp
import ipaddress
import json
import os
import pwd
import re
import stat
import time
from dataclasses import dataclass, field

from core import homed, netd
from core.config import ConfigError, read_file
from core.proc import program
from core.run import Result
from core.run import run as core_run
from modules.security.kernel import letters

SYSTEMCTL = "/usr/bin/systemctl"
FIREWALL_CMD = "/usr/bin/firewall-cmd"
NMCLI = "/usr/bin/nmcli"
RPM_OSTREE = "/usr/bin/rpm-ostree"
HOSTNAMECTL = "/usr/bin/hostnamectl"
RESOLVECTL = "/usr/bin/resolvectl"
JOURNALCTL = "/usr/bin/journalctl"
SS = netd.bin_path("ss")
TIMEOUT = 5.0                      # per command; a whole collect stays well under INTERVAL
OSTREE_TIMEOUT = 15.0
OSTREE_EVERY = 86400.0             # rpm-ostree status: once a day (architecture: updates)
SECUREBOOT = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
LOCKDOWN = "/sys/kernel/security/lockdown"
TAINTED = "/proc/sys/kernel/tainted"
CMDLINE = "/proc/cmdline"
MOUNTINFO = "/proc/self/mountinfo"
OSTREE_BOOTED = "/run/ostree-booted"
STAGED = "/run/ostree/staged-deployment"
REMOTES = "/etc/ostree/remotes.d"
PROC_NET = (("tcp", "/proc/net/tcp", 4), ("tcp", "/proc/net/tcp6", 6),
            ("udp", "/proc/net/udp", 4), ("udp", "/proc/net/udp6", 6))
TCP_LISTEN, UDP_UNCONN = "0A", "07"
WIFI = "802-11-wireless"
MAX_WIFI = 32                      # NetworkManager profiles read per check
NET = "/sys/class/net"
ARPHRD_ETHER = "1"                 # /sys/class/net/<if>/type of Ethernet and Wi-Fi
IFNAME_RE = re.compile(r"[A-Za-z0-9_.:@-]{1,15}")
UUID_RE = re.compile(r"[0-9a-f-]{36}")
HOSTNAMES = ("Hostname", "StaticHostname", "DefaultHostname")   # hostnamectl --json
MAX_LINES = 12                     # detail lines per check
MAX_READ = 1024 * 1024
SETUID_ROOT = "/usr"             # audit-rules setuid_key: scanned once (immutable per boot)
KV_RE = r"^\s*{}\s*=\s*(.*?)\s*$"
WS_RE = r"^\s*{}\s+(.*?)\s*$"   # login.defs: KEY, spaces / tabs, value
CGROUP_RE = re.compile(r"(?:^|\s)cgroup:(\S+)")
WILD_UDP = ("udp 0.0.0.0:", "udp [::]:")
LINK_RE = re.compile(r"Link \d+ \(([^)]{1,15})\)")       # resolvectl status section
RKEY_RE = re.compile(r"([A-Za-z][A-Za-z .]*?):(?: (.*)|$)")  # "DNS Servers: a b", not "fe::1"


@dataclass
class Res:
    status: str                    # pass | fail | unknown
    have: str
    lines: list = field(default_factory=list)    # (k, v) detail
    source: str = ""


class Host:
    """What the checks read. Tests give a fake one."""

    def read(self, path: str) -> str:
        with open(path, "rb") as f:
            return f.read(MAX_READ).decode("utf-8", errors="replace")

    def read_bytes(self, path: str) -> bytes:
        with open(path, "rb") as f:
            return f.read(4096)

    def stat(self, path: str):
        return os.stat(path)

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def listdir(self, path: str) -> list:
        return sorted(os.listdir(path))

    def setuid_files(self, root: str = SETUID_ROOT) -> tuple:
        """Regular files with the setuid or setgid bit under root, one file system
        (`find root -xdev -type f -perm /6000`). -> (sorted paths, dirs not readable)."""
        found, unread = [], 0
        dev = os.lstat(root).st_dev                    # OSError: the check says unknown
        stack = [root]
        while stack:
            try:
                it = os.scandir(stack.pop())
            except OSError:
                unread += 1
                continue
            with it:
                for e in it:
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISDIR(st.st_mode):
                        if st.st_dev == dev:
                            stack.append(e.path)
                    elif stat.S_ISREG(st.st_mode) and st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                        found.append(e.path)
        return sorted(found), unread

    def run(self, argv: list, timeout: float = TIMEOUT):
        return core_run(argv, timeout=timeout)

    def statvfs(self, path: str):
        return os.statvfs(path)

    def read_owned(self, path: str) -> str | None:
        """A root-owned list (not group / other writable, no symlink, its folder too):
        core/config.py read_file. None = missing; ConfigError = not safe."""
        data = read_file(path, 0)
        return None if data is None else data.decode("utf-8", errors="replace")

    def home_report(self, user: str) -> tuple:
        """The home watch's last report (core/homed.py): ({path: sig}, home). ValueError."""
        return homed.load_report(user, wall=time.time)

    def wg_listen_port(self, tunnel: str):
        """The net unit's last `wg show <tunnel> listen-port` (core/netd.py Reader)."""
        try:
            reader = netd.Reader(tunnel)
            return reader(list(netd.commands(tunnel)["listen_port"][0]))
        except ValueError as e:
            return Result(1, "", str(e))

    def user(self, uid: int) -> str:
        try:
            return pwd.getpwuid(uid).pw_name
        except KeyError:
            return str(uid)

    def group(self, gid: int) -> str:
        try:
            return grp.getgrgid(gid).gr_name
        except KeyError:
            return str(gid)


class Cx:
    """One collect: the host, the time, audit counts and caches shared by checks."""

    def __init__(self, host: Host, now: float, audit=None, ostree=None, setuid=None):
        self.host, self.now = host, now
        self.audit = audit                     # State audit counts (posture __init__)
        self.ostree = ostree                   # dict: cached rpm-ostree status (ts, res)
        self.setuid = setuid if setuid is not None else {}   # dict: one /usr scan (files, unread)
        self._units = None

    def units(self, names: list) -> dict | str:
        """name -> {LoadState, ActiveState, UnitFileState}; str = error."""
        if self._units is None:
            self._units = _units(self.host, names)
        return self._units


def _err(e: OSError) -> str:
    return e.strerror or type(e).__name__


def _fail_run(res) -> str:
    text = (res.err or res.out).strip().splitlines()
    why = text[-1] if text else f"rc {res.rc}"
    return ("timed out" if res.timed_out else why)[:120]


def compare(have: str, op: str, want: str) -> bool:
    if op == "=":
        return have == want
    if op == "!=":
        return have != want
    if op == "in":
        return have in want.split("|")
    try:
        a, b = int(have), int(want)
    except ValueError:
        return False
    return a >= b if op == ">=" else a <= b


def _want(c) -> str:
    return c.want if c.op == "=" else f"{c.op} {c.want}"


def _value(text: str, key: str, sep: str = "=") -> str | None:
    """`key = value` / `KEY=value`, sep "space": `KEY value` (last one wins, # ; comments),
    or the first line."""
    found = None
    rx = re.compile((WS_RE if sep == "space" else KV_RE).format(re.escape(key))) if key else None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if rx is None:
            return line
        m = rx.match(line)
        if m:
            found = m.group(1).strip().strip("\"'")
    return found


# --- files -------------------------------------------------------------------

def k_file(c, cx: Cx) -> Res:
    src = c.path + (f" {c.key}" if c.key else "")
    try:
        text = cx.host.read(c.path)
    except FileNotFoundError:
        return Res("fail", "missing", source=src)
    except OSError as e:
        return Res("unknown", _err(e), source=src)
    v = _value(text, c.key, c.sep)
    if v is None:
        return Res("fail", "not set", source=src)
    return Res("pass" if compare(v, c.op, c.want) else "fail", v[:60], source=src)


def _norm(line: str) -> str:
    return " ".join(line.split())


def k_lines(c, cx: Cx) -> Res:
    try:
        text = cx.host.read(c.path)
    except FileNotFoundError:
        return Res("fail", "missing", source=c.path)
    except OSError as e:
        return Res("unknown", _err(e), source=c.path)
    have = {_norm(x) for x in text.splitlines() if x.strip() and not x.lstrip().startswith("#")}
    missing = [w for w in c.want if _norm(w) not in have]
    res = Res("fail" if missing else "pass", f"{len(c.want) - len(missing)} of {len(c.want)}",
              source=c.path)
    res.lines = [("missing", m) for m in missing[:MAX_LINES]]
    return res


def k_sysctl(c, cx: Cx) -> Res:
    bad, unread = [], []
    for key, want in c.values:
        path = "/proc/sys/" + key.replace(".", "/")
        try:
            have = " ".join(cx.host.read(path).split())
        except OSError as e:
            unread.append(f"{key}: {_err(e)}")
            continue
        if have != want:
            bad.append(f"{key} = {have} (want {want})")
    n = len(c.values)
    status = "fail" if bad else ("unknown" if unread else "pass")
    res = Res(status, f"{n - len(bad) - len(unread)} of {n}", source="/proc/sys")
    res.lines = [("differs", b) for b in bad] + [("unread", u) for u in unread]
    res.lines = res.lines[:MAX_LINES]
    return res


def k_cmdline(c, cx: Cx) -> Res:
    try:
        words = set(cx.host.read(CMDLINE).split())
    except OSError as e:
        return Res("unknown", _err(e), source=CMDLINE)
    missing = [w for w in c.want if w not in words]
    res = Res("fail" if missing else "pass",
              "missing " + " ".join(missing) if missing else " ".join(c.want), source=CMDLINE)
    return res


def k_taint(c, cx: Cx) -> Res:
    try:
        value = int(cx.host.read(TAINTED).strip())
    except (OSError, ValueError) as e:
        return Res("unknown", getattr(e, "strerror", None) or str(e)[:60], source=TAINTED)
    have = letters(value).split()
    allowed = set(c.want.split())
    extra = [x for x in have if x not in allowed]
    res = Res("fail" if extra else "pass", " ".join(have) or "none", source=TAINTED)
    res.lines = [("value", str(value))] + ([("not expected", " ".join(extra))] if extra else [])
    return res


def _mounts(cx: Cx) -> list:
    """-> [(mount point, fstype, source)] from mountinfo (order kept: last wins)."""
    out = []
    for line in cx.host.read(MOUNTINFO).splitlines():
        left, sep, right = line.partition(" - ")
        a, b = left.split(), right.split()
        if sep and len(a) >= 5 and len(b) >= 2:
            out.append((a[4].replace("\\040", " "), b[0], b[1]))
    return out


def _dm_uuids(cx: Cx, dm: str, depth: int = 0) -> list:
    """dm-N -> its dm uuid, then the uuids under it (LVM on LUKS)."""
    base = f"/sys/block/{dm}"
    out = [cx.host.read(f"{base}/dm/uuid").strip()]
    if depth < 4:
        try:
            slaves = cx.host.listdir(f"{base}/slaves")
        except OSError:
            slaves = []
        for s in slaves:
            if s.startswith("dm-"):
                out += _dm_uuids(cx, s, depth + 1)
    return out


def k_luks(c, cx: Cx) -> Res:
    try:
        mounts = [m for m in _mounts(cx) if m[0] == c.path]
    except OSError as e:
        return Res("unknown", _err(e), source=MOUNTINFO)
    if not mounts:
        return Res("unknown", f"{c.path} not mounted", source=MOUNTINFO)
    _, fstype, source = mounts[-1]
    dm = None
    try:
        if source.startswith("/dev/dm-"):
            dm = os.path.basename(source)
        elif source.startswith("/dev/mapper/"):
            name = os.path.basename(source)
            for d in cx.host.listdir("/sys/block"):
                if d.startswith("dm-") and cx.host.read(f"/sys/block/{d}/dm/name").strip() == name:
                    dm = d
                    break
        if dm is None:
            return Res("fail", f"{fstype} on {source}: not device-mapper", source=MOUNTINFO)
        uuids = _dm_uuids(cx, dm)
    except OSError as e:
        return Res("unknown", _err(e), source="/sys/block")
    luks = next((u for u in uuids if u.startswith("CRYPT-LUKS")), None)
    have = luks.split("-")[1] if luks else (uuids[0].split("-")[0] or "no dm uuid")
    res = Res("pass" if luks else "fail", have, source=f"{MOUNTINFO}, /sys/block")
    res.lines = [("fs", f"{fstype} on {dm}")]           # never the uuid itself
    return res


def k_secureboot(c, cx: Cx) -> Res:
    try:
        b = cx.host.read_bytes(SECUREBOOT)
    except FileNotFoundError:
        efi = cx.host.exists("/sys/firmware/efi")
        return Res("fail" if efi else "unknown", "no SecureBoot variable" if efi else "no EFI",
                   source=SECUREBOOT)
    except OSError as e:
        return Res("unknown", _err(e), source=SECUREBOOT)
    if len(b) < 5:
        return Res("unknown", "short variable", source=SECUREBOOT)
    on = b[4] == 1                     # 4 bytes attributes, then the value
    return Res("pass" if on else "fail", "on" if on else "off", source=SECUREBOOT)


def k_lockdown(c, cx: Cx) -> Res:
    try:
        text = cx.host.read(LOCKDOWN)
    except OSError as e:
        return Res("unknown", _err(e), source=LOCKDOWN)
    m = re.search(r"\[(\w+)\]", text)
    if m is None:
        return Res("unknown", "no [mode]", source=LOCKDOWN)
    return Res("pass" if compare(m.group(1), "in", c.want) else "fail", m.group(1),
               source=LOCKDOWN)


def _passwd_like(cx: Cx, path: str) -> list:
    return [line.split(":") for line in cx.host.read(path).splitlines() if line.count(":") >= 3]


def k_uid0(c, cx: Cx) -> Res:
    try:
        names = [f[0] for f in _passwd_like(cx, "/etc/passwd") if len(f) > 2 and f[2] == "0"]
    except OSError as e:
        return Res("unknown", _err(e), source="/etc/passwd")
    ok = sorted(names) == sorted(c.want)
    return Res("pass" if ok else "fail", " ".join(names) or "none", source="/etc/passwd")


def k_group(c, cx: Cx) -> Res:
    try:
        rows = [f for f in _passwd_like(cx, "/etc/group") if f[0] == c.group]
    except OSError as e:
        return Res("unknown", _err(e), source="/etc/group")
    if not rows:
        return Res("fail", f"no group {c.group}", source="/etc/group")
    members = [m for m in rows[-1][3].strip().split(",") if m]
    extra = [m for m in members if m not in c.want]
    res = Res("fail" if extra else "pass", " ".join(members) or "empty", source="/etc/group")
    if extra:
        res.lines = [("not allowed", " ".join(extra))]
    return res


def k_perms(c, cx: Cx) -> Res:
    try:
        st = cx.host.stat(c.path)
    except FileNotFoundError:
        return Res("fail", "missing", source=c.path)
    except OSError as e:
        return Res("unknown", _err(e), source=c.path)
    mode = st.st_mode & 0o7777
    owner = f"{cx.host.user(st.st_uid)}:{cx.host.group(st.st_gid)}"
    ok = not (mode & ~c.mode) and owner == c.owner
    return Res("pass" if ok else "fail", f"{mode:o} {owner}", source=c.path)


def _remotes(text: str) -> list:
    """-> [(remote, gpg-verify value or None)] of one remotes.d file."""
    out, name = [], None
    for raw in text.splitlines():
        line = raw.strip()
        m = re.fullmatch(r'\[remote "([^"]+)"\]', line)
        if m:
            name = m.group(1)
            out.append([name, None])
        elif name and re.match(r"gpg-verify\s*=", line):
            out[-1][1] = line.split("=", 1)[1].strip()
    return [tuple(x) for x in out]


def k_ostree_gpg(c, cx: Cx) -> Res:
    try:
        files = [f for f in cx.host.listdir(REMOTES) if f.endswith(".conf")]
        remotes = [r for f in files for r in _remotes(cx.host.read(f"{REMOTES}/{f}"))]
    except OSError as e:
        return Res("unknown", _err(e), source=REMOTES)
    if not remotes:
        return Res("unknown", "no remotes", source=REMOTES)
    off = [n for n, v in remotes if v is not None and v.lower() != "true"]   # default true
    res = Res("fail" if off else "pass", f"{len(remotes) - len(off)} of {len(remotes)} verify",
              source=REMOTES)
    if off:
        res.lines = [("gpg-verify off", " ".join(off))]
    return res


def k_ostree_unlocked(c, cx: Cx) -> Res:
    if not cx.host.exists(OSTREE_BOOTED):
        return Res("unknown", "not an ostree system", source=OSTREE_BOOTED)
    try:
        over = [m for m in _mounts(cx) if m[0] == "/usr" and m[1] == "overlay"]
    except OSError as e:
        return Res("unknown", _err(e), source=MOUNTINFO)
    return Res("fail" if over else "pass", "unlocked: overlay on /usr" if over else "locked",
               source=MOUNTINFO)


def k_ostree_staged(c, cx: Cx) -> Res:
    if not cx.host.exists(OSTREE_BOOTED):
        return Res("unknown", "not an ostree system", source=OSTREE_BOOTED)
    staged = cx.host.exists(STAGED)
    return Res("fail" if staged else "pass", "staged, reboot to use it" if staged else "none",
               source=STAGED)


def _ostree_status(cx: Cx) -> tuple:
    """-> (booted timestamp or None, error). rpm-ostree once a day, cached."""
    cache = cx.ostree
    if cache is not None and cache.get("ts") is not None and \
            cx.now - cache["ts"] < OSTREE_EVERY and cache.get("err") is None:
        return cache["stamp"], None
    res = cx.host.run([RPM_OSTREE, "status", "--json"], timeout=OSTREE_TIMEOUT)
    stamp, err = None, None
    if res.rc != 0 or res.timed_out or res.truncated:
        err = _fail_run(res)
    else:
        try:
            deps = json.loads(res.out)["deployments"]
            stamp = float(next(d for d in deps if d.get("booted"))["timestamp"])
        except (ValueError, KeyError, TypeError, StopIteration):
            err = "rpm-ostree status: no booted deployment"
    if cache is not None:
        cache.update(ts=cx.now, stamp=stamp, err=err)
    return stamp, err


def k_ostree_age(c, cx: Cx) -> Res:
    stamp, err = _ostree_status(cx)
    if err:
        return Res("unknown", err, source="rpm-ostree status --json")
    days = int((cx.now - stamp) // 86400)
    res = Res("fail" if days > c.max_days else "pass", f"{days} day{'' if days == 1 else 's'}",
              source="rpm-ostree status --json (once a day)")
    res.lines = [("booted commit", time.strftime("%Y-%m-%d", time.localtime(stamp)))]
    return res


def k_firewalld_zone(c, cx: Cx) -> Res:
    res = cx.host.run([FIREWALL_CMD, "--get-default-zone"])
    src = "firewall-cmd --get-default-zone"
    if res.rc != 0 or res.timed_out:
        return Res("unknown", _fail_run(res), source=src)
    zone = res.out.strip()
    return Res("pass" if zone == c.want else "fail", zone or "?", source=src)


def k_wifi_ipv6(c, cx: Cx) -> Res:
    src = "nmcli ipv6.method of every wifi profile"
    res = cx.host.run([NMCLI, "-g", "UUID,TYPE", "connection", "show"])
    if res.rc != 0 or res.timed_out:
        return Res("unknown", _fail_run(res), source=src)
    uuids = [ln.split(":", 1)[0] for ln in res.out.splitlines()
             if ln.count(":") == 1 and ln.split(":", 1)[1] == WIFI]
    bad, unread = [], []
    for u in uuids[:MAX_WIFI]:
        if not re.fullmatch(r"[0-9a-f-]{36}", u):
            continue
        r = cx.host.run([NMCLI, "-g", "ipv6.method", "connection", "show", u])
        if r.rc != 0 or r.timed_out:
            unread.append(u)
        elif r.out.strip() != c.want:
            bad.append(f"{u} {r.out.strip()}")
    n = min(len(uuids), MAX_WIFI)
    status = "fail" if bad else ("unknown" if unread else "pass")
    out = Res(status, f"{n - len(bad) - len(unread)} of {n} {c.want}", source=src)
    out.lines = ([("not " + c.want, b) for b in bad] + [("unread", u) for u in unread])
    out.lines = out.lines[:MAX_LINES]                    # uuids only, never names
    return out


def _profiles(cx: Cx, types) -> list | str:
    """-> uuids of the NetworkManager profiles of these types (max MAX_WIFI); str = error."""
    res = cx.host.run([NMCLI, "-g", "UUID,TYPE", "connection", "show"])
    if res.rc != 0 or res.timed_out:
        return _fail_run(res)
    out = []
    for ln in res.out.splitlines():
        u, _, t = ln.partition(":")
        if t in types and UUID_RE.fullmatch(u):
            out.append(u)
    return out[:MAX_WIFI]


def k_nm_props(c, cx: Cx) -> Res:
    names = [p for p, _ in c.props]
    src = f"nmcli {','.join(names)} of every {' / '.join(c.types)} profile"
    uuids = _profiles(cx, c.types)
    if isinstance(uuids, str):
        return Res("unknown", uuids, source=src)
    bad, unread = [], []
    for u in uuids:
        r = cx.host.run([NMCLI, "-g", ",".join(names), "connection", "show", u])
        vals = [v.strip() for v in r.out.splitlines()]
        if r.rc != 0 or r.timed_out or len(vals) != len(names):
            unread.append(u)
            continue
        bad += [(u, f"{p}={v}") for (p, want), v in zip(c.props, vals)
                if not compare(v, "in", want)]
    n_bad = len({u for u, _ in bad})
    n = len(uuids)
    status = "fail" if bad else ("unknown" if unread else "pass")
    out = Res(status, f"{n - n_bad - len(unread)} of {n} profiles", source=src)
    out.lines = ([("differs", f"{u} {pv}") for u, pv in bad] + [("unread", u) for u in unread])
    out.lines = out.lines[:MAX_LINES]                    # uuids only, never names
    return out


# --- network identity (silverblue-cis-hardening netprivacy) --------------------

def k_mac_local(c, cx: Cx) -> Res:
    """Every physical Ethernet / Wi-Fi link that is up has a locally administered MAC
    (bit 0x02 of the first byte): set by NetworkManager (cloned MAC, random). A
    hardware MAC never has it. The address itself is never shown."""
    src = f"{NET}/*/address (physical links that are up)"
    try:
        names = cx.host.listdir(NET)
    except OSError as e:
        return Res("unknown", _err(e), source=NET)
    local, real, unread = [], [], []
    for name in names:
        base = f"{NET}/{name}"
        if not IFNAME_RE.fullmatch(name) or not cx.host.exists(f"{base}/device"):
            continue                                     # virtual: bridge, tunnel, veth
        try:
            if cx.host.read(f"{base}/type").strip() != ARPHRD_ETHER:
                continue
            if cx.host.read(f"{base}/operstate").strip() != "up":
                continue                                 # NetworkManager sets it on connect
            first = int(cx.host.read(f"{base}/address").strip()[:2], 16)
        except (OSError, ValueError):
            unread.append(name)
            continue
        (local if first & 0x02 else real).append(name)
    if real:
        have = "hardware MAC: " + " ".join(real)
    elif local:
        have = f"{len(local)} up, all local"
    else:
        have = "unread: " + " ".join(unread) if unread else "no link up"
    out = Res("fail" if real else ("unknown" if unread else "pass"), have, source=src)
    out.lines = ([("hardware MAC", n) for n in real] + [("local", n) for n in local] +
                 [("unread", n) for n in unread])[:MAX_LINES]
    return out


def k_hostname(c, cx: Cx) -> Res:
    """hostnamed, not /proc/sys/kernel/hostname: sectop.service has ProtectHostname=yes,
    its own copy of the name from its start."""
    src = "hostnamectl --json=short"
    res = cx.host.run([HOSTNAMECTL, "--json=short"])
    if res.rc != 0 or res.timed_out or res.truncated:
        return Res("unknown", _fail_run(res), source=src)
    try:
        d = json.loads(res.out)
    except ValueError:
        d = None
    if not isinstance(d, dict):
        return Res("unknown", "hostnamectl: no JSON object", source=src)
    bad = [(k, str(d.get(k))[:64]) for k in HOSTNAMES if d.get(k) != c.want]
    if d.get("PrettyHostname"):
        bad.append(("PrettyHostname", str(d["PrettyHostname"])[:64]))
    out = Res("fail" if bad else "pass", str(d.get("Hostname"))[:64], source=src)
    out.lines = [("differs", f"{k} = {v}") for k, v in bad]
    return out


def resolved_servers(text: str) -> tuple | None:
    """`resolvectl status` -> (global, fallback, {link: servers}), None without a Global
    section. Servers on the key's line or on the lines under it (no key there)."""
    glob, fallback, links = [], [], {}
    sec, key, seen = None, "", False
    for raw in text.splitlines():
        if not raw.strip():
            continue
        line = raw.strip()
        m = LINK_RE.fullmatch(line)
        if not raw[0].isspace() and (m or line == "Global"):    # "Current DNS Server:" is
            sec = m.group(1) if m else True                      # not indented either
            seen = seen or sec is True
            key = ""
            continue
        m = RKEY_RE.fullmatch(line)
        if m:
            key, vals = m.group(1), (m.group(2) or "").split()
        else:
            vals = raw.split()                           # continuation of the last key
        if sec is None or key not in ("DNS Servers", "Fallback DNS Servers"):
            continue
        if sec is True:
            (glob if key == "DNS Servers" else fallback).extend(vals)
        elif key == "DNS Servers":
            links.setdefault(sec, []).extend(vals)
    return (glob, fallback, links) if seen else None


def k_dns_servers(c, cx: Cx) -> Res:
    """Only the allowed links (the tunnel) have DNS servers; none global, no fallback.
    A server anywhere else is where resolved goes while the tunnel has none (connect,
    reconnect): unencrypted, outside the tunnel."""
    src = "resolvectl status (global, fallback and per-link DNS servers)"
    res = cx.host.run([RESOLVECTL, "status", "--no-pager"])
    if res.rc != 0 or res.timed_out or res.truncated:
        return Res("unknown", _fail_run(res), source=src)
    found = resolved_servers(res.out)
    if found is None:
        return Res("unknown", "resolvectl: no Global section", source=src)
    glob, fallback, links = found
    bad = [("global", glob), ("fallback", fallback)]
    bad = [(k, v) for k, v in bad if v]
    out_links = [(n, v) for n, v in links.items() if v and n not in c.allow]
    ok = [(n, v) for n, v in links.items() if v and n in c.allow]
    if bad or out_links:
        have = "DNS on " + " ".join(n for n, _ in bad + out_links)
    elif ok:
        have = "only " + " ".join(n for n, _ in ok)
    else:
        have = "no DNS server"                           # tunnel down: nothing leaves
    out = Res("fail" if bad or out_links else "pass", have, source=src)
    out.lines = ([(k, " ".join(v)[:120]) for k, v in bad] +
                 [("not allowed", f"{n} {' '.join(v)}"[:120]) for n, v in out_links] +
                 [("allowed", f"{n} {' '.join(v)}"[:120]) for n, v in ok])[:MAX_LINES]
    return out


# --- units ---------------------------------------------------------------------

def _units(host: Host, names: list) -> dict | str:
    if not names:
        return {}
    res = host.run([SYSTEMCTL, "show", "--no-pager", "-p",
                    "Id,LoadState,ActiveState,UnitFileState", "--", *names])
    if res.rc != 0 or res.timed_out:
        return _fail_run(res)
    blocks = [b for b in res.out.strip().split("\n\n")]
    out = {}
    for name, block in zip(names, blocks):
        out[name] = dict(ln.split("=", 1) for ln in block.splitlines() if "=" in ln)
    return out


ACTIVE_STATES = ("active", "inactive", "failed")


def k_units(c, cx: Cx, all_names: list) -> Res:
    got = cx.units(all_names)
    src = "systemctl show"
    if isinstance(got, str):
        return Res("unknown", got, source=src)
    bad, have = [], []
    for unit, want in c.units:
        props = got.get(unit, {})
        field_ = "ActiveState" if want in ACTIVE_STATES else "UnitFileState"
        value = props.get(field_) or props.get("LoadState") or "?"
        have.append(value)
        if value != want:
            bad.append(f"{unit}: {value} (want {want})")
    res = Res("fail" if bad else "pass",
              " ".join(sorted(set(have))) if len(c.units) > 1 else have[0], source=src)
    res.lines = [("differs", b) for b in bad][:MAX_LINES]
    return res


def k_failed_units(c, cx: Cx) -> Res:
    res = cx.host.run([SYSTEMCTL, "list-units", "--state=failed", "--plain", "--no-legend",
                       "--no-pager"])
    src = "systemctl list-units --state=failed"
    if res.rc != 0 or res.timed_out:
        return Res("unknown", _fail_run(res), source=src)
    names = [ln.split()[0] for ln in res.out.splitlines() if ln.strip()]
    out = Res("fail" if names else "pass", f"{len(names)} failed", source=src)
    out.lines = [("failed", n) for n in names[:MAX_LINES]]
    return out


# --- listeners -------------------------------------------------------------------

def _addr(hexaddr: str, fam: int) -> ipaddress._BaseAddress:
    raw = bytes.fromhex(hexaddr)
    if fam == 4:
        return ipaddress.IPv4Address(raw[::-1])
    return ipaddress.IPv6Address(b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)))


def listening(cx: Cx) -> list:
    """-> sorted "proto addr:port" of TCP listeners and unconnected UDP sockets."""
    out = set()
    for proto, path, fam in PROC_NET:
        try:
            text = cx.host.read(path)
        except FileNotFoundError:
            continue                          # no IPv6 in the kernel
        for line in text.splitlines()[1:]:
            f = line.split()
            if len(f) < 4:
                continue
            local, remote, st = f[1], f[2], f[3]
            if proto == "tcp" and st != TCP_LISTEN:
                continue
            if proto == "udp" and (st != UDP_UNCONN or set(remote.replace(":", "")) != {"0"}):
                continue
            try:
                h, p = local.split(":")
                ip, port = _addr(h, fam), int(p, 16)
            except ValueError:
                continue
            mapped = getattr(ip, "ipv4_mapped", None)
            if ip.is_loopback or (mapped is not None and mapped.is_loopback):
                continue                      # loopback: always fine
            out.add(f"{proto} {ip}:{port}" if fam == 4 else f"{proto} [{ip}]:{port}")
    return sorted(out)


def _ss_key(proto: str, local: str) -> str | None:
    """ss local address -> the listening() form. '0.0.0.0%virbr0:67', '*:52880' (IPv6
    socket on any address), '[::]:22', '[fe80::1]%wlo1:546'. Bad: None."""
    host, sep, port = local.rpartition(":")
    if not sep or not port.isdigit():
        return None
    host = host.split("%", 1)[0].strip("[]")
    try:
        ip = ipaddress.ip_address("::" if host == "*" else host)
    except ValueError:
        return None
    return f"{proto} {ip}:{port}" if ip.version == 4 else f"{proto} [{ip}]:{port}"


def owners(cx: Cx) -> tuple:
    """-> ({"proto addr:port": (program, ...)}, error or ''). `ss -Htuln --cgroup`:
    program = innermost systemd unit of the socket's cgroup (core/proc.py), no
    CAP_SYS_PTRACE (same as the firewall screen). A socket without a cgroup in ss:
    not in the result."""
    res = cx.host.run([SS, "-Htuln", "--cgroup"])
    if res.rc != 0 or res.timed_out:
        return {}, f"ss: {_fail_run(res)}"
    out = {}
    for line in res.out.splitlines():
        t = line.split()
        if not t or t[0] not in ("tcp", "udp"):
            continue
        # [state] recv-q send-q local peer: the state column only without a state filter
        i = next((j for j in range(1, len(t) - 2) if t[j].isdigit() and t[j + 1].isdigit()),
                 None)
        m = CGROUP_RE.search(line)
        key = _ss_key(t[0], t[i + 2]) if i is not None else None
        name = program(m.group(1)) if m else None
        if key and name and name not in out.get(key, ()):
            out[key] = out.get(key, ()) + (name,)
    return out, ""


def _named(s: str, own: dict) -> str:
    names = own.get(s)
    return f"{s}  {', '.join(names)}" if names else s


def wg_port(cx: Cx, tunnel: str) -> tuple:
    """-> (port or None, note). `wg show <tunnel> listen-port` from the net unit's file
    (core/netd.py: wg needs CAP_NET_ADMIN even to read). The VPN tunnel's port can
    change on every connect (host 2026-10-26), so no port in the policy."""
    res = cx.host.wg_listen_port(tunnel)
    text = res.out.strip()
    if res.rc != 0 or res.timed_out or not text.isdigit():
        return None, f"{tunnel}: {_fail_run(res) if res.rc else 'no port'}"
    return int(text), f"{tunnel} listen-port {text}"


def k_listeners(c, cx: Cx) -> Res:
    try:
        socks = listening(cx)
    except OSError as e:
        return Res("unknown", _err(e), source="/proc/net")
    own, own_err = owners(cx)
    wg, lines, user_wg = set(), [], ""
    if c.wireguard:
        port, note = wg_port(cx, c.wireguard)
        lines.append(("wireguard", note))
        if port is not None:
            wg = {f"udp 0.0.0.0:{port}", f"udp [::]:{port}"}
        elif c.tunnel_owner and cx.host.exists(f"{NET}/{c.wireguard}"):
            # userspace tunnel (tun device, Mullvad DAITA): no kernel port; its socket
            # belongs to the VPN daemon's unit
            user_wg = c.tunnel_owner
            lines.append(("wireguard", f"{c.wireguard} present, no kernel port: udp 0.0.0.0 "
                                       f"/ [::] of {user_wg} allowed (userspace tunnel)"))
    if own_err:
        lines.append(("programs", own_err))
    extra, ok = [], []
    for s in socks:
        if s in wg:
            ok.append(("allowed", f"{s} ({c.wireguard})"))
        elif user_wg and s.startswith(WILD_UDP) and own.get(s) == (user_wg,):
            ok.append(("allowed", f"{s} ({c.wireguard}, {user_wg})"))
        elif any(fnmatch.fnmatchcase(s, a) for a in c.allow):
            ok.append(("allowed", _named(s, own)))
        else:
            extra.append(s)
    res = Res("fail" if extra else "pass",
              f"{len(extra)} not allowed" if extra else f"{len(socks)} listening, all allowed",
              source="/proc/net/{tcp,tcp6,udp,udp6}, ss --cgroup"
                     + (", wg (net unit)" if c.wireguard else ""))
    res.lines = ([("not allowed", _named(s, own)) for s in extra] + lines + ok)[:MAX_LINES]
    return res


# --- audit (journal CONFIG_CHANGE, counted in __init__) -------------------------

def _setuid(cx: Cx):
    """(files, dirs not readable) of SETUID_ROOT, scanned on the first use only: /usr
    changes with a new deployment, i.e. a reboot (and sectop starts again)."""
    if "files" not in cx.setuid:
        cx.setuid["files"], cx.setuid["unread"] = cx.host.setuid_files(SETUID_ROOT)
    return cx.setuid["files"], cx.setuid["unread"]


FIX_SYNC = "reboot (audit-privileged-sync.service writes the list at boot)"


def k_audit_rules(c, cx: Cx) -> Res:
    """Rules loaded this boot >= want. With setuid_key: rules of the other keys >= want,
    and setuid_rules setuid_key rules per setuid / setgid file under /usr (2: one per
    arch; the list changes with image updates: a fixed total breaks)."""
    a = cx.audit
    src = "journal CONFIG_CHANGE this boot (add_rule - remove_rule)"
    if a is None or a.err:
        return Res("unknown", (a.err if a else "no journal scan") or "?", source=src)
    n = a.added - a.removed
    if not c.setuid_key:
        res = Res("pass" if n >= c.want else "fail", f"{n} rules", source=src)
        res.lines = [("added", str(a.added)), ("removed", str(a.removed))]
        return res
    src += f", setuid / setgid files under {SETUID_ROOT}"
    try:
        files, unread = _setuid(cx)
    except OSError as e:
        return Res("unknown", f"{SETUID_ROOT}: {_err(e)}", source=src)
    k = a.keys.get(c.setuid_key, 0)
    other = n - k
    need = c.setuid_rules * len(files)
    ok = other >= c.want and k == need
    res = Res("pass" if ok else "fail", f"{n} rules, setuid {k}/{need}", source=src)
    res.lines = [("other rules", f"{other} (want >= {c.want})"),
                 (f"{c.setuid_key} rules", str(k)
                  + (f" ({c.setuid_rules} per file)" if c.setuid_rules > 1 else "")),
                 ("setuid files", str(len(files))
                  + (f" ({unread} dirs not readable)" if unread else ""))]
    # silverblue-privacy-hardening since 2026-11-22: the list is written at every boot
    # (audit-privileged-sync.service, before audit-rules.service; failed: failed units)
    if k < need:
        res.lines.append(("fix", f"a setuid program has no rule: {FIX_SYNC}"))
    elif k > need:
        res.lines.append(("fix", f"rules for programs no longer here: {FIX_SYNC}"))
    res.lines += [("setuid", p) for p in files]
    res.lines = res.lines[:MAX_LINES]
    return res


# --- audit-rules.service and auditd's own lines (review 2026-11-17, L-2 / L-4) ------
# The units' own journal lines this boot (_SYSTEMD_UNIT: set by journald, a process
# outside the unit cannot fake it). sectop has the journal group, no root needed.

AUDIT_RULES_UNIT = "audit-rules.service"
AUDITD_UNIT = "auditd.service"
UNIT_LINES = 400                   # last lines per unit and collect
LOAD_ERR_RE = re.compile(r"\berror\b", re.I)    # auditctl: "Error sending add rule data
#                                    request (...)", "There was an error in line N of <file>"
LOAD_PROPS = "Result,ExecMainStatus,ExecMainStartTimestampMonotonic"
# auditd 4 (auditd-event.c, auditd.c): suspended until a resume or a new start
AUDITD_START = "Init complete, auditd"
AUDITD_SUSPEND = re.compile(r"suspending logging|logging suspended|"
                            r"Could not reopen a log after resume")
AUDITD_RESUME = re.compile(r"attempting to resume logging|resumed logging")
AUDITD_SPACE = re.compile(r"low on disk space|no space left on logging partition|"
                          r"error writing an event|write error")
PRINTABLE = re.compile(r"[^\x20-\x7e]")


def unit_lines(cx: Cx, unit: str) -> list | str:
    """-> [(time HH:MM:SS, message)] of the unit's own lines this boot; str = error."""
    res = cx.host.run([JOURNALCTL, "-b", "-q", "--no-pager", "-o", "json",
                       "--output-fields=MESSAGE", "-n", str(UNIT_LINES), f"_SYSTEMD_UNIT={unit}"])
    if res.timed_out or res.truncated or (res.rc != 0 and (res.out.strip() or res.err.strip())):
        return _fail_run(res)
    out = []
    for line in res.out.splitlines():                # rc 1 without output: no entries
        try:
            e = json.loads(line)
        except ValueError:
            continue
        msg = e.get("MESSAGE") if isinstance(e, dict) else None
        if not isinstance(msg, str):
            continue                                 # binary (a list of bytes): not ours
        try:
            ts = time.strftime("%H:%M:%S", time.localtime(int(e["__REALTIME_TIMESTAMP"]) / 1e6))
        except (KeyError, TypeError, ValueError, OverflowError):
            ts = "?"
        out.append((ts, PRINTABLE.sub("?", msg.strip())[:160]))
    return out


def k_audit_load(c, cx: Cx) -> Res:
    """audit-rules.service ran this boot, ended with success, printed no error line.
    With -c (01-continue.rules) auditctl loads the other rules and exits 1: the unit
    fails, the rule in the error line is missing until the next boot (-e 2)."""
    src = f"systemctl show {AUDIT_RULES_UNIT}, its journal lines this boot"
    res = cx.host.run([SYSTEMCTL, "show", "--no-pager", "-p", LOAD_PROPS, "--", AUDIT_RULES_UNIT])
    if res.rc != 0 or res.timed_out:
        return Res("unknown", _fail_run(res), source=src)
    p = dict(ln.split("=", 1) for ln in res.out.splitlines() if "=" in ln)
    lines = unit_lines(cx, AUDIT_RULES_UNIT)
    if isinstance(lines, str):
        return Res("unknown", f"journal: {lines}", source=src)
    errors = [(t, m) for t, m in lines if LOAD_ERR_RE.search(m)]
    ran = p.get("ExecMainStartTimestampMonotonic", "0") not in ("", "0")
    result, code = p.get("Result", "?"), p.get("ExecMainStatus", "?")
    if not ran:
        out = Res("fail", "not run this boot", source=src)
    elif errors or result != "success" or code != "0":
        n = sum(1 for _, m in errors if "error in line" in m)
        out = Res("fail", f"{result}, exit {code}, {n} rule(s) not loaded", source=src)
    else:
        return Res("pass", "loaded, no error", [("result", f"{result}, exit {code}")], source=src)
    out.lines = [("result", f"{result}, exit {code}")]
    out.lines += [("error", f"{t} {m}") for t, m in errors][:MAX_LINES - 2]
    out.lines.append(("fix", "the line in /etc/audit/rules.d (augenrules order), then reboot "
                             "(rules locked: -e 2)"))
    return out


def k_auditd_logging(c, cx: Cx) -> Res:
    """auditd writes its log: no suspend since its last start or resume this boot
    (auditd.conf admin_space_left / disk_full / disk_error action SUSPEND, or a log it
    could not reopen). The kernel still sends records to the journal; auditd's own log
    (ausearch, the scanner's checks) has a gap."""
    src = f"{AUDITD_UNIT} journal lines this boot"
    lines = unit_lines(cx, AUDITD_UNIT)
    if isinstance(lines, str):
        return Res("unknown", lines, source=src)
    state, since, space = "logging", "", []
    for t, m in lines:
        if m.startswith(AUDITD_START):
            state, since, space = "logging", "", []
        elif AUDITD_SUSPEND.search(m):
            state, since = "suspended", t
            space.append((t, m))
        elif AUDITD_RESUME.search(m):
            state, since = "logging", ""
            space.append((t, m))
        elif AUDITD_SPACE.search(m):
            space.append((t, m))
    if state == "suspended":
        out = Res("fail", f"suspended since {since}", source=src)
        out.lines = [("line", f"{t} {m}") for t, m in space][-(MAX_LINES - 1):]
        out.lines.append(("fix", "free space on /var, then: sudo auditctl --signal resume"))
        return out
    out = Res("pass", "logging" + (f", {len(space)} space line(s)" if space else ""), source=src)
    out.lines = [("line", f"{t} {m}") for t, m in space][-MAX_LINES:]
    return out


def k_free_space(c, cx: Cx) -> Res:
    """Free space for unprivileged users (f_bavail) on the file system of path. statvfs
    needs search on the parent folders only (/var/log/audit itself is root 0700)."""
    src = f"statvfs {c.path}"
    try:
        st = cx.host.statvfs(c.path)
    except OSError as e:
        return Res("unknown", _err(e), source=src)
    free = st.f_bavail * st.f_frsize // (1024 * 1024)
    size = st.f_blocks * st.f_frsize // (1024 * 1024)
    out = Res("pass" if free >= c.min_mb else "fail", f"{_mib(free)} free", source=src)
    out.lines = [("free", f"{free} MiB of {size} MiB"), ("want", f">= {c.min_mb} MiB")]
    return out


def _mib(n: int) -> str:
    return f"{n / 1024:.1f} GiB" if n >= 1024 else f"{n} MiB"


def k_setuid_known(c, cx: Cx) -> Res:
    """Every setuid / setgid file under /usr is on my list of seen programs (review
    2026-11-22, with L-1). silverblue-privacy-hardening writes an audit rule for a new one
    at the next boot by itself, so the audit-rules row stays green: this row stays yellow
    until I accept it (install.sh --setuid-accept). A program that left: detail only."""
    src = f"{c.path}, setuid / setgid files under {SETUID_ROOT}"
    try:
        text = cx.host.read_owned(c.path)
    except (ConfigError, OSError) as e:
        return Res("unknown", (str(e) if isinstance(e, ConfigError) else _err(e))[:120], source=src)
    if text is None:
        res = Res("fail", "no list", source=src)
        res.lines = [("fix", ACCEPT)]
        return res
    known = {ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")}
    try:
        files, unread = _setuid(cx)
    except OSError as e:
        return Res("unknown", f"{SETUID_ROOT}: {_err(e)}", source=src)
    new = [p for p in files if p not in known]
    gone = sorted(known - set(files))
    if new:
        res = Res("fail", f"{len(new)} new: {new[0]}" + (" ..." if len(new) > 1 else ""), source=src)
    else:
        res = Res("pass", f"{len(files)} known" + (f", {len(gone)} gone" if gone else ""), source=src)
    lines = ([("new", p) for p in new] + [("gone", p) for p in gone]
             + ([("not readable", f"{unread} dirs under {SETUID_ROOT}")] if unread else []))
    tail = [("fix", f"seen and wanted: {ACCEPT}")] if new else []
    res.lines = lines[:MAX_LINES - len(tail)] + tail
    return res


ACCEPT = "sudo ./install.sh --setuid-accept (the admin's sectop clone)"


# --- IOMMU (silverblue-privacy-hardening kargs, 2026-11-24, KSPP) ----------------------

CPUINFO = "/proc/cpuinfo"
INTERRUPTS = "/proc/interrupts"
IOMMU_GROUPS = "/sys/kernel/iommu_groups"
# kernel arg that turns the IOMMU on for a CPU vendor (vendor_id in /proc/cpuinfo)
IOMMU_VENDOR_ARG = {"GenuineIntel": "intel_iommu=on", "AuthenticAMD": "amd_iommu=force_isolation"}
VENDOR_RE = re.compile(r"^vendor_id\s*:\s*(\S+)", re.M)
IR_RE = re.compile(r"\sIR-\S+")


def k_iommu_vendor(c, cx: Cx) -> Res:
    """The IOMMU arg of this CPU's vendor is on the command line (Intel intel_iommu=on, AMD
    amd_iommu=force_isolation). Another vendor: unknown (no arg known)."""
    src = f"{CPUINFO} + {CMDLINE}"
    try:
        m = VENDOR_RE.search(cx.host.read(CPUINFO))
        words = set(cx.host.read(CMDLINE).split())
    except OSError as e:
        return Res("unknown", _err(e), source=src)
    vendor = m.group(1) if m else ""
    arg = IOMMU_VENDOR_ARG.get(vendor)
    if arg is None:
        return Res("unknown", f"CPU vendor {vendor or '?'}: no arg known", source=src)
    res = Res("pass" if arg in words else "fail", arg if arg in words else f"missing {arg}",
              source=src)
    res.lines = [("cpu", vendor)]
    return res


def k_iommu_groups(c, cx: Cx) -> Res:
    """Every IOMMU group has the domain type want (DMA: translated, strict flush; not
    identity = no IOMMU for that device, not DMA-FQ = lazy flush). No group: the IOMMU
    is off (firmware VT-d / AMD-Vi off, or no arg)."""
    try:
        groups = [g for g in cx.host.listdir(IOMMU_GROUPS) if g.isdigit()]
    except FileNotFoundError:
        return Res("fail", "no IOMMU groups (IOMMU off)", source=IOMMU_GROUPS)
    except OSError as e:
        return Res("unknown", _err(e), source=IOMMU_GROUPS)
    if not groups:
        return Res("fail", "no IOMMU groups (IOMMU off)", source=IOMMU_GROUPS)
    types, bad, unread = {}, [], 0
    for g in sorted(groups, key=int):
        try:
            t = cx.host.read(f"{IOMMU_GROUPS}/{g}/type").strip()
        except OSError:
            unread += 1
            continue
        types[t] = types.get(t, 0) + 1
        if t != c.want:
            bad.append((g, t))
    if unread and not types:
        return Res("unknown", f"{unread} group types not readable", source=IOMMU_GROUPS)
    have = ", ".join(f"{n} {t}" for t, n in sorted(types.items()))
    res = Res("fail" if bad or unread else "pass", f"{len(groups)} groups: {have}"[:120],
              source=f"{IOMMU_GROUPS}/*/type")
    res.lines = [(f"group {g}", t) for g, t in bad] + ([("unread", str(unread))] if unread else [])
    res.lines = res.lines[:MAX_LINES]
    return res


def k_irq_remap(c, cx: Cx) -> Res:
    """Interrupt remapping on: /proc/interrupts names IR- chips (IR-PCI-MSI*, IR-IO-APIC).
    Without it a device that may DMA can also send forged interrupts (MSI)."""
    try:
        n = len(IR_RE.findall(cx.host.read(INTERRUPTS)))
    except OSError as e:
        return Res("unknown", _err(e), source=INTERRUPTS)
    return Res("pass" if n else "fail", f"{n} IR- interrupt lines" if n else "no IR- interrupt",
               source=INTERRUPTS)


# --- harden-check (silverblue-privacy-hardening integrity section) ----------------------

HC_STALE = 26 * 3600               # daily timer + a late day
HC_BOOT_GRACE = 15 * 60            # first run 5 min after boot (aidecheck.timer)
HC_ACCEPT = "sudo harden-check --accept (admin, text console)"
UPTIME = "/proc/uptime"


def parse_harden_check(text: str) -> tuple:
    """RESULT of harden-check: `time<TAB>epoch<TAB>iso`, `check<TAB>id<TAB>status<TAB>summary`,
    `item<TAB>id<TAB>text`. -> (epoch or None, [(id, status, summary, [items])])."""
    when, checks, by_id = None, [], {}
    for line in text.splitlines():
        f = line.split("\t")
        if f[0] == "time" and len(f) >= 2 and f[1].isdigit():
            when = int(f[1])
        elif f[0] == "check" and len(f) >= 4:
            entry = (f[1], f[2], f[3], [])
            checks.append(entry)
            by_id[f[1]] = entry
        elif f[0] == "item" and len(f) >= 3 and f[1] in by_id:
            by_id[f[1]][3].append(f[2])
    return when, checks


def k_harden_check(c, cx: Cx) -> Res:
    """The root drift check's last result (silverblue-privacy-hardening: aidecheck.service
    runs aide --check, then harden-check; review D-U1, 2026-11-22). A file changed since
    the admin's last accept, a boot file that is not the image's, a root-only value off:
    fail (sev warn: yellow) until it is gone or accepted. Older than a day: fail, except
    in the first minutes after boot (the timer runs 5 min after boot)."""
    src = f"{c.path} (aidecheck.service, root)"
    try:
        text = cx.host.read_owned(c.path)
    except (ConfigError, OSError) as e:
        return Res("unknown", (str(e) if isinstance(e, ConfigError) else _err(e))[:120], source=src)
    if text is None:
        res = Res("fail", "no result", source=src)
        res.lines = [("fix", "sudo ./harden-workstation.sh integrity (aide layered first)")]
        return res
    when, checks = parse_harden_check(text)
    if when is None or not checks:
        return Res("unknown", "result not readable", source=src)
    age = cx.now - when
    if age > HC_STALE:
        try:
            up = float(cx.host.read(UPTIME).split()[0])
        except (OSError, ValueError, IndexError):
            up = HC_BOOT_GRACE + 1
        hours = int(age // 3600)
        if up < HC_BOOT_GRACE:
            return Res("unknown", f"{hours} h old, the run after boot is due", source=src)
        res = Res("fail", f"{hours} h old: did aidecheck.service run?", source=src)
        res.lines = [("fix", "systemctl status aidecheck.timer aidecheck.service")]
        return res
    bad = [x for x in checks if x[1] == "fail"]
    unk = [x for x in checks if x[1] not in ("pass", "fail")]
    if bad:
        first = bad[0]
        res = Res("fail", f"{first[0]}: {first[2]}"[:120], source=src)
    elif unk:
        res = Res("unknown", f"{len(unk)} of {len(checks)} not checked: "
                             + " ".join(x[0] for x in unk), source=src)
    else:
        return Res("pass", f"{len(checks)} checks pass", source=src,
                   lines=[(x[0], x[2]) for x in checks][:MAX_LINES])
    lines = []
    for cid, st, summ, items in bad + unk:
        lines.append((cid, f"{st}: {summ}"))
        lines += [(cid, i) for i in items]
    tail = [("fix", f"seen and wanted: {HC_ACCEPT}")] if any(x[0] == "aide" for x in bad) else []
    shown = lines[:MAX_LINES - len(tail)]
    if len(lines) > len(shown) and shown:
        shown[-1] = ("more", f"{len(lines) - len(shown) + 1} lines: sudo cat {c.path}")
    res.lines = shown + tail
    return res


# --- home-watch (sectop-home@<user>.service, core/homed.py) ---------------------------

HOME_ACCEPT = "sudo ./install.sh --home-accept (the admin's sectop clone)"


def k_home_watch(c, cx: Cx) -> Res:
    """The start places in the desktop user's home as the admin accepted them (step 8b2,
    2026-11-23): a new, changed or gone entry, a place that became unreadable (ACL taken
    away), or no fresh report: fail (sev warn: yellow) until it is back or accepted. The
    report comes from sectop-home, never from the desktop user."""
    src = f"{c.path} + {homed.RUN_DIR}/<user>/{homed.FILE}"
    try:
        text = cx.host.read_owned(c.path)
    except (ConfigError, OSError) as e:
        return Res("unknown", (str(e) if isinstance(e, ConfigError) else _err(e))[:120], source=src)
    if text is None:
        res = Res("fail", "no accepted list", source=src)
        res.lines = [("fix", HOME_ACCEPT)]
        return res
    try:
        user, known = homed.parse_known(text)
    except ValueError as e:
        return Res("unknown", f"{c.path}: {e}"[:120], source=src)
    try:
        now, home = cx.host.home_report(user)
    except ValueError as e:
        res = Res("fail", str(e)[:120], source=src)
        res.lines = [("fix", f"systemctl status sectop-home@{user}.service")]
        return res
    changes = homed.diff(known, now)
    if not changes:
        n_un = sum(1 for v in now.values() if v == homed.UNREADABLE)
        return Res("pass", f"{len(now)} entries as accepted" + (f" ({n_un} unreadable)" if n_un else ""),
                   source=src)
    first = changes[0]
    res = Res("fail", f"{len(changes)} changed: ~/{first[1]} ({first[0]})"[:120], source=src)
    lines = [(kind, f"~/{path}" + (f" ({d})" if d else "")) for kind, path, d in changes]
    tail = [("fix", f"seen and wanted: {HOME_ACCEPT}")]
    shown = lines[:MAX_LINES - len(tail)]
    if len(lines) > len(shown) and shown:
        shown[-1] = ("more", f"{len(lines) - len(shown) + 1} more: {HOME_ACCEPT} shows all")
    res.lines = shown + tail
    return res


# --- fwupd (silverblue-cis-hardening FIRMWARE_REPORTS=no) ------------------------

REPORT_KEYS = ("ReportURI", "SecurityReportURI")
AUTO_KEYS = ("AutomaticReports", "AutomaticSecurityReports")


def k_fwupd_reports(c, cx: Cx) -> Res:
    """No remote may send reports: no ReportURI, nothing automatic."""
    try:
        names = [n for n in cx.host.listdir(c.path) if n.endswith(".conf")]
    except FileNotFoundError:
        return Res("pass", "no fwupd remotes", source=c.path)
    except OSError as e:
        return Res("unknown", _err(e), source=c.path)
    bad, unread = [], []
    for name in names:
        try:
            text = cx.host.read(f"{c.path}/{name}")
        except OSError as e:
            unread.append(f"{name}: {_err(e)}")
            continue
        bad += [f"{name}: {k} set" for k in REPORT_KEYS if _value(text, k)]
        bad += [f"{name}: {k}=true" for k in AUTO_KEYS
                if (_value(text, k) or "").lower() == "true"]
    status = "fail" if bad else ("unknown" if unread else "pass")
    have = (f"{len(bad)} report settings on" if bad
            else f"{len(names)} remotes, no report address")
    res = Res(status, have, source=c.path)
    res.lines = ([("on", b) for b in bad] + [("unread", u) for u in unread])[:MAX_LINES]
    return res


def k_audit_enabled(c, cx: Cx) -> Res:
    a = cx.audit
    src = "journal CONFIG_CHANGE op=set audit_enabled this boot"
    if a is None or a.err:
        return Res("unknown", (a.err if a else "no journal scan") or "?", source=src)
    if a.enabled is None:
        return Res("pass", "not changed this boot", source=src)
    return Res("fail" if a.enabled == "0" else "pass", f"audit_enabled={a.enabled}", source=src)


def k_audit_locked(c, cx: Cx) -> Res:
    """-e 2 at boot (99-finalize.rules) leaves audit_enabled=2; the kernel then refuses
    every later change (logged with res=0, not counted)."""
    a = cx.audit
    src = "journal CONFIG_CHANGE op=set audit_enabled this boot"
    if a is None or a.err:
        return Res("unknown", (a.err if a else "no journal scan") or "?", source=src)
    if a.enabled is None:
        return Res("fail", "not locked this boot", source=src)
    return Res("pass" if a.enabled == "2" else "fail", f"audit_enabled={a.enabled}", source=src)


KINDS = {
    "file": k_file, "lines": k_lines, "sysctl": k_sysctl, "cmdline": k_cmdline,
    "failed-units": k_failed_units, "listeners": k_listeners, "taint": k_taint,
    "luks": k_luks, "secureboot": k_secureboot, "lockdown": k_lockdown,
    "audit-rules": k_audit_rules, "audit-enabled": k_audit_enabled,
    "audit-locked": k_audit_locked, "uid0": k_uid0,
    "group": k_group, "perms": k_perms, "ostree-unlocked": k_ostree_unlocked,
    "ostree-staged": k_ostree_staged, "ostree-age": k_ostree_age, "ostree-gpg": k_ostree_gpg,
    "firewalld-zone": k_firewalld_zone, "wifi-ipv6": k_wifi_ipv6, "nm-props": k_nm_props,
    "mac-local": k_mac_local, "hostname": k_hostname, "dns-servers": k_dns_servers,
    "fwupd-reports": k_fwupd_reports, "audit-load": k_audit_load,
    "auditd-logging": k_auditd_logging, "free-space": k_free_space,
    "setuid-known": k_setuid_known, "harden-check": k_harden_check,
    "home-watch": k_home_watch, "iommu-vendor": k_iommu_vendor,
    "iommu-groups": k_iommu_groups, "irq-remap": k_irq_remap,
}


def want_text(c) -> str:
    """The want cell of a row."""
    k = c.kind
    if k == "file":
        return _want(c)
    if k in ("lines", "sysctl"):
        n = len(c.want) if k == "lines" else len(c.values)
        return f"{n} of {n}"
    if k == "units":
        return " ".join(sorted({s for _, s in c.units}))
    if k in ("cmdline", "uid0"):
        return " ".join(c.want)
    if k == "group":
        return " ".join(c.want) or "empty"
    if k == "taint":
        return f"only {c.want}" if c.want.strip() else "none"
    if k == "audit-rules":
        return f">= {c.want} + {c.setuid_rules} per setuid file" if c.setuid_key else f">= {c.want}"
    if k == "perms":
        return f"{c.mode:o} {c.owner}"
    if k == "ostree-age":
        return f"<= {c.max_days} days"
    if k == "free-space":
        return f">= {_mib(c.min_mb)} free"
    if k == "listeners":
        return "allowlist"
    if k == "failed-units":
        return "0 failed"
    if k == "iommu-groups":
        return f"every type {c.want}"
    if k in ("lockdown", "firewalld-zone", "wifi-ipv6"):
        return c.want
    if k == "hostname":
        return f"{c.want}, no pretty name"
    if k == "nm-props":
        return " ".join(f"{p}={w or '-'}" for p, w in c.props)
    if k == "dns-servers":
        return "only " + " ".join(c.allow) if c.allow else "none"
    return {"luks": "CRYPT-LUKS", "secureboot": "on", "audit-enabled": "not 0",
            "audit-locked": "audit_enabled=2",
            "ostree-unlocked": "locked", "ostree-staged": "none",
            "ostree-gpg": "all verify", "mac-local": "local MAC",
            "fwupd-reports": "no report address", "audit-load": "loaded, no error",
            "auditd-logging": "not suspended",
            "setuid-known": "none new", "harden-check": "no change, all pass",
            "home-watch": "as accepted", "iommu-vendor": "arg of the CPU vendor",
            "irq-remap": "on"}.get(k, "-")


def check(c, cx: Cx, unit_names: list) -> Res:
    if c.kind == "units":
        return k_units(c, cx, unit_names)
    return KINDS[c.kind](c, cx)
