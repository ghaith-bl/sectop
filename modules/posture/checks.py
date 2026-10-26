"""Posture check kinds (docs/modules/posture.md, Kinds). One function per kind.

Each takes the check (policy.Check) and the collect context (Cx: host access, the
audit counts, per-collect caches) and returns a Res: pass / fail / unknown, what was
found (`have`, one short line) and detail lines. Reads files where a file exists;
commands only where there is no file (systemctl, firewall-cmd, nmcli, rpm-ostree),
fixed argv, run as user sectop. Nothing here changes the host.
"""

import fnmatch
import grp
import ipaddress
import json
import os
import pwd
import re
import time
from dataclasses import dataclass, field

from core import netd
from core.run import Result
from core.run import run as core_run
from modules.security.kernel import letters

SYSTEMCTL = "/usr/bin/systemctl"
FIREWALL_CMD = "/usr/bin/firewall-cmd"
NMCLI = "/usr/bin/nmcli"
RPM_OSTREE = "/usr/bin/rpm-ostree"
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
MAX_WIFI = 32
MAX_LINES = 12                     # detail lines per check
MAX_READ = 1024 * 1024
KV_RE = r"^\s*{}\s*=\s*(.*?)\s*$"


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

    def run(self, argv: list, timeout: float = TIMEOUT):
        return core_run(argv, timeout=timeout)

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

    def __init__(self, host: Host, now: float, audit=None, ostree=None):
        self.host, self.now = host, now
        self.audit = audit                     # State audit counts (posture __init__)
        self.ostree = ostree                   # dict: cached rpm-ostree status (ts, res)
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


def _value(text: str, key: str) -> str | None:
    """`key = value` / `KEY=value` (last one wins, # ; comments), or the first line."""
    found = None
    rx = re.compile(KV_RE.format(re.escape(key))) if key else None
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
    v = _value(text, c.key)
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
    res = Res("fail" if days > c.max_days else "pass", f"{days} days",
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


def wg_port(cx: Cx, tunnel: str) -> tuple:
    """-> (port or None, note). `wg show <tunnel> listen-port` from the net unit's file
    (core/netd.py: wg needs CAP_NET_ADMIN even to read). Proton picks a new random port
    on every connect (host 2026-10-26), so no port in the policy."""
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
    wg, lines = set(), []
    if c.wireguard:
        port, note = wg_port(cx, c.wireguard)
        lines.append(("wireguard", note))
        if port is not None:
            wg = {f"udp 0.0.0.0:{port}", f"udp [::]:{port}"}
    extra, ok = [], []
    for s in socks:
        if s in wg:
            ok.append(("allowed", f"{s} ({c.wireguard})"))
        elif any(fnmatch.fnmatchcase(s, a) for a in c.allow):
            ok.append(("allowed", s))
        else:
            extra.append(s)
    res = Res("fail" if extra else "pass",
              f"{len(extra)} not allowed" if extra else f"{len(socks)} listening, all allowed",
              source="/proc/net/{tcp,tcp6,udp,udp6}" + (", wg (net unit)" if c.wireguard else ""))
    res.lines = ([("not allowed", s) for s in extra] + lines + ok)[:MAX_LINES]
    return res


# --- audit (journal CONFIG_CHANGE, counted in __init__) -------------------------

def k_audit_rules(c, cx: Cx) -> Res:
    a = cx.audit
    src = "journal CONFIG_CHANGE this boot (add_rule - remove_rule)"
    if a is None or a.err:
        return Res("unknown", (a.err if a else "no journal scan") or "?", source=src)
    n = a.added - a.removed
    res = Res("pass" if n >= c.want else "fail", f"{n} rules", source=src)
    res.lines = [("added", str(a.added)), ("removed", str(a.removed))]
    return res


def k_audit_enabled(c, cx: Cx) -> Res:
    a = cx.audit
    src = "journal CONFIG_CHANGE op=set audit_enabled this boot"
    if a is None or a.err:
        return Res("unknown", (a.err if a else "no journal scan") or "?", source=src)
    if a.enabled is None:
        return Res("pass", "not changed this boot", source=src)
    return Res("fail" if a.enabled == "0" else "pass", f"audit_enabled={a.enabled}", source=src)


KINDS = {
    "file": k_file, "lines": k_lines, "sysctl": k_sysctl, "cmdline": k_cmdline,
    "failed-units": k_failed_units, "listeners": k_listeners, "taint": k_taint,
    "luks": k_luks, "secureboot": k_secureboot, "lockdown": k_lockdown,
    "audit-rules": k_audit_rules, "audit-enabled": k_audit_enabled, "uid0": k_uid0,
    "group": k_group, "perms": k_perms, "ostree-unlocked": k_ostree_unlocked,
    "ostree-staged": k_ostree_staged, "ostree-age": k_ostree_age, "ostree-gpg": k_ostree_gpg,
    "firewalld-zone": k_firewalld_zone, "wifi-ipv6": k_wifi_ipv6,
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
        return f">= {c.want}"
    if k == "perms":
        return f"{c.mode:o} {c.owner}"
    if k == "ostree-age":
        return f"<= {c.max_days} days"
    if k == "listeners":
        return "allowlist"
    if k == "failed-units":
        return "0 failed"
    if k in ("lockdown", "firewalld-zone", "wifi-ipv6"):
        return c.want
    return {"luks": "CRYPT-LUKS", "secureboot": "on", "audit-enabled": "not 0",
            "ostree-unlocked": "locked", "ostree-staged": "none",
            "ostree-gpg": "all verify"}.get(k, "-")


def check(c, cx: Cx, unit_names: list) -> Res:
    if c.kind == "units":
        return k_units(c, cx, unit_names)
    return KINDS[c.kind](c, cx)
