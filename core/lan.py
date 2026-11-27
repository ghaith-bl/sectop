"""The network this laptop is on: router, ARP table, own addresses (step 11b2a, 2026-11-27).

Read only: three files in /proc and one netlink question to the kernel. No command, no
packet on the network, no capability. Used by the lan box (modules/lan, the collector,
user sectop) and by the accept (`sudo ./install.sh --lan-accept`, root).

Sources:
- /proc/net/route: the IPv4 default route with the lowest metric that is not on a tunnel
  or a bridge = the uplink and its router; the connected route on that device that holds
  the router's address = the subnet. Main table only (Mullvad's routes live in its own
  table: the main default route stays the Wi-Fi / cable one).
- /proc/net/arp: complete entries (ATF_COM): address -> MAC per device. The kernel keeps
  one MAC per address and device, so "the router's address answered by two MACs" shows as
  a change over time.
- /proc/net/fib_trie: this host's own IPv4 addresses (`/32 host LOCAL`).
- nl80211 (generic netlink, NL80211_CMD_GET_INTERFACE dump): the Wi-Fi name (SSID) of the
  uplink, the question `iw dev` asks; no privilege needed.

Privacy: a MAC address and a Wi-Fi name never leave this process. They go into
HMAC-SHA256 with a local key (/etc/sectop/lan.key, root:sectop 0640, made by the first
accept) and only the result is kept:
  network id = HMAC(key, "net1" kind ssid subnet router)    kind: wifi / cable
  router id  = HMAC(key, "mac1" mac)
The screen shows the first 8 hex digits of a network id, never a MAC or a Wi-Fi name.
The accepted list (/etc/sectop/lan-known.txt, root:sectop 0640) holds ids only.
"""

import errno
import grp
import hashlib
import hmac
import ipaddress
import os
import re
import socket
import struct
import sys
import time

from core.config import read_file
from core.sanitize import display

ROUTE = "/proc/net/route"
ARP = "/proc/net/arp"
FIB = "/proc/net/fib_trie"
KEY = "/etc/sectop/lan.key"
KNOWN = "/etc/sectop/lan-known.txt"
KNOWN_GROUP = "sectop"           # the collector reads both files through its group
PROC_MAX = 1 << 20
KEY_MAX = 256
KNOWN_MAX = 64 << 10
MAX_KNOWN = 500
# never an uplink: loopback, tunnels, bridges, container / VM links (as hardening's
# harden-ids sync)
NOT_UPLINK = ("lo", "wg", "tun", "tap", "virbr", "vnet", "veth", "docker", "podman", "cni",
              "br-")
IFNAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,15}")
MAC_RE = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}")
HEX64 = re.compile(r"[0-9a-f]{64}")
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
RTF_UP, RTF_GATEWAY = 0x1, 0x2
ATF_COM = 0x2


# --- /proc files --------------------------------------------------------------------------

def read_proc(path: str, limit: int = PROC_MAX) -> str:
    """A /proc text file (size 0 in stat: read until the end, at most limit). OSError."""
    with open(path, "rb") as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise OSError(errno.EFBIG, f"{path}: more than {limit} bytes")
    return data.decode("ascii", errors="replace")


def _ip4(hexval: str) -> ipaddress.IPv4Address:
    """/proc/net/route field: the address as a host-order u32 in hex."""
    return ipaddress.IPv4Address(struct.pack("=I", int(hexval, 16)))


class Route:
    __slots__ = ("dev", "dst", "gw", "flags", "metric", "mask")


def parse_route(text: str) -> list:
    out = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 8 or not IFNAME_RE.fullmatch(f[0]):
            continue
        try:
            r = Route()
            r.dev, r.dst, r.gw = f[0], _ip4(f[1]), _ip4(f[2])
            r.flags, r.metric, r.mask = int(f[3], 16), int(f[6]), _ip4(f[7])
        except (ValueError, struct.error):
            continue
        out.append(r)
    return out


class Uplink:
    __slots__ = ("dev", "gw", "subnet")

    def __init__(self, dev: str, gw: str, subnet: str):
        self.dev, self.gw, self.subnet = dev, gw, subnet

    def __eq__(self, other):
        return isinstance(other, Uplink) and (self.dev, self.gw, self.subnet) == \
            (other.dev, other.gw, other.subnet)

    def __repr__(self):
        return f"Uplink({self.dev!r}, {self.gw!r}, {self.subnet!r})"


def uplink(routes: list):
    """The default route (lowest metric, not a tunnel / bridge) -> Uplink, or None."""
    best, want = None, RTF_UP | RTF_GATEWAY
    for r in routes:
        if int(r.dst) or int(r.mask) or (r.flags & want) != want:
            continue
        if r.dev.startswith(NOT_UPLINK) or not int(r.gw):
            continue
        if best is None or r.metric < best.metric:
            best = r
    if best is None:
        return None
    subnet, plen = "", -1
    for r in routes:
        if r.dev != best.dev or r.flags & RTF_GATEWAY or not r.flags & RTF_UP or not int(r.mask):
            continue
        try:
            net = ipaddress.IPv4Network(f"{r.dst}/{r.mask}")
        except ValueError:
            continue
        if best.gw in net and net.prefixlen > plen:
            subnet, plen = str(net), net.prefixlen
    return Uplink(best.dev, str(best.gw), subnet)


def parse_arp(text: str) -> list:
    """-> [(address, mac, device)], complete entries only, mac lower case."""
    out = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 6 or not IFNAME_RE.fullmatch(f[5]):
            continue
        try:
            ip = str(ipaddress.IPv4Address(f[0]))
            flags = int(f[2], 16)
        except ValueError:
            continue
        mac = f[3].lower()
        if not flags & ATF_COM or not MAC_RE.fullmatch(mac) or mac == "00:00:00:00:00:00":
            continue
        out.append((ip, mac, f[5]))
    return out


def parse_fib_local(text: str) -> set:
    """This host's own IPv4 addresses: a `|-- <addr>` line followed by `/32 host LOCAL`."""
    out, last = set(), None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith(("|-- ", "+-- ")):
            last = s[4:].split()[0] if s.startswith("|-- ") else None
        elif last and s.startswith("/32 host LOCAL"):
            try:
                out.add(str(ipaddress.IPv4Address(last)))
            except ValueError:
                pass
    return out


# --- nl80211: the Wi-Fi name of an interface ----------------------------------------------

NETLINK_GENERIC = 16
GENL_ID_CTRL = 0x10
CTRL_CMD_GETFAMILY = 3
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2
NLM_F_REQUEST, NLM_F_MULTI, NLM_F_ACK, NLM_F_DUMP = 0x1, 0x2, 0x4, 0x300
NLMSG_ERROR, NLMSG_DONE = 2, 3
NL80211_CMD_GET_INTERFACE = 5
NL80211_ATTR_IFNAME = 4
NL80211_ATTR_SSID = 52
HDR = struct.Struct("=IHHII")        # nlmsghdr: len, type, flags, seq, pid
GENL = struct.Struct("=BBH")          # genlmsghdr: cmd, version, reserved
NLA = struct.Struct("=HH")            # nlattr: len, type
NL_MAX = 1 << 20                      # bytes read per question
SSID_MAX = 32                         # IEEE 802.11: 0..32 octets


def nl_attr(kind: int, data: bytes) -> bytes:
    n = NLA.size + len(data)
    return NLA.pack(n, kind) + data + b"\0" * (-n % 4)


def nl_msg(mtype: int, flags: int, seq: int, cmd: int, version: int, attrs: bytes = b"") -> bytes:
    body = GENL.pack(cmd, version, 0) + attrs
    return HDR.pack(HDR.size + len(body), mtype, flags, seq, 0) + body


def nl_attrs(data: bytes) -> dict:
    """Attributes of one message (after the genl header): type -> first payload."""
    out, i = {}, 0
    while i + NLA.size <= len(data):
        n, kind = NLA.unpack_from(data, i)
        if n < NLA.size or i + n > len(data):
            break
        out.setdefault(kind & 0x3FFF, bytes(data[i + NLA.size:i + n]))
        i += (n + 3) & ~3
    return out


def nl_messages(buf: bytes):
    """-> [(type, flags, seq, payload)] of one datagram. A cut message -> ValueError."""
    out, i = [], 0
    while i + HDR.size <= len(buf):
        n, mtype, flags, seq, _ = HDR.unpack_from(buf, i)
        if n < HDR.size or i + n > len(buf):
            raise ValueError("netlink: cut message")
        out.append((mtype, flags, seq, bytes(buf[i + HDR.size:i + n])))
        i += (n + 3) & ~3
    return out


def nl_request(sock, msg: bytes, seq: int) -> list:
    """Send one request, -> the payloads of its answers (until DONE or the ack).
    Netlink error -> OSError(errno)."""
    sock.send(msg)
    out, got = [], 0
    while True:
        buf = sock.recv(65536)
        if not buf:
            raise OSError(errno.EIO, "netlink: no answer")
        got += len(buf)
        if got > NL_MAX:
            raise OSError(errno.EFBIG, "netlink: answer too large")
        for mtype, _, s, payload in nl_messages(buf):
            if s != seq:
                continue
            if mtype == NLMSG_ERROR:
                if len(payload) < 4:
                    raise OSError(errno.EIO, "netlink: short error")
                err = struct.unpack_from("=i", payload)[0]
                if err:
                    raise OSError(-err, os.strerror(-err))
                return out              # the ack
            if mtype == NLMSG_DONE:
                return out
            out.append(payload)


def nl_socket():
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW | socket.SOCK_CLOEXEC, NETLINK_GENERIC)
    try:
        s.settimeout(1.0)
        s.bind((0, 0))
    except BaseException:
        s.close()
        raise
    return s


def genl_family(sock, name: bytes, seq: int = 1):
    """Generic netlink family id of name, None when the kernel has no such family."""
    msg = nl_msg(GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK, seq, CTRL_CMD_GETFAMILY, 1,
                 nl_attr(CTRL_ATTR_FAMILY_NAME, name + b"\0"))
    try:
        answers = nl_request(sock, msg, seq)
    except OSError as e:
        if e.errno == errno.ENOENT:
            return None
        raise
    for payload in answers:
        v = nl_attrs(payload[GENL.size:]).get(CTRL_ATTR_FAMILY_ID)
        if v is not None and len(v) >= 2:
            return struct.unpack_from("=H", v)[0]
    raise OSError(errno.EIO, "netlink: no family id in the answer")


def wifi_ssid(ifname: str, connect=nl_socket):
    """The Wi-Fi name (bytes) the interface is connected to; None: not Wi-Fi / not connected.
    OSError when the kernel cannot be asked."""
    with connect() as s:
        fam = genl_family(s, b"nl80211")
        if fam is None:
            return None                 # no Wi-Fi driver loaded
        seq = 2
        want = ifname.encode("ascii")
        for payload in nl_request(s, nl_msg(fam, NLM_F_REQUEST | NLM_F_DUMP, seq,
                                            NL80211_CMD_GET_INTERFACE, 0), seq):
            a = nl_attrs(payload[GENL.size:])
            if a.get(NL80211_ATTR_IFNAME, b"").rstrip(b"\0") != want:
                continue
            ssid = a.get(NL80211_ATTR_SSID)
            return ssid[:SSID_MAX] if ssid else None
    return None


# --- ids ----------------------------------------------------------------------------------

def net_id(key: bytes, kind: str, ssid: bytes, subnet: str, gw: str) -> str:
    msg = b"\0".join((b"net1", kind.encode(), ssid or b"", subnet.encode(), gw.encode()))
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def mac_id(key: bytes, mac: str) -> str:
    return hmac.new(key, b"mac1\0" + mac.lower().encode(), hashlib.sha256).hexdigest()


def parse_key(data: bytes) -> bytes:
    text = data.decode("ascii", errors="replace").strip()
    if not HEX64.fullmatch(text):
        raise ValueError("not 64 hex digits")
    return bytes.fromhex(text)


def load_key(path: str = KEY, owner: int = 0):
    """-> 32 bytes, None when the file is missing. Unsafe file / bad content -> ValueError."""
    data = read_file(path, owner, KEY_MAX)   # ConfigError is a ValueError
    if data is None:
        return None
    try:
        return parse_key(data)
    except ValueError as e:
        raise ValueError(f"{path}: {e}") from None


def parse_known(text: str) -> dict:
    """lan-known.txt -> {(network id, router id): date}. Comments and odd lines skipped."""
    out = {}
    for line in text.splitlines():
        f = line.split("#", 1)[0].split()
        if len(f) < 2 or not HEX64.fullmatch(f[0]) or not HEX64.fullmatch(f[1]):
            continue
        date = f[2] if len(f) > 2 and DATE_RE.fullmatch(f[2]) else ""
        out[(f[0], f[1])] = date
        if len(out) >= MAX_KNOWN:
            break
    return out


def load_known(path: str = KNOWN, owner: int = 0) -> dict:
    data = read_file(path, owner, KNOWN_MAX)
    return {} if data is None else parse_known(data.decode("ascii", errors="replace"))


def render_known(known: dict) -> str:
    lines = ["# sectop lan box: accepted routers per network (sudo ./install.sh --lan-accept).",
             "# <network id> <router id> <date>: HMAC-SHA256 with /etc/sectop/lan.key.",
             "# No network name, address or MAC in this file (core/lan.py)."]
    for (nid, mid), date in sorted(known.items(), key=lambda kv: (kv[1], kv[0])):
        lines.append(f"{nid} {mid} {date}".rstrip())
    return "\n".join(lines) + "\n"


# --- what the laptop sees now -------------------------------------------------------------

class Seen:
    """One look at the network: uplink, Wi-Fi name, router MAC, ARP, own addresses."""
    __slots__ = ("up", "kind", "ssid", "gw_mac", "arp", "local", "notes")


def look(route=ROUTE, arp=ARP, fib=FIB, ssid_of=wifi_ssid) -> Seen:
    s = Seen()
    s.notes, s.ssid, s.kind, s.gw_mac, s.arp, s.local = [], None, "", None, [], set()
    try:
        s.up = uplink(parse_route(read_proc(route)))
    except OSError as e:
        s.up = None
        s.notes.append(f"{route}: {e.strerror or e}")
    try:
        s.arp = parse_arp(read_proc(arp))
    except OSError as e:
        s.notes.append(f"{arp}: {e.strerror or e}")
    try:
        s.local = parse_fib_local(read_proc(fib))
    except OSError as e:
        s.notes.append(f"{fib}: {e.strerror or e}")
    if s.up is None:
        return s
    try:
        s.ssid = ssid_of(s.up.dev)
        s.kind = "wifi" if s.ssid else "cable"
    except (OSError, ValueError) as e:
        s.kind = "net"
        s.notes.append(f"Wi-Fi name not read ({getattr(e, 'strerror', None) or e}): "
                       "networks with the same router address look the same")
    for ip, mac, dev in s.arp:
        if ip == s.up.gw and dev == s.up.dev:
            s.gw_mac = mac
    return s


KIND_TEXT = {"wifi": "Wi-Fi", "cable": "cable", "net": "network"}


# --- accept (root: sudo ./install.sh --lan-accept) ----------------------------------------

def _write(path: str, text: str, uid: int, gid: int) -> None:
    d, name = os.path.split(path)
    tmp = os.path.join(d, f".{name}.tmp")
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o640)
    try:
        os.fchown(fd, uid, gid)
        os.fchmod(fd, 0o640)
        view = memoryview(text.encode("ascii"))
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def ask(tty: str, out=print) -> str:
    """One numbered choice from the terminal: '1' or '0'; asked again up to 3 times.
    The question ends with a newline (a line filter in front of the screen passes whole
    lines only)."""
    for _ in range(3):
        out("type 1 or 0, then Enter:", flush=True)
        try:
            with open(tty) as t:
                ans = t.readline()
        except OSError:
            return "0"
        if not ans:
            return "0"
        ans = ans.strip().lower()
        if ans in ("1", "0"):
            return ans
        out(f"'{display(ans, width=10)}' is not 1 or 0")
    return "0"


def accept(key_path: str = KEY, known_path: str = KNOWN, tty: str = "/dev/tty",
           look_fn=look, wall=time.time, getgr=grp.getgrnam, euid=os.geteuid,
           out=print, owner: int = 0) -> int:
    """This network's router as trusted: its (network id, router id) into the list.
    owner: uid of the files (root; tests: the test user)."""
    if euid() != 0:
        out("sectop-lan --accept: run as root (sudo ./install.sh --lan-accept)", file=sys.stderr)
        return 2
    try:
        gid = getgr(KNOWN_GROUP).gr_gid
    except KeyError:
        out(f"sectop-lan --accept: no group {KNOWN_GROUP}: install first", file=sys.stderr)
        return 1
    s = look_fn()
    for n in s.notes:
        out(f"note: {display(n)}")
    if s.up is None:
        out("no default route (not connected?): nothing to accept")
        return 1
    if s.gw_mac is None:
        out(f"router {s.up.gw}: no ARP entry yet (no traffic to it so far): try again in a "
            "minute, with the tunnel up")
        return 1
    try:
        key = load_key(key_path, owner)
        known = load_known(known_path, owner)
    except (ValueError, OSError) as e:
        out(f"sectop-lan --accept: {display(str(e))}", file=sys.stderr)
        return 1
    if key is None:
        key = os.urandom(32)
        _write(key_path, key.hex() + "\n", owner, gid)
        out(f"key: {key_path} made (root:{KNOWN_GROUP} 0640, random)")
        known = {}                      # ids made with another key are of no use
    nid = net_id(key, s.kind, s.ssid, s.up.subnet, s.up.gw)
    mid = mac_id(key, s.gw_mac)
    others = sum(1 for (n, m) in known if n == nid and m != mid)
    out("sectop lan: accept this network's router as trusted")
    out(f"  network:  {KIND_TEXT.get(s.kind, s.kind)}, id {nid[:8]} (no name shown)")
    out(f"  router:   {s.up.gw} on {s.up.dev}, subnet {s.up.subnet or '?'} (MAC read, not shown)")
    if (nid, mid) in known:
        out(f"  already accepted ({known[(nid, mid)] or 'no date'}): nothing to do")
        return 0
    out(f"  this network: {'new' if not others else f'{others} other router(s) accepted'}")
    out("Only for a network you trust (your own, or the owner agrees), and only when no")
    out("attack is suspected now: from then on another router MAC here is a red alert.")
    out("  1  accept this router for this network")
    out("  0  stop, change nothing")
    if ask(tty, out) != "1":
        out("lan list: not changed")
        return 0
    known[(nid, mid)] = time.strftime("%Y-%m-%d", time.localtime(wall()))
    _write(known_path, render_known(known), owner, gid)
    out(f"lan list: {known_path} written ({len(known)} accepted; sectop reads it at its next "
        "collect, 5 s)")
    return 0


def main(argv: list | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv != ["--accept"]:
        print("usage: sectop-lan --accept   (root: sudo ./install.sh --lan-accept)",
              file=sys.stderr)
        return 2
    return accept()
