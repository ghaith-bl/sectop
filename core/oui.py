"""Maker of a network card from its MAC address, offline (2026-11-11).

The first 3 bytes of a hardware MAC (the OUI / MA-L block) are registered by the maker
at the IEEE. The distro ships that list: hwdata (Fedora, RHEL, Arch) or ieee-data
(Debian, Ubuntu), updated with the system. No network, no web lookup service: a web
service would learn every device on my LAN.

- read only on demand (a log card opens), one prefix at a time, answers cached
- a MAC with the locally administered bit (0x02 of the first byte) has no maker: random
  Wi-Fi addresses of phones, VMs (52:54:00), containers
- only MA-L (24-bit) blocks: a device from a smaller block (MA-M / MA-S) shows
  "maker not in the list"
Pure except maker() (reads one file).
"""

import re
import unicodedata

PATHS = ("/usr/share/hwdata/oui.txt",      # hwdata: Fedora, RHEL, Arch
         "/usr/share/ieee-data/oui.txt")   # ieee-data: Debian, Ubuntu
MAX_BYTES = 16 * 1024 * 1024               # the list is ~6 MiB
NAME_MAX = 60

_MAC = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}")
_cache: dict = {}


def parts(field: str) -> tuple | None:
    """Kernel log MAC field 'dst:src:type' (6 + 6 + 2 bytes) -> (dst, src, type)."""
    b = (field or "").lower().split(":")
    if len(b) != 14 or not all(re.fullmatch(r"[0-9a-f]{2}", x) for x in b):
        return None
    return ":".join(b[0:6]), ":".join(b[6:12]), "".join(b[12:14])


def kind(mac: str) -> str | None:
    """broadcast, multicast, local (no maker: random / virtual), global; None if not a MAC."""
    mac = (mac or "").lower()
    if not _MAC.fullmatch(mac):
        return None
    if mac == "ff:ff:ff:ff:ff:ff":
        return "broadcast"
    first = int(mac[:2], 16)
    if first & 0x01:
        return "multicast"
    if first & 0x02:
        return "local"
    return "global"


def _ascii(name: str) -> str:
    s = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    s = " ".join("".join(c if c.isprintable() else " " for c in s).split())
    return s[:NAME_MAX]


def _find(prefix: str, paths) -> tuple:
    """-> (name or None, list found: bool). One read of the list per new prefix."""
    key = ("\n" + prefix.upper().replace(":", "-")).encode()
    for path in paths:
        try:
            with open(path, "rb") as f:
                data = b"\n" + f.read(MAX_BYTES)
        except OSError:
            continue
        i = data.find(key)
        while i >= 0:
            end = data.find(b"\n", i + 1)
            line = data[i + 1:end if end >= 0 else len(data)].decode("utf-8", "replace")
            if "(hex)" in line:
                return _ascii(line.split("(hex)", 1)[1]) or None, True
            i = data.find(key, i + 1)
        return None, True
    return None, False


def maker(mac: str, paths=PATHS) -> str | None:
    """Maker name of a global MAC, None if not in the list or no list."""
    if kind(mac) != "global":
        return None
    prefix = mac.lower()[:8]
    k = (prefix, tuple(paths))
    if k not in _cache:
        _cache[k] = _find(prefix, paths)
    return _cache[k][0]


def describe(mac: str, paths=PATHS) -> str:
    """One line for the fields view: what the address says about the device."""
    k = kind(mac)
    if k is None:
        return "-"
    if k == "broadcast":
        return "broadcast (every device on the LAN)"
    if k == "multicast":
        return "multicast (a group address, no single device)"
    if k == "local":
        return "local address (random or virtual): no maker"
    name = maker(mac, paths)
    if name:
        return name
    prefix = mac.lower()[:8]
    if not _cache.get((prefix, tuple(paths)), (None, False))[1]:
        return "maker unknown: no OUI list (package hwdata or ieee-data)"
    return "maker not in the list"


def short(name: str | None) -> str:
    """Table cell: 'Honor Device Co., Ltd.' -> 'Honor Device'."""
    if not name:
        return "-"
    s = name.split(",")[0].strip()
    s = re.sub(r"\s+(co|corp|corporation|inc|ltd|llc|gmbh|limited)\.?$", "", s,
               flags=re.IGNORECASE).strip()
    return s or name


def cell(mac: str | None, paths=PATHS) -> str:
    """Maker column of a flow: the source MAC's maker, 'local mac', or '-'."""
    k = kind(mac or "")
    if k == "local":
        return "local mac"
    if k != "global":
        return "-"
    return short(maker(mac, paths)) if maker(mac, paths) else "?"
