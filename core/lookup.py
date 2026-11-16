"""whois for a public IP: asks the RDAP socket service (core/rdap.py).

The UI runs as my user and must not parse network data with my rights, and
cannot switch to another user. So the lookup runs in sectop-whois@.service:
one instance per connection to SOCKET, its own dynamic user, network and
nothing else (docs/architecture.md, Privilege split). Here: connect, send
the IP, read the one JSON line back, check it. It goes out via the tunnel
like any program (audit shows it). Only on key press, one lookup per address
per session (cache in core/ui.py). Blocks the UI up to TIMEOUT (core/app.py,
the UI).

Special-purpose addresses (multicast, broadcast, private, link-local, ...) have no
owner in any registry: special() names them here, nothing is sent anywhere.
"""

import ipaddress
import json
import socket
import time

SOCKET = "/run/sectop-whois.sock"
TIMEOUT = 12.0
MAX_FIELDS = 20
MAX_VALUE = 200
MAX_ANSWER = 65536


# Most specific first: the first network that holds the address wins (IANA
# special-purpose registries, RFC 6890; multicast: IANA multicast address space).
SPECIAL = tuple((ipaddress.ip_network(n), what) for n, what in (
    ("224.0.0.1/32", "multicast: all hosts on this network"),
    ("224.0.0.2/32", "multicast: all routers on this network"),
    ("224.0.0.22/32", "multicast: IGMPv3 reports (a program joined a multicast group)"),
    ("224.0.0.251/32", "multicast: mDNS (local names and service discovery)"),
    ("224.0.0.252/32", "multicast: LLMNR (local name lookup)"),
    ("239.255.255.250/32", "multicast: SSDP / UPnP discovery"),
    ("224.0.0.0/24", "multicast: local network control, never routed"),
    ("239.0.0.0/8", "multicast: organization-local scope"),
    ("224.0.0.0/4", "multicast"),
    ("255.255.255.255/32", "broadcast: every device on this network"),
    ("0.0.0.0/8", "this network / unspecified"),
    ("10.0.0.0/8", "private network (RFC 1918)"),
    ("100.64.0.0/10", "shared address space, carrier-grade NAT (RFC 6598)"),
    ("127.0.0.0/8", "loopback: this machine"),
    ("169.254.0.0/16", "link-local: no DHCP answer (RFC 3927)"),
    ("172.16.0.0/12", "private network (RFC 1918)"),
    ("192.0.0.0/24", "IETF protocol assignments"),
    ("192.0.2.0/24", "documentation (TEST-NET-1)"),
    ("192.168.0.0/16", "private network (RFC 1918)"),
    ("198.18.0.0/15", "benchmarking (RFC 2544)"),
    ("198.51.100.0/24", "documentation (TEST-NET-2)"),
    ("203.0.113.0/24", "documentation (TEST-NET-3)"),
    ("240.0.0.0/4", "reserved"),
    ("ff02::1/128", "multicast: all nodes on this link"),
    ("ff02::2/128", "multicast: all routers on this link"),
    ("ff02::16/128", "multicast: MLDv2 reports (a program joined a multicast group)"),
    ("ff02::fb/128", "multicast: mDNS (local names and service discovery)"),
    ("ff02::1:2/128", "multicast: DHCPv6 servers and relays"),
    ("ff02::1:3/128", "multicast: LLMNR (local name lookup)"),
    ("ff02::1:ff00:0/104", "multicast: solicited-node (neighbor discovery)"),
    ("ff02::/16", "multicast: this link only"),
    ("ff00::/8", "multicast"),
    ("::/128", "unspecified"),
    ("::1/128", "loopback: this machine"),
    ("::ffff:0:0/96", "IPv4-mapped IPv6 address"),
    ("64:ff9b::/96", "NAT64 (IPv4 behind IPv6)"),
    ("2001:db8::/32", "documentation"),
    ("fc00::/7", "unique local, private (ULA)"),
    ("fe80::/10", "link-local"),
))


def special(ip: str) -> list | None:
    """Detail pairs for a special-purpose address, None for a public (or bad) one."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    what = next((w for n, w in SPECIAL if a.version == n.version and a in n), None)
    if what is None:
        if _public(a):
            return None
        what = "special-purpose address"
    return [("address", str(a)), ("kind", what),
            ("whois", "no owner in any registry: named here, nothing looked up")]


def _public(a) -> bool:
    # is_global is True for most multicast (224.0.0.22 too): no registry owns those
    return a.is_global and not a.is_multicast


def public(ip: str) -> bool:
    try:
        return _public(ipaddress.ip_address(ip))
    except ValueError:
        return False


def _err(text: str) -> list:
    return [("whois", text[:MAX_VALUE])]


def _fields(out: str) -> list:
    lines = [ln for ln in out.splitlines() if ln.strip()]
    doc = json.loads(lines[-1]) if lines else None
    if not isinstance(doc, dict):
        raise ValueError("no JSON object")
    if not doc.get("ok"):
        err = doc.get("error")
        return _err(err if isinstance(err, str) else "lookup failed")
    fields = doc.get("fields")
    if not isinstance(fields, list):
        raise ValueError("fields: list required")
    pairs = []
    for f in fields[:MAX_FIELDS]:
        if not (isinstance(f, list) and len(f) == 2 and all(isinstance(x, str) for x in f)):
            raise ValueError("fields: [str, str] pairs required")
        pairs.append((f[0][:40], f[1][:MAX_VALUE]))
    return pairs


def ask(path: str, ip: str, timeout: float = TIMEOUT, clock=time.monotonic) -> str:
    """One request on the unix socket -> the answer text. Whole exchange within timeout."""
    deadline = clock() + timeout
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(path)
        s.sendall(ip.encode("ascii") + b"\n")
        s.shutdown(socket.SHUT_WR)
        buf = bytearray()
        while True:
            left = deadline - clock()
            if left <= 0:
                raise TimeoutError("timed out")
            s.settimeout(left)
            chunk = s.recv(MAX_ANSWER)
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_ANSWER:
                raise ValueError("answer larger than 64 KiB")
    return buf.decode("utf-8", errors="replace")


def lookup(ip: str, ask=ask, path: str = SOCKET) -> list:
    """-> [(key, value)] for the detail view. A problem comes back as one 'whois' pair."""
    if not public(ip):
        return special(ip) or _err("not an IP address: no whois")
    try:
        out = ask(path, ip, TIMEOUT)
    except FileNotFoundError:
        return _err(f"{path} missing: sectop-whois.socket not running? (docs/install.md)")
    except PermissionError:
        return _err(f"{path}: permission denied: my user in group sectop? "
                    "(log in again after install)")
    except TimeoutError:
        return _err(f"timeout after {TIMEOUT:g} s")
    except ConnectionRefusedError:
        return _err(f"{path}: connection refused: sectop-whois.socket stopped?")
    except OSError as e:
        return _err(f"{path}: {e.strerror or e}")
    except ValueError as e:
        return _err(f"bad service answer: {e}")
    try:
        pairs = _fields(out)
    except ValueError as e:                       # JSONDecodeError too
        return _err(f"bad service answer: {e}")
    return pairs + [("via", f"RDAP by sectop-whois.service (own dynamic user), "
                            f"timeout {TIMEOUT:g} s")]
