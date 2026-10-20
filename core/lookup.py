"""whois for a public IP: asks the RDAP socket service (core/rdap.py).

The UI runs as my user and must not parse network data with my rights, and
cannot switch to another user. So the lookup runs in sectop-whois@.service:
one instance per connection to SOCKET, its own dynamic user, network and
nothing else (docs/architecture.md, Privilege split). Here: connect, send
the IP, read the one JSON line back, check it. It goes out via the tunnel
like any program (audit shows it). Only on key press, one lookup per address
per session (cache in core/ui.py). Blocks the UI up to TIMEOUT (core/app.py,
the UI).
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


def public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
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
        return _err("not a public address: no whois")
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
