"""Make untrusted text safe to draw in a terminal.

Every string from a module is untrusted (log lines, process names,
command output). Core calls display() on each one before drawing.
"""

import ipaddress
import re
import unicodedata

TRUNC = "~"

# IPv6 first: a run of hex groups with 2+ colons, optional dotted tail
# (::ffff:1.2.3.4) and zone id. The run is matched whole, so a MAC
# (14 groups) or a time (13:26:30) fails to parse and stays as is.
# IPv4 may be followed by ":port" and preceded by "src:".
# When unsure, mask: a 4-part version string (6.18.44.1) may get masked too.
_ADDR = re.compile(
    r"(?<![0-9A-Za-z:.])"
    r"(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f.]*(?:%[0-9A-Za-z_.-]+)?"
    r"(?![0-9A-Za-z:])"
    r"|"
    r"(?<![0-9A-Za-z.])"
    r"\d{1,3}(?:\.\d{1,3}){3}"
    r"(?![0-9A-Za-z])(?!\.\d)"
)


def clean(text: object) -> str:
    """Tab and space separators -> ' ', anything else not printable -> '?'.

    Covers C0 / C1 controls (incl. ESC, newline), DEL, format chars
    (bidi overrides, zero-width), line / paragraph separators,
    surrogates, private use, unassigned code points.
    """
    s = text if isinstance(text, str) else str(text)
    if s.isprintable():
        return s
    out = []
    for ch in s:
        if ch.isprintable():
            out.append(ch)
        elif ch == "\t" or unicodedata.category(ch) == "Zs":
            out.append(" ")
        else:
            out.append("?")
    return "".join(out)


def _maskable(addr) -> bool:
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


def _mask(addr) -> str:
    if addr.version == 4:
        a, b = str(addr).split(".")[:2]
        return f"{a}.{b}.x.x"
    if addr.ipv4_mapped is not None:
        return "::ffff:" + _mask(addr.ipv4_mapped)
    g = addr.exploded.split(":")
    return f"{int(g[0], 16):x}:{int(g[1], 16):x}::x"


def _repl(m: re.Match) -> str:
    token = m.group(0)
    # Retry without trailing dots: "... to 8.8.8.8."
    for body in (token, token.rstrip(".")):
        try:
            addr = ipaddress.ip_address(body)
        except ValueError:
            continue
        if not _maskable(addr):
            return token
        return _mask(addr) + token[len(body):]
    return token


def mask_ips(text: str) -> str:
    """Mask public (global, non-multicast) IPv4 / IPv6 addresses in text."""
    return _ADDR.sub(_repl, text)


# Secrets in a command line (docs/architecture.md, Security screen, Commands): kept off
# the screen only; argv is in /proc/<pid>/cmdline, audit and the journal anyway.
SECRET = "***"
_FLAG = re.compile(r"(--(?:password|passwd|token|secret|api-key)(?:=|\s+))(\S+)", re.I)
_URL = re.compile(r"(\b[a-z][a-z0-9+.-]*://[^\s/:@]+:)([^\s/@]+)(@)", re.I)
_ENV = re.compile(r"(\b[A-Z0-9_]*(?:PASSWORD|PASSWD|TOKEN|SECRET)=)(\S+)")


def mask_secrets(text: str) -> str:
    """Values of --password / --passwd / --token / --secret / --api-key, user:pass@ in
    URLs, *_PASSWORD= / *_TOKEN= / *_SECRET= -> ***."""
    text = _FLAG.sub(lambda m: m.group(1) + SECRET, text)
    text = _URL.sub(lambda m: m.group(1) + SECRET + m.group(3), text)
    return _ENV.sub(lambda m: m.group(1) + SECRET, text)


def truncate(s: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(s) <= width:
        return s
    return s[: width - 1] + TRUNC


def display(text: object, mask: bool = True, width: int | None = None,
            secrets: bool | None = None) -> str:
    """clean -> mask -> truncate. Mask before cut, so no partial public IP is shown.
    secrets: mask secrets too (default: same as mask; a detail shows real IPs but keeps
    secrets masked while mask is on)."""
    s = clean(text)
    if mask if secrets is None else secrets:
        s = mask_secrets(s)
    if mask:
        s = mask_ips(s)
    if width is not None:
        s = truncate(s, width)
    return s
