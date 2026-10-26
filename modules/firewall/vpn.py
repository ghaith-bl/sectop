"""Parse `wg show <iface> <field>`. Pure functions.

`wg show <iface> dump` is not used: its first line has the private key.
The per-field subcommands used here never print it.
"""


def _rows(text: str) -> list:
    """Tab separated: public key, value(s). One row per peer."""
    return [line.split("\t") for line in text.splitlines() if line.strip()]


def _int(s: str) -> int:
    v = int(s)
    if v < 0:
        raise ValueError(f"negative value {s!r}")
    return v


def handshake(text: str) -> int:
    """Newest handshake over all peers, epoch seconds. 0 = never."""
    vals = [_int(r[1]) for r in _rows(text) if len(r) >= 2]
    if not vals:
        raise ValueError("wg: no peer in latest-handshakes")
    return max(vals)


def transfer(text: str) -> tuple:
    """(rx, tx) bytes, summed over peers."""
    rx = tx = 0
    rows = [r for r in _rows(text) if len(r) >= 3]
    if not rows:
        raise ValueError("wg: no peer in transfer")
    for r in rows:
        rx += _int(r[1])
        tx += _int(r[2])
    return rx, tx


def endpoint(text: str) -> str:
    """First peer endpoint, '(none)' if not set."""
    rows = [r for r in _rows(text) if len(r) >= 2]
    if not rows:
        raise ValueError("wg: no peer in endpoints")
    return rows[0][1]


def fwmark(text: str) -> int | None:
    """'0x6d6f6c65' -> int; 'off' -> None."""
    s = text.strip()
    if s == "off":
        return None
    return int(s, 16) if s.lower().startswith("0x") else _int(s)

