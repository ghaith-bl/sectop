"""Parse `wg show <iface> <field>` and `ip -j route show default`. Pure functions.

`wg show <iface> dump` is not used: its first line has the private key.
The per-field subcommands used here never print it.
"""

import json


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
    """'0xea13b2c' -> int; 'off' -> None."""
    s = text.strip()
    if s == "off":
        return None
    return int(s, 16) if s.lower().startswith("0x") else _int(s)


def routes(text: str) -> list:
    """`ip -j route show default` -> [(dev, metric, gateway)], lowest metric first."""
    if not text.strip():
        return []
    doc = json.loads(text)
    if not isinstance(doc, list):
        raise ValueError("ip: list required")
    out = []
    for r in doc:
        if not isinstance(r, dict) or not isinstance(r.get("dev"), str):
            continue
        metric = r.get("metric", 0)
        if not isinstance(metric, int) or isinstance(metric, bool):
            raise ValueError("ip: bad metric")
        gw = r.get("gateway") if isinstance(r.get("gateway"), str) else ""
        out.append((r["dev"], metric, gw))
    return sorted(out, key=lambda x: x[1])
