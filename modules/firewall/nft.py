"""Parse `nft -j` output for the hostfw table. Pure functions, no I/O."""

import json


def _items(text: str) -> list:
    doc = json.loads(text)
    if not isinstance(doc, dict) or not isinstance(doc.get("nftables"), list):
        raise ValueError("nft: no nftables list")
    return [it for it in doc["nftables"] if isinstance(it, dict)]


def _count(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


def counters(text: str) -> dict:
    """`list counters table inet hostfw` -> {name: (packets, bytes)}, nft order."""
    out = {}
    for it in _items(text):
        c = it.get("counter")
        if not isinstance(c, dict):
            continue
        name, pkts, nbytes = c.get("name"), c.get("packets"), c.get("bytes")
        if not isinstance(name, str) or not _count(pkts) or not _count(nbytes):
            raise ValueError(f"nft: bad counter {name!r}")
        out[name] = (pkts, nbytes)
    return out


def mode(text: str) -> str:
    """`list chain inet hostfw enforce` -> observe | enforce | unknown.

    hostfw contract: empty chain = observe, one reject rule = enforce.
    """
    rules = [it["rule"] for it in _items(text) if isinstance(it.get("rule"), dict)]
    if not rules:
        return "observe"
    expr = rules[0].get("expr")
    if len(rules) == 1 and isinstance(expr, list) and \
            any(isinstance(e, dict) and "reject" in e for e in expr):
        return "enforce"
    return "unknown"


def set_elems(text: str) -> list:
    """`list set inet hostfw <name>` -> list of int elements (mark sets)."""
    for it in _items(text):
        s = it.get("set")
        if not isinstance(s, dict):
            continue
        elems = s.get("elem", [])
        if not isinstance(elems, list) or not all(_count(e) for e in elems):
            raise ValueError("nft: set elements must be integers")
        return elems
    raise ValueError("nft: no set in output")


def missing(err: str) -> bool:
    """nft error output for a table / chain / set that does not exist."""
    return "No such file or directory" in err
