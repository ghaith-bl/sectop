"""Parse `nft -j` output (hostfw table, VPN kill switch table). Pure functions, no I/O."""

import ipaddress
import json


def _items(text: str) -> list:
    doc = json.loads(text)
    if not isinstance(doc, dict) or not isinstance(doc.get("nftables"), list):
        raise ValueError("nft: no nftables list")
    return [it for it in doc["nftables"] if isinstance(it, dict)]


def _count(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


def counters(text: str) -> dict:
    """`list counters table inet hostfw` or `-t list table inet hostfw`
    -> {name: (packets, bytes)}, nft order."""
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


def comments(text: str) -> dict:
    """Same output as counters() -> {name: comment} (rule meaning)."""
    out = {}
    for it in _items(text):
        c = it.get("counter")
        if isinstance(c, dict) and isinstance(c.get("name"), str) \
                and isinstance(c.get("comment"), str):
            out[c["name"]] = c["comment"]
    return out


def mode(text: str) -> str:
    """`list chain inet hostfw enforce` or `-t list table inet hostfw`
    -> observe | enforce | unknown.

    hostfw contract: chain `enforce` empty = observe, one reject rule = enforce.
    Only rules of chain `enforce` count. No chain `enforce` in the output = unknown.
    """
    items = _items(text)
    chains = {c.get("name") for c in (it.get("chain") for it in items) if isinstance(c, dict)}
    if "enforce" not in chains:
        return "unknown"
    rules = [it["rule"] for it in items
             if isinstance(it.get("rule"), dict) and it["rule"].get("chain") == "enforce"]
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


def addr_elems(text: str) -> list:
    """`list set inet hostfw <ipv4_addr set>` -> list of addresses (str). Empty set: []."""
    for it in _items(text):
        s = it.get("set")
        if not isinstance(s, dict):
            continue
        elems = s.get("elem", [])
        if not isinstance(elems, list) or not all(_ipv4(e) for e in elems):
            raise ValueError("nft: set elements must be IPv4 addresses")
        return elems
    raise ValueError("nft: no set in output")


def _ipv4(x) -> bool:
    try:
        return isinstance(x, str) and ipaddress.IPv4Address(x).compressed == x
    except ValueError:
        return False


_API = [({"payload": {"protocol": "tcp", "field": "dport"}}, 443),
        ({"meta": {"key": "skuid"}}, 0)]
_DADDR = {"payload": {"protocol": "ip", "field": "daddr"}}


def api_addrs(text: str) -> list:
    """`-t list table inet mullvad` -> sorted addresses of Mullvad's API rule in chain
    output: exactly `ip daddr <addr> tcp dport 443 meta skuid 0 accept` (any order).
    Mullvad has it only while not connected; the relay rule has a mark, not skuid.
    Same match as `hostfw api-update` (silverblue-cis-hardening firewall/hostfw.sh)."""
    out = set()
    for it in _items(text):
        r = it.get("rule")
        if not isinstance(r, dict) or r.get("chain") != "output" or \
                not isinstance(r.get("expr"), list):
            continue
        expr = [e for e in r["expr"] if isinstance(e, dict)]
        m = [e["match"] for e in expr if isinstance(e.get("match"), dict)]
        if len(expr) != 4 or len(m) != 3 or expr[-1] != {"accept": None} or \
                any(x.get("op") != "==" for x in m):
            continue
        got = [(x.get("left"), x.get("right")) for x in m]
        ip = [v for k, v in got if k == _DADDR]
        if len(ip) == 1 and _ipv4(ip[0]) and all(w in got for w in _API):
            out.add(ip[0])
    return sorted(out)


def policies(text: str) -> dict:
    """`-t list table <family> <name>` -> {hook: policy} of its filter base chains,
    e.g. {"input": "drop", "output": "drop"}. A hook with a drop policy in any filter
    chain = drop (unmatched packets end there). route / nat chains do not filter."""
    out = {}
    for it in _items(text):
        c = it.get("chain")
        if not isinstance(c, dict) or "hook" not in c or c.get("type", "filter") != "filter":
            continue
        hook, pol = c.get("hook"), c.get("policy", "accept")
        if not isinstance(hook, str) or not isinstance(pol, str):
            raise ValueError("nft: bad base chain")
        out[hook] = "drop" if "drop" in (pol, out.get(hook)) else pol
    return out


def missing(err: str) -> bool:
    """nft error output for a table / chain / set that does not exist."""
    return "No such file or directory" in err
