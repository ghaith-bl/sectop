"""lan: the network this laptop is on, on screen 1 (firewall). docs/modules/lan.md

Step 11b2a (2026-11-27; design 2026-11-24): two of the four red alerts Ghaith asked for.
- Router MAC (ARP spoofing, a fake router): per network, the router's MAC compared with
  the routers accepted for that network (`sudo ./install.sh --lan-accept`). A network
  not accepted yet: compared with the first MAC seen for it since sectop started (trust
  on first use, this run only). Another MAC = red.
- The router's MAC on another address of the LAN (one device answering for two
  addresses, the other sign of ARP spoofing) = red.
- Rogue DHCP: a DHCP server answering on the uplink that is not the router, or on a VM
  bridge one that is not this host = red. From Suricata's DHCP records, counted by
  sectop-ids (core/idsd.py, the summary's dhcp part). On the uplink only answers since
  this network came up count (minus 60 s: the answer that brought it up comes first).

Sources: core/lan.py (/proc/net/route, /proc/net/arp, /proc/net/fib_trie, the Wi-Fi name
through nl80211), /etc/sectop/lan.key + lan-known.txt (root-owned, read again when they
change), /run/sectop-ids/summary.json. No MAC and no Wi-Fi name leaves the collector:
HMAC-SHA256 with the local key; the box shows the first 8 hex digits of a network id.

Options ([modules.lan] in /etc/sectop/config.toml): `dhcp_ok` = list of IPv4 addresses of
DHCP servers that are fine besides the router (a Pi-hole, a second router).
"""

import ipaddress
import os
import pwd
import time

from core import lan, statefile
from core.config import ConfigError

NAME = "lan"
INTERVAL = 5.0
SUMMARY = "/run/sectop-ids/summary.json"
SUMMARY_OWNER = "sectop-ids"
SUMMARY_MAX = 1 << 20
HOLD = 3600.0
MARGIN = 60.0                    # a network's first DHCP answer comes before its route
MAX_SESSIONS = 20
MAX_DHCP = 50
MAX_OK = 20
ACCEPT = "sudo ./install.sh --lan-accept"
DHCP_COLUMNS = ["last", "24 h", "hour", "where", "server", "is"]
DHCP_TYPES = ["age", "num", "num", "text", "text", "text"]
RANK = {"crit": 3, "warn": 2, "info": 1, "ok": 0}


class Session:
    """One network since sectop started: the router MACs seen (as ids, first seen)."""
    __slots__ = ("first", "first_mid", "macs")

    def __init__(self, now: float):
        self.first, self.first_mid, self.macs = now, None, {}


class State:
    def __init__(self, key_path=lan.KEY, known_path=lan.KNOWN, summary=SUMMARY,
                 etc_owner=0, summary_owner=None, look=lan.look, wall=time.time,
                 dhcp_ok=(), clock=lambda ts: time.strftime("%H:%M", time.localtime(ts)),
                 stamp=lambda ts: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))):
        self.key_path, self.known_path, self.summary = key_path, known_path, summary
        self.etc_owner, self.summary_owner = etc_owner, summary_owner
        self.look, self.wall, self.clock, self.stamp = look, wall, clock, stamp
        self.dhcp_ok = set(dhcp_ok)
        self.run_key = os.urandom(32)   # no key file yet: ids for this run only
        self.key, self.known, self.files_note = None, {}, ""
        self.key_m = self.known_m = ()
        self.sessions = {}              # network id -> Session
        self.net, self.since = None, wall()
        self.sum_m, self.dhcp, self.sum_note = None, [], ""
        self.dhcp_seen = {}             # (iface, server) -> (last, n24) reported


def _ips(v) -> set:
    if not isinstance(v, list) or len(v) > MAX_OK:
        raise ValueError(f"dhcp_ok: list of max {MAX_OK} IPv4 addresses required")
    out = set()
    for a in v:
        try:
            out.add(str(ipaddress.IPv4Address(a)))
        except (ValueError, TypeError):
            raise ValueError(f"dhcp_ok: {a!r} is not an IPv4 address") from None
    return out


def init(cfg: dict) -> State:
    cfg = dict(cfg)
    ok = _ips(cfg.pop("dhcp_ok", []))
    if cfg:
        raise ValueError(f"unknown option(s): {', '.join(sorted(cfg))}")
    return State(dhcp_ok=ok)


def close(st: State) -> None:
    pass


# --- files ----------------------------------------------------------------------------------

def _mtime(path: str) -> tuple:
    try:
        s = os.stat(path)
        return (s.st_mtime_ns, s.st_ino, s.st_size)
    except FileNotFoundError:
        return ()
    except OSError as e:
        return ("error", e.errno)


def reload(st: State) -> None:
    """Key + accepted list, read again when either file changed."""
    km, nm = _mtime(st.key_path), _mtime(st.known_path)
    if (km, nm) == (st.key_m, st.known_m):
        return
    st.key_m, st.known_m = km, nm
    old = st.key
    try:
        data = lan.read_file(st.key_path, st.etc_owner, lan.KEY_MAX)
        st.key = None if data is None else lan.parse_key(data)
        data = lan.read_file(st.known_path, st.etc_owner, lan.KNOWN_MAX) if st.key else None
        st.known = {} if data is None else lan.parse_known(data.decode("ascii", "replace"))
        st.files_note = ""
    except (ConfigError, ValueError, OSError) as e:
        st.key, st.known = None, {}
        st.files_note = f"lan key / list not used: {e}"[:200]
    if st.key != old:
        st.sessions.clear()             # other ids from here on


def _summary_owner(st: State) -> int:
    if st.summary_owner is not None:
        return st.summary_owner
    try:
        return pwd.getpwnam(SUMMARY_OWNER).pw_uid
    except KeyError:
        raise ValueError(f"no user {SUMMARY_OWNER}") from None


def _num(d: dict, key: str) -> float:
    v = d.get(key)
    if not isinstance(v, (int, float)) or isinstance(v, bool) or not 0 <= v < 1e11:
        raise ValueError(f"dhcp.{key}: number required")
    return float(v)


def _count(d: dict, key: str) -> int:
    v = d.get(key)
    if type(v) is not int or not 0 <= v <= 10 ** 9:
        raise ValueError(f"dhcp.{key}: count required")
    return v


def check_dhcp(items) -> list:
    """The summary's dhcp part (core/idsd.py doc()) -> checked list. Wrong -> ValueError."""
    if items is None:
        return []                       # an older sectop-ids
    if not isinstance(items, list) or len(items) > MAX_DHCP:
        raise ValueError(f"dhcp: list of max {MAX_DHCP} required")
    out = []
    for d in items:
        if not isinstance(d, dict):
            raise ValueError("dhcp: objects required")
        iface, server, types = d.get("iface"), d.get("server"), d.get("types")
        if not isinstance(iface, str) or (iface and not lan.IFNAME_RE.fullmatch(iface)):
            raise ValueError("dhcp.iface: interface name required")
        try:
            server = str(ipaddress.IPv4Address(server))
        except (ValueError, TypeError):
            raise ValueError("dhcp.server: IPv4 address required") from None
        if not isinstance(types, list) or len(types) > 4 or not all(
                isinstance(t, str) and (t == "?" or t.isalpha() and t.islower()) and len(t) <= 12
                for t in types):
            raise ValueError("dhcp.types: max 4 short words required")
        out.append({"iface": iface, "server": server, "types": list(types),
                    "first": _num(d, "first"), "last": _num(d, "last"),
                    "n24": _count(d, "n24"), "nh": _count(d, "nh")})
    return out


def load_summary(st: State) -> None:
    m = _mtime(st.summary)
    if not m:
        st.sum_m, st.dhcp = None, []
        st.sum_note = "no ids summary: DHCP not watched (Suricata / sectop-ids off?)"
        return
    if m == st.sum_m:
        return
    try:
        d = statefile.load(st.summary, _summary_owner(st), SUMMARY_MAX)
        if not isinstance(d, dict):
            raise ValueError("not an object")
        st.dhcp, st.sum_note, st.sum_m = check_dhcp(d.get("dhcp")), "", m
    except (statefile.StateError, ValueError) as e:
        st.sum_m, st.dhcp = None, []
        st.sum_note = f"ids summary (dhcp): {e}"[:200]


# --- the look -------------------------------------------------------------------------------

def judge(g: dict, s, since: float, ok: set) -> tuple:
    """A DHCP server -> (what it is, sev)."""
    if g["server"] in s.local:
        return "this host", "ok"
    if g["server"] in ok:
        return "fine (config dhcp_ok)", "ok"
    if g["iface"].startswith("virbr"):
        return "NOT this host: rogue DHCP on a VM bridge?", "crit"
    if s.up is not None and g["iface"] == s.up.dev:
        if g["server"] == s.up.gw:
            return "the router", "ok"
        if g["last"] < since - MARGIN:
            return "before this network (not checked)", "info"
        return "NOT the router: rogue DHCP?", "crit"
    return "another network (not checked)", "info"


def own_item(s) -> dict:
    """This laptop on the LAN: its own address(es) in the router's subnet + the device
    (2026-11-28; a local address is fine to show, his privacy rule). From fib_trie."""
    try:
        net = ipaddress.IPv4Network(s.up.subnet) if s.up.subnet else None
    except ValueError:
        net = None
    mine = sorted((ip for ip in s.local if net is not None
                   and ipaddress.IPv4Address(ip) in net), key=ipaddress.IPv4Address)
    if not mine:
        where = f" in {s.up.subnet}" if s.up.subnet else ""
        return {"k": "this laptop", "v": f"no own address{where} found ({s.up.dev})",
                "sev": "info"}
    more = f" +{len(mine) - 2}" if len(mine) > 2 else ""
    return {"k": "this laptop", "v": f"{', '.join(mine[:2])}{more} on {s.up.dev}"}


def _session(st: State, nid: str, now: float) -> Session:
    sess = st.sessions.get(nid)
    if sess is None:
        if len(st.sessions) >= MAX_SESSIONS:
            del st.sessions[min(st.sessions, key=lambda k: st.sessions[k].first)]
        sess = st.sessions[nid] = Session(now)
    return sess


def collect(st: State, ctx) -> dict:
    now = st.wall()
    s = st.look()
    reload(st)
    load_summary(st)
    key = st.key or st.run_key
    nid = "" if s.up is None else lan.net_id(key, s.kind, s.ssid, s.up.subnet, s.up.gw)
    if nid != st.net:
        st.net, st.since = nid, now
    checks, items = [], []
    notes = [n for n in s.notes + [st.files_note, st.sum_note] if n]
    status_sev = "ok"
    accepted = {}

    if s.up is None:
        items.append({"k": "network", "v": "none: no default route", "sev": "info"})
        summary = "no network"
    else:
        id8 = nid[:8]
        kind = lan.KIND_TEXT.get(s.kind, s.kind)
        accepted = {m: d for (n, m), d in st.known.items() if n == nid}
        items.append({"k": "network", "v": f"{kind}, id {id8} (no name shown)"})
        items.append({"k": "router", "v": f"{s.up.gw} on {s.up.dev}"
                      + (f", {s.up.subnet}" if s.up.subnet else "")})
        items.append(own_item(s))
        sess = _session(st, nid, now)
        if s.gw_mac is None:
            items.append({"k": "router MAC", "v": "not in the ARP table yet", "sev": "info"})
            state = "no MAC yet"
        else:
            mid = lan.mac_id(key, s.gw_mac)
            sess.macs.setdefault(mid, now)
            if sess.first_mid is None:
                sess.first_mid = mid
            trusted = set(accepted) or {sess.first_mid}
            if mid in trusted:
                if accepted:
                    v, sev, state = f"accepted {accepted[mid] or ''}".rstrip(), "ok", "accepted"
                else:
                    v = f"not accepted yet; same since {st.clock(sess.macs[mid])}"
                    sev, state = "info", "not accepted"
            else:
                why = "an accepted one" if accepted else \
                    f"the one seen first (since {st.clock(sess.first)})"
                v, sev, state = "CHANGED: ARP spoofing / a new router?", "crit", "CHANGED"
                checks.append({
                    "key": f"gw_changed:{id8}", "sev": "crit",
                    "title": f"LAN: router MAC changed on network {id8} (ARP spoofing?)",
                    "detail": (f"router {s.up.gw} on {s.up.dev}: its MAC is not {why}. A new "
                               f"router of your own: {ACCEPT} (tty3)")[:300],
                    "hold": HOLD})
            items.append({"k": "router MAC", "v": v, "sev": sev})
        # trusted now: accepted for this network, else the first one seen (an accept during
        # the run turns a changed one white)
        trusted = set(accepted) or {sess.first_mid}
        bad = sum(1 for m in sess.macs if m not in trusted)
        items.append({"k": "MACs seen", "v": f"{len(sess.macs)} this session, {bad} not trusted",
                      "sev": "crit" if bad else "ok"})
        dups = sorted({ip for ip, mac, dev in s.arp
                       if s.gw_mac and dev == s.up.dev and mac == s.gw_mac and ip != s.up.gw},
                      key=ipaddress.IPv4Address)
        if dups:
            items.append({"k": "same MAC", "v": "also " + ", ".join(dups[:3])
                          + (f" +{len(dups) - 3}" if len(dups) > 3 else ""), "sev": "crit"})
            for ip in dups[:10]:
                checks.append({
                    "key": f"mac_dup:{ip}", "sev": "crit",
                    "title": f"LAN: the router's MAC also answers for {ip} (ARP spoofing?)",
                    "detail": (f"router {s.up.gw} on {s.up.dev}: the same MAC is in the ARP "
                               f"table for {ip}")[:300], "hold": HOLD})
        else:
            items.append({"k": "same MAC", "v": "no other address"})
        if not accepted:
            items.append({"k": "accept", "v": f"{ACCEPT} (tty3)", "sev": "info"})
            status_sev = "info"
        summary = f"{kind} {id8}: router {state}"

    rows, rogue = [], 0
    for g in sorted(st.dhcp, key=lambda g: g["last"], reverse=True):
        what, sev = judge(g, s, st.since, st.dhcp_ok)
        k = (g["iface"], g["server"])
        last, n24 = st.dhcp_seen.get(k, (None, 0))
        if sev == "crit":
            rogue += 1
            if last is None or g["last"] > last:
                checks.append({
                    "key": f"dhcp_rogue:{g['iface'] or 'none'}:{g['server']}", "sev": "crit",
                    "title": f"LAN: DHCP server {g['server']} on {g['iface'] or '?'}: "
                             f"{'not this host' if what.endswith('bridge?') else 'not the router'}"
                             " (rogue DHCP?)",
                    "detail": (f"{g['n24']} answer(s) in 24 h ({', '.join(g['types'])}), "
                               f"{g['nh']} this hour. Fine (a Pi-hole, a second router): "
                               "[modules.lan] dhcp_ok in /etc/sectop/config.toml")[:300],
                    "n": max(1, g["n24"] - n24), "at": g["last"], "hold": HOLD})
        st.dhcp_seen[k] = (g["last"], g["n24"])
        rows.append({"cells": [f"{g['last']:.3f}", str(g["n24"]), str(g["nh"]),
                               g["iface"] or "?", g["server"], what], "sev": sev,
                     "id": f"{g['iface']}|{g['server']}",
                     "detail": [{"k": "types", "v": ", ".join(g["types"]) or "-"},
                                {"k": "first", "v": st.stamp(g["first"])},
                                {"k": "rule", "v": "uplink: the router only; VM bridge: this "
                                                   "host only; dhcp_ok in config"}]})
    live = {(g["iface"], g["server"]) for g in st.dhcp}
    st.dhcp_seen = {k: v for k, v in st.dhcp_seen.items() if k in live}
    items.append({"k": "DHCP 24 h", "v": f"{len(st.dhcp)} server(s), {rogue} rogue"
                  if not st.sum_note else "not watched (no ids summary)",
                  "sev": "crit" if rogue else ("info" if st.sum_note else "ok")})
    for n in notes:
        items.append({"k": "note", "v": n, "sev": "warn"})

    if checks:
        status = "crit"
    elif any(n for n in s.notes + [st.files_note]):
        status = "warn"
    elif status_sev == "info" or st.sum_note:
        status = "info"
    else:
        status = "ok"
    summary += f" | DHCP {len(st.dhcp)} server(s)" + (f", {rogue} ROGUE" if rogue else "")
    panels = [
        {"id": "lan", "title": "lan  this network: router, its MAC, DHCP", "type": "kv",
         "items": items},
        {"id": "dhcp", "title": f"dhcp  servers that answered, last 24 h: {len(rows)}",
         "type": "table", "columns": list(DHCP_COLUMNS), "types": list(DHCP_TYPES),
         "rows": rows},
    ]
    return {"v": 2, "status": status, "summary": summary, "panels": panels, "events": [],
            "checks": checks[:50]}
