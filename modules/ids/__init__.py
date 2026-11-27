"""ids: Suricata alerts on screen 1 (firewall). docs/modules/ids.md

Source: the summary of sectop-ids.service (core/idsd.py, /run/sectop-ids/summary.json,
0640 sectop-ids:sectop-feed): every alert line of Suricata's eve.json counted per rule
(sid) + source address, exact (no limit inside Suricata, eve.json as Suricata wrote it).
The collector never opens eve.json and is not in group suricata. Every field of the
summary is checked here (the writer is another, less trusted process).

Boxes:
- ids: the last 24 clock hours, one row per rule + source, worst first, then newest:
  last, 24 h count, this hour's count (since hh:00), rule (local / ET Open), the rule's
  own severity, its type (category / local kind), signature, from, to.
- eve: the newest alert lines (any age), newest first.
- ids key: what the colours mean and what the ET rule groups are.

Colour (decision 2026-11-27, Ghaith): the hardening's own rules by kind (leak, scan =
red; probe, vm_lan, vm_probe = yellow). ET Open: red = signature_severity Critical, or
priority 1 not marked low; white (info, row only, no alert) = marked Informational /
Minor AND not a dangerous type AND not priority 1; yellow = a dangerous type (malware,
C2, exploit, attack ...), priority 1 / 2 or Major; else white.

Alerts: one per rule + source, held an hour (hold 3600 s): new lines within the hour add
to its count, no new alert (decision 2026-11-27: one alert per rule + source per hour,
with the count). `at` = the newest line, so a summary read again opens nothing old.
"""

import ipaddress
import math
import os
import pwd
import re
import time

from core import statefile
from core.sanitize import clean

NAME = "ids"
INTERVAL = 2.0
SUMMARY = "/run/sectop-ids/summary.json"
OWNER = "sectop-ids"             # core/idsd.py OWNER
VERSION = 1
MAX_SIZE = 1 << 20
MAX_AGE = 120.0                  # the helper writes at least every 30 s
HOLD = 3600.0
MAX_GROUPS = 200
TAIL = 50
MAX_DSTS = 5
MAX_CHECKS = 50
MAX_N = 10 ** 9
CRIT_KINDS = ("leak", "scan")
LOCAL_SIDS = range(9200000, 9300000)      # hardening ids/local.rules
LOW = ("Informational", "Minor")
COLUMNS = ["last", "24 h", "hour", "rule", "sev", "type", "signature", "from", "to"]
TYPES = ["age", "num", "num", "text", "text", "text", "text", "text", "text"]
TAIL_COLUMNS = ["time", "rule", "type", "signature", "from", "to"]
TAIL_TYPES = ["age", "text", "text", "text", "text", "text"]
RANK = {"crit": 3, "warn": 2, "info": 1, "ok": 0}

KIND_TYPE = {"leak": "tunnel leak", "scan": "scan of this laptop",
             "probe": "probe of this laptop", "vm_lan": "VM to the LAN",
             "vm_probe": "VM probing the host"}
# a dangerous type, by the rule's category (classification) or its ET group
DANGER = re.compile(r"\b(trojan|malware|command and control|c2|cnc|exploit|privilege gain|"
                    r"executable code|attack|credential|targeted|coin ?min|mining|phishing|"
                    r"denial of service|shellcode|worm|compromised|ransom)", re.I)
ET_DANGER = {"MALWARE", "TROJAN", "CNC", "EXPLOIT", "EXPLOIT_KIT", "ATTACK_RESPONSE",
             "PHISHING", "MOBILE_MALWARE", "CURRENT_EVENTS", "WEB_CLIENT", "WEB_SERVER",
             "WEB_SPECIFIC_APPS", "SHELLCODE", "COINMINING", "WORM", "COMPROMISED", "DROP",
             "CINS", "DOS", "ADWARE_PUP", "PHISHING"}
ET_WHAT = {
    "DNS": "DNS lookups that look unusual (a name, a top-level domain); alone usually harmless",
    "INFO": "facts about traffic, not an attack by itself",
    "POLICY": "use of an app / service a strict policy may forbid, not an attack by itself",
    "HUNTING": "weak signs, worth a look with other alerts",
    "SCAN": "port / service scanning",
    "MALWARE": "traffic of known malware: danger",
    "CNC": "a known malware control server: danger",
    "EXPLOIT": "an attack on a known hole: danger",
    "ATTACK_RESPONSE": "a reply that looks like a successful attack: danger",
    "PHISHING": "a known phishing page: danger",
    "WEB_CLIENT": "an attack on a browser / client: danger",
    "DROP": "an address on a known bad list (Spamhaus DROP): danger",
    "CINS": "an address with a bad reputation (CINS): danger",
    "TOR": "Tor network traffic",
    "GAMES": "game traffic",
    "P2P": "peer-to-peer traffic",
    "USER_AGENTS": "an unusual program name in web traffic",
}

NOTE_NONE = "no ids summary (sectop-ids.service: Suricata installed? sudo ./install.sh)"


def et_group(sig: str) -> str:
    """'ET DNS Query ...' -> 'DNS'; '' for other rules."""
    p = sig.split()
    return p[1] if len(p) > 1 and p[0] in ("ET", "GPL") and re.fullmatch(r"[A-Z0-9_]{2,30}", p[1]) \
        else ""


def dangerous(category: str, sig: str) -> bool:
    return bool(DANGER.search(category)) or et_group(sig) in ET_DANGER


def rate(kind: str, severity: int | None, sigsev: list, category: str = "", sig: str = "") -> str:
    """Colour of a group (see the module doc)."""
    if kind:
        return "crit" if kind in CRIT_KINDS else "warn"
    low = any(s in LOW for s in sigsev)
    danger = dangerous(category, sig)
    if "Critical" in sigsev or (severity == 1 and not low):
        return "crit"
    if low and not danger and severity != 1:
        return "info"
    if danger or severity in (1, 2) or "Major" in sigsev:
        return "warn"
    return "info"


# --- the summary (core/idsd.py doc()) ---------------------------------------------------

def _text(d: dict, key: str, limit: int, where: str, empty: bool = True) -> str:
    v = d.get(key)
    if not isinstance(v, str) or len(v) > limit or (not v and not empty):
        raise ValueError(f"{where}.{key}: text of max {limit} required")
    return clean(v)


def _num(d: dict, key: str, where: str, lo: float = 0) -> float:
    v = d.get(key)
    if not isinstance(v, (int, float)) or isinstance(v, bool) or not math.isfinite(v) or v < lo:
        raise ValueError(f"{where}.{key}: number >= {lo} required")
    return float(v)


def _count(d: dict, key: str, where: str) -> int:
    v = d.get(key)
    if type(v) is not int or not 0 <= v <= MAX_N:
        raise ValueError(f"{where}.{key}: count required")
    return v


def _addr(d: dict, key: str, where: str) -> str:
    v = d.get(key)
    if v == "":
        return ""
    try:
        if isinstance(v, str):
            return str(ipaddress.ip_address(v))
    except ValueError:
        pass
    raise ValueError(f"{where}.{key}: IP address or empty required")


def _sev(d: dict, where: str) -> tuple:
    severity = d.get("severity")
    if severity is not None and (type(severity) is not int or not 1 <= severity <= 255):
        raise ValueError(f"{where}.severity: 1..255 or null required")
    sigsev = d.get("sigsev")
    if not isinstance(sigsev, list) or len(sigsev) > 3 or not all(
            isinstance(s, str) and len(s) <= 20 for s in sigsev):
        raise ValueError(f"{where}.sigsev: max 3 texts required")
    return severity, [clean(s) for s in sigsev]


def _rule(d: dict, where: str) -> dict:
    sid = d.get("sid")
    if type(sid) is not int or not 1 <= sid < 2 ** 32:
        raise ValueError(f"{where}.sid: rule id required")
    severity, sigsev = _sev(d, where)
    kind = _text(d, "kind", 20, where)
    if kind and not re.fullmatch(r"[a-z_]{1,20}", kind):
        raise ValueError(f"{where}.kind: [a-z_] required")
    return {"sid": sid, "sig": _text(d, "sig", 200, where) or f"sid {sid}", "kind": kind,
            "severity": severity, "sigsev": sigsev, "category": _text(d, "category", 100, where),
            "src": _addr(d, "src", where)}


def check_group(d, where: str) -> dict:
    if not isinstance(d, dict):
        raise ValueError(f"{where}: object required")
    g = _rule(d, where)
    dsts = d.get("dsts")
    if not isinstance(dsts, list) or len(dsts) > MAX_DSTS or not all(
            isinstance(x, str) and len(x) <= 60 for x in dsts):
        raise ValueError(f"{where}.dsts: max {MAX_DSTS} texts required")
    g.update(target=_text(d, "target", 40, where), confidence=_text(d, "confidence", 20, where),
             proto=_text(d, "proto", 10, where), app=_text(d, "app", 20, where),
             first=_num(d, "first", where), last=_num(d, "last", where),
             n24=_count(d, "n24", where), nh=_count(d, "nh", where),
             dsts=[clean(x) for x in dsts])
    g["sev"] = rate(g["kind"], g["severity"], g["sigsev"], g["category"], g["sig"])
    return g


def check_tail(d, where: str) -> dict:
    if not isinstance(d, dict):
        raise ValueError(f"{where}: object required")
    a = _rule(d, where)
    dport = d.get("dport")
    if dport is not None and (type(dport) is not int or not 0 <= dport <= 65535):
        raise ValueError(f"{where}.dport: port or null required")
    a.update(ts=_num(d, "ts", where), dst=_addr(d, "dst", where), dport=dport,
             proto=_text(d, "proto", 10, where))
    a["sev"] = rate(a["kind"], a["severity"], a["sigsev"], a["category"], a["sig"])
    return a


def check_summary(d) -> dict:
    """summary.json -> checked dict. Wrong -> ValueError."""
    if not isinstance(d, dict) or type(d.get("v")) is not int or d["v"] != VERSION:
        raise ValueError(f"v: {VERSION} required")
    out = {"ts": _num(d, "ts", "summary"), "note": _text(d, "note", 200, "summary"),
           "skipped": _count(d, "skipped", "summary"), "dropped": _count(d, "dropped", "summary")}
    other = d.get("other")
    if not isinstance(other, dict) or len(other) > 20 or not all(
            isinstance(k, str) and re.fullmatch(r"[a-z0-9_?]{1,40}", k) and type(v) is int
            and 0 <= v <= MAX_N for k, v in other.items()):
        raise ValueError("other: {event type: count} required")
    out["other"] = dict(other)
    groups, tail = d.get("groups"), d.get("tail")
    if not isinstance(groups, list) or len(groups) > MAX_GROUPS:
        raise ValueError(f"groups: list of max {MAX_GROUPS} required")
    if not isinstance(tail, list) or len(tail) > TAIL:
        raise ValueError(f"tail: list of max {TAIL} required")
    out["groups"] = [check_group(g, f"groups[{i}]") for i, g in enumerate(groups)]
    out["tail"] = [check_tail(a, f"tail[{i}]") for i, a in enumerate(tail)]
    return out


# --- module -----------------------------------------------------------------------------

class State:
    def __init__(self, path=SUMMARY, wall=time.time, owner=None,
                 stamp=lambda ts: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))):
        self.path, self.wall, self.owner, self.stamp = path, wall, owner, stamp
        self.seen = {}              # group key -> (newest line, 24 h count) last collect
        self.mtime = None           # summary file read last
        self.data = None            # its checked content
        self.error = ""


def init(cfg: dict) -> State:
    cfg = dict(cfg)
    path = cfg.pop("path", SUMMARY)
    if cfg:
        raise ValueError(f"unknown option(s): {', '.join(sorted(cfg))}")
    if not isinstance(path, str) or not os.path.isabs(path):
        raise ValueError("path: absolute path required")
    return State(path=path)


def close(st: State) -> None:
    pass


def _owner(st: State) -> int:
    if st.owner is not None:
        return st.owner
    try:
        return pwd.getpwnam(OWNER).pw_uid
    except KeyError:
        raise ValueError(f"no user {OWNER} (sectop install.sh makes it)") from None


def load(st: State) -> None:
    """The summary, read again only when it changed. Sets st.data / st.error."""
    try:
        m = os.stat(st.path).st_mtime_ns
    except FileNotFoundError:
        st.data, st.mtime, st.error = None, None, NOTE_NONE
        return
    except OSError as e:
        st.data, st.mtime, st.error = None, None, f"{st.path}: {e.strerror}"
        return
    if m == st.mtime and st.data is not None:
        return
    try:
        d = statefile.load(st.path, _owner(st), MAX_SIZE)
        if d is None:
            st.data, st.error = None, NOTE_NONE
        else:
            st.data, st.error = check_summary(d), ""
        st.mtime = m
    except (statefile.StateError, ValueError) as e:
        st.data, st.mtime, st.error = None, None, f"ids summary: {e}"[:200]


def _rule_name(sid: int) -> str:
    return "local" if sid in LOCAL_SIDS else "ET Open"


def _rule_sev(g: dict) -> str:
    p = f"p{g['severity']}" if g["severity"] is not None else ""
    return " ".join(x for x in (", ".join(g["sigsev"]), p) if x) or "-"


def _type(g: dict) -> str:
    if g["kind"]:
        return KIND_TYPE.get(g["kind"], g["kind"])
    return g["category"] or "-"


def _to(dst: str, dport) -> str:
    return dst + (f":{dport}" if dport is not None else "") if dst else "-"


def age_text(s: float) -> str:
    s = max(0, int(s))
    for unit, n in (("d", 86400), ("h", 3600), ("min", 60)):
        if s >= n:
            return f"{s // n} {unit}"
    return f"{s} s"


def _row(st: State, g: dict) -> dict:
    to = g["dsts"][0] if g["dsts"] else "-"
    if len(g["dsts"]) > 1:
        to += f" +{len(g['dsts']) - 1}"
    grp_ = et_group(g["sig"])
    detail = [("signature", g["sig"]), ("sid", str(g["sid"])),
              ("rule", "local rule (hardening ids/local.rules)" if g["sid"] in LOCAL_SIDS
               else "ET Open")]
    if grp_:
        detail.append(("ET group", f"{grp_}: {ET_WHAT.get(grp_, 'see the ids key box')}"))
    detail.append(("type", _type(g)))
    if g["kind"]:
        detail.append(("kind", g["kind"]))
    detail.append(("rule severity", _rule_sev(g)))
    detail.append(("colour", {"crit": "red: act now", "warn": "yellow: look at it",
                              "info": "white: info, no alert"}[g["sev"]]))
    if g["target"]:
        detail.append(("target", g["target"]))
    if g["confidence"]:
        detail.append(("confidence", g["confidence"]))
    detail += [("from", g["src"] or "-"), ("to", ", ".join(g["dsts"]) or "-"),
               ("proto", g["proto"] + (f" / {g['app']}" if g["app"] and g["app"] != "failed"
                                       else "") or "-"),
               ("24 h", str(g["n24"])), ("this hour", str(g["nh"])),
               ("first", st.stamp(g["first"])), ("last", st.stamp(g["last"]))]
    row = {"cells": [f"{g['last']:.3f}", str(g["n24"]), str(g["nh"]), _rule_name(g["sid"]),
                     _rule_sev(g), _type(g), g["sig"], g["src"] or "-", to],
           "sev": g["sev"], "id": f"{g['sid']}:{g['src']}",
           "detail": [{"k": k, "v": v} for k, v in detail]}
    if g["src"]:
        row["ip"] = g["src"]
        row["filter"] = g["src"]
    return row


def _tail_row(a: dict) -> dict:
    row = {"cells": [f"{a['ts']:.3f}", _rule_name(a["sid"]), _type(a), a["sig"],
                     a["src"] or "-", _to(a["dst"], a["dport"])],
           "sev": a["sev"], "detail": [{"k": "sid", "v": str(a["sid"])},
                                       {"k": "rule severity", "v": _rule_sev(a)},
                                       {"k": "proto", "v": a["proto"] or "-"}]}
    if a["src"]:
        row["ip"] = a["src"]
    return row


def _check(g: dict, n: int) -> dict:
    to = g["dsts"][0] if g["dsts"] else "-"
    return {"key": f"ids:{g['sid']}:{g['src'] or 'none'}", "sev": g["sev"],
            "title": f"IDS {g['sig']} from {g['src'] or '?'}"[:160],
            "detail": (f"sid {g['sid']} ({_rule_name(g['sid'])}), {_type(g)}, to {to}, "
                       f"{g['nh']} this hour, {g['n24']} in 24 h")[:300],
            "n": n, "at": g["last"], "hold": HOLD}


KEY_ITEMS = [   # short values: the box is narrow (each <= 50 chars)
    {"k": "red", "v": "act now: leak, scan of this laptop, ET Critical/p1", "sev": "crit"},
    {"k": "yellow", "v": "look at it: probe / VM rules, ET Major/p2, danger", "sev": "warn"},
    {"k": "white", "v": "info, no alert: ET Informational/Minor, no danger", "sev": "info"},
    {"k": "danger", "v": "malware trojan C2/CNC exploit attack phishing DROP"},
    {"k": "24 h", "v": "every line of the last 24 clock hours (exact)"},
    {"k": "hour", "v": "every line since hh:00"},
    {"k": "alert", "v": "one per rule + source an hour, its count grows"},
    {"k": "sev", "v": "the rule's own: ET word + priority p1 high..p4 low"},
    {"k": "ET low", "v": "DNS / INFO / POLICY: unusual, usually harmless"},
    {"k": "ET scan", "v": "SCAN: port / service scanning"},
    {"k": "ET danger", "v": "MALWARE / CNC / EXPLOIT / DROP / CINS: danger"},
]

def collect(st: State, ctx) -> dict:
    now = st.wall()
    load(st)
    d = st.data
    checks = []
    if d is None:
        groups, tail, note = [], [], st.error
    else:
        groups = sorted(d["groups"], key=lambda g: (RANK[g["sev"]], g["last"]), reverse=True)
        tail, note = d["tail"], d["note"]
        age = now - d["ts"]
        if age > MAX_AGE:
            note = f"ids summary {int(age)} s old (sectop-ids.service stuck?)"
            checks.append({"key": "ids:stale", "sev": "warn", "title": "IDS summary not updated",
                           "detail": note})
    for g in groups:
        key = f"{g['sid']}:{g['src']}"
        last, n24 = st.seen.get(key, (None, 0))
        if g["sev"] in ("crit", "warn") and (last is None or g["last"] > last) \
                and len(checks) < MAX_CHECKS:
            # n = the new lines: the alert's count grows by them (core/alerts.py)
            checks.append(_check(g, max(1, g["n24"] - n24)))
        st.seen[key] = (g["last"], g["n24"])
    live = {f"{g['sid']}:{g['src']}" for g in groups}
    st.seen = {k: v for k, v in st.seen.items() if k in live}
    count = {"crit": 0, "warn": 0, "info": 0}
    for g in groups:
        count[g["sev"]] += g["n24"]
    total = sum(count.values())
    title = (f"ids  alerts last 24 h, per rule + source: {total} in {len(groups)} group(s)")
    if note:
        title += f"  ({note})"
    oldest = f", oldest {age_text(now - tail[-1]['ts'])} ago" if tail else ""
    panels = [
        {"id": "ids", "title": title, "type": "table", "columns": list(COLUMNS),
         "types": list(TYPES), "rows": [_row(st, g) for g in groups], "width": "full"},
        {"id": "eve", "title": f"eve  last {len(tail)} alert lines (any age{oldest})",
         "type": "table", "columns": list(TAIL_COLUMNS), "types": list(TAIL_TYPES),
         "rows": [_tail_row(a) for a in tail]},
        {"id": "ids_key", "title": "ids key  colours, counts, rule types", "type": "kv",
         "items": [dict(it) for it in KEY_ITEMS]},
    ]
    if note:
        summary = note
    else:
        summary = f"24 h: crit {count['crit']} | warn {count['warn']} | info {count['info']}"
        if d["other"]:
            summary += " | " + ", ".join(f"{k} {v}" for k, v in sorted(d["other"].items()))
    denied = d is not None and d["note"].startswith("eve.json not readable")
    if denied:
        checks.append({"key": "ids:no_access", "sev": "warn", "title": "IDS alerts not readable",
                       "detail": d["note"]})
    if denied or any(c["key"] == "ids:stale" for c in checks):
        status = "warn"
    elif note:
        status = "info"
    else:
        status = "ok"
    return {"v": 2, "status": status, "summary": summary, "panels": panels, "events": [],
            "checks": checks}
