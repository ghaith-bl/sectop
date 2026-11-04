"""Counter card: every logged line of one hostfw rule this boot, as flows and packets.

Opened by enter on a hostfw counter row (row `logs` = the rule, docs/module-interface.md,
Rows). Runs in the UI process (my user, journal readable: group wheel / systemd-journal),
only when the card opens, never on a tick (2026-11-04: read on open, no load while closed).
One fixed `journalctl` argv per rule: the grep pattern comes from the rule name, which
must match RULE_RE (no typed text reaches the command).

Three levels:
  flows    one row per flow (proto, src, dst, iface, uid; the ephemeral port left out,
           journal.flow()), count, first, last
  packets  every logged line of one flow, oldest first, with its own ports and flags
  fields   every field of one line (enter on a packet), the main ones in the value color

Counted vs logged: the counter is exact (since the hostfw table load), lines are what
hostfw logged (rate-limited, this boot). The card head says both.
Pure except load() (one command).
"""

import re
import time

from core.run import run as _run
from modules import firewall as fw
from modules.firewall import journal

RULE_RE = re.compile(r"[a-z][a-z0-9_]{0,39}")
JOURNALCTL = "/usr/bin/journalctl"
MAX_LINES = 3000              # newest lines read per card
TIMEOUT = 5.0
OUT_LIMIT = 4 * 1024 * 1024   # bytes: MAX_LINES json lines with MESSAGE only fit

FLOW_COLUMNS = ["last", "first", "n", "proto", "src", "dst", "iface", "uid"]
FLOW_TYPES = ["age", "age", "num", "text", "text", "text", "text", "text"]
FLOW_ROLES = ["note", "note", "value", "text", "name", "value", "text", "text"]
PACKET_COLUMNS = ["time", "proto", "src", "dst", "flags", "len", "ttl", "iface"]
PACKET_TYPES = ["text", "text", "text", "text", "text", "num", "num", "text"]
PACKET_ROLES = ["note", "text", "name", "value", "high", "text", "text", "text"]

ICMP4 = {"0": "echo reply", "3": "unreachable", "5": "redirect", "8": "echo",
         "11": "time exceeded"}
ICMP6 = {"1": "unreachable", "2": "too big", "3": "time exceeded", "128": "echo",
         "129": "echo reply", "133": "router solicit", "134": "router advert",
         "135": "neighbor solicit", "136": "neighbor advert", "143": "mld2 report"}
# kernel field -> label in the fields view; MAIN fields in the value color
LABELS = {
    "IN": "in iface", "OUT": "out iface", "PHYSIN": "bridge port in",
    "PHYSOUT": "bridge port out", "MAC": "mac (dst:src:type)", "SRC": "source",
    "DST": "destination", "LEN": "length", "TOS": "tos", "PREC": "precedence",
    "TTL": "ttl", "ID": "ip id", "PROTO": "protocol", "SPT": "source port",
    "DPT": "dest port", "WINDOW": "tcp window", "RES": "reserved bits", "URGP": "urgent ptr",
    "TYPE": "icmp type", "CODE": "icmp code", "SEQ": "icmp seq", "MTU": "mtu",
    "UID": "uid", "GID": "gid", "MARK": "mark", "TC": "traffic class",
    "HOPLIMIT": "hop limit", "FLOWLBL": "flow label",
}
MAIN = {"IN", "OUT", "SRC", "DST", "SPT", "DPT", "PROTO", "TYPE", "UID"}
TCP_FLAGS = ("SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR")


def code(rule: str) -> str:
    """fwd_vm_lan -> HFW-FWD-VM-LAN (the log prefix of the counter)."""
    return "HFW-" + rule.upper().replace("_", "-")


def argv(rule: str) -> list:
    if not RULE_RE.fullmatch(rule):
        raise ValueError(f"bad rule name: {rule!r}")
    return [JOURNALCTL, "-b", "0", "_TRANSPORT=kernel", "-o", "json",
            "--output-fields=MESSAGE", "-q", "--no-pager",
            f"--grep=^{code(rule)}: ", "-n", str(MAX_LINES)]


def load(rule: str, run=_run) -> tuple:
    """-> (entries of this rule, oldest first; note: why lines may be missing, or '')."""
    res = run(argv(rule), timeout=TIMEOUT, limit=OUT_LIMIT)
    cut = res.timed_out or res.truncated
    if res.rc != 0 and not cut and (res.out.strip() or res.err.strip()):
        first = (res.err.strip() or res.out.strip()).splitlines()[0]
        return [], f"journalctl failed (rc {res.rc}): {first[:200]}"
    entries, _cursor, bad = journal.parse(res.out)
    # oldest first by time: with --grep, -n hands the lines back newest first (host
    # 2026-11-04: flows showed first newer than last). Stable: same second keeps order
    entries = sorted((e for e in entries if e.kind == rule), key=lambda e: e.ts)
    notes = []
    if cut:
        notes.append("read cut (timeout / size): the newest lines may be missing")
    if len(entries) >= MAX_LINES:
        notes.append(f"newest {MAX_LINES} lines only")
    if bad:
        notes.append(f"{bad} unreadable journal line{'s' if bad != 1 else ''} skipped")
    return entries, "; ".join(notes)


def proto(e) -> str:
    """tcp, udp, icmp 8 echo, icmpv6 135 neighbor solicit."""
    f = e.fields
    p = f.get("PROTO", "-").lower()
    t = f.get("TYPE")
    if t is None or p not in ("icmp", "icmpv6"):
        return p
    name = (ICMP4 if p == "icmp" else ICMP6).get(t, "")
    return f"{p} {t} {name}".rstrip()


def iface(e) -> str:
    f = e.fields
    i, o = f.get("IN") or "", f.get("OUT") or ""
    if i and o:
        return f"{i}>{o}"
    return i or o or "-"


def uid(e) -> str:
    if e.kind.startswith("fwd_vm"):
        return "vm"
    return e.fields.get("UID") or "-"


def flow_key(e) -> tuple:
    src, dst, _side, _port = journal.flow(e)
    return (proto(e), src, dst, iface(e), uid(e))


def group(entries) -> list:
    """-> [(key, [entries oldest first])], newest last line first."""
    flows = {}
    for e in entries:
        flows.setdefault(flow_key(e), []).append(e)
    return sorted(flows.items(), key=lambda kv: kv[1][-1].ts, reverse=True)


def flow_id(key: tuple) -> str:
    return "|".join(key)


def _flags(e) -> str:
    return " ".join(x for x in e.flags if x in TCP_FLAGS) or "-"


def _remote(e) -> str | None:
    """The other side of the line, for w (whois): dst going out, src coming in."""
    a = e.fields.get("SRC" if e.dir == "in" else "DST")
    try:
        return journal._addr(a) if a else None
    except ValueError:
        return None


def _hms(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))


def _stamp(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def flows_panel(entries, sev: str = "ok", tone: str = "plain", stamp=_stamp) -> dict:
    rows = []
    for key, es in group(entries):
        last, first = es[-1], es[0]
        src_ports = sorted({e.fields["SPT"] for e in es if e.fields.get("SPT")},
                           key=lambda p: (len(p), p))
        detail = [{"k": "lines", "v": str(len(es))},
                  {"k": "first", "v": stamp(first.ts)}, {"k": "last", "v": stamp(last.ts)}]
        if src_ports:
            shown = " ".join(src_ports[:20]) + (" ..." if len(src_ports) > 20 else "")
            detail.append({"k": "source ports", "v": shown})
        row = {"cells": [repr(last.ts), repr(first.ts), str(len(es)), *key],
               "sev": sev, "tone": tone, "id": flow_id(key), "detail": detail}
        ip = _remote(last)
        if ip:
            row["ip"] = ip
        rows.append(row)
    return {"id": "logflows", "title": "", "type": "table", "sev": "ok",
            "columns": list(FLOW_COLUMNS), "types": list(FLOW_TYPES),
            "roles": list(FLOW_ROLES), "rows": rows}


def packet_fields(e, rule_line: str, verdict_line: str, sev: str, stamp=_stamp) -> list:
    """Every field of one line: main ones (addresses, ports, proto, ifaces, uid) in the
    value color, the verdict in the rule's severity color."""
    hot = sev if sev in ("info", "warn", "crit") else "value"
    out = [{"k": "rule", "v": rule_line, "style": "name"},
           {"k": "verdict", "v": verdict_line, "style": hot},
           {"k": "time", "v": stamp(e.ts), "style": "text"},
           {"k": "", "v": ""}]
    for k, v in e.fields.items():
        if v == "":
            continue
        label = LABELS.get(k, k.lower())
        out.append({"k": f"{label} ({k})", "v": v, "style": "value" if k in MAIN else "text"})
    if e.flags:
        out.append({"k": "flags", "v": " ".join(e.flags), "style": "high"})
    return out


def packets_panel(entries, rule_line: str, verdict_line: str, sev: str = "ok",
                  tone: str = "plain", hms=_hms, stamp=_stamp) -> dict:
    rows = []
    for i, e in enumerate(entries):
        f = e.fields
        row = {"cells": [hms(e.ts), proto(e), journal.src(e), journal.dst(e), _flags(e),
                         f.get("LEN", "-"), f.get("TTL") or f.get("HOPLIMIT") or "-",
                         iface(e)],
               "sev": sev, "tone": tone, "id": f"{e.cursor or i}",
               "detail": packet_fields(e, rule_line, verdict_line, sev, stamp)}
        ip = _remote(e)
        if ip:
            row["ip"] = ip
        rows.append(row)
    return {"id": "logpkts", "title": "", "type": "table", "sev": "ok",
            "columns": list(PACKET_COLUMNS), "types": list(PACKET_TYPES),
            "roles": list(PACKET_ROLES), "rows": rows, "detail_only": True}


def colors(rule: str, verdict: str) -> tuple:
    """(sev, tone) of the rule's rows, as on the counter row: a blocked kind in its
    severity, the verdict as tone (allow blue, block yellow); noise (in_noise) dim.
    out_leak: warn when blocked (fw.leak_sev)."""
    sev = fw.kind_sev(rule) or "ok"
    if rule == "out_leak":
        sev = fw.leak_sev(None, verdict)
    if rule in fw.SEV and fw.SEV[rule] is None:
        return sev, "dim"
    return sev, fw._tone(verdict)


def _int(text: str) -> int | None:
    return int(text) if text.isdigit() else None


def head(rule: str, info: dict, lines: int, note: str, sev: str) -> list:
    """Lines above the flows table: counted vs logged, verdict, match, read problems."""
    counted = info.get("pkts", "?")
    out = [(f"{code(rule)}   counted {counted} packets (since the hostfw table load)   "
            f"logged {lines} lines (this boot)", "text")]
    c = _int(counted)
    log = info.get("log", "")
    if c is not None and c > lines:
        out.append((f"{c - lines} packets counted, not logged: {log}", "note"))
    elif c is not None and c < lines:
        out.append(("more lines than packets: the table was reloaded this boot "
                    "(the counter restarted, the lines stay)", "note"))
    elif c is not None:
        out.append(("every counted packet has its line", "note"))
    hot = sev if sev in ("info", "warn", "crit") else "value"
    out.append((f"verdict  {info.get('verdict', '-')}", hot))
    if info.get("meaning"):
        out.append((f"meaning  {info['meaning']}", "text"))
    if info.get("match"):
        out.append((f"match    {info['match']}", "note"))
    if note:
        out.append((note, "warn"))
    if lines == 0 and not note.startswith("journalctl failed"):
        out.append(("no lines this boot", "note"))
    return out


def card(rule: str, info: dict, run=_run, hms=_hms, stamp=_stamp) -> dict:
    """Everything the card shows, built once when it opens (core/logs.py).
    info: the counter row (pkts cell, its detail: verdict, meaning, match, log)."""
    entries, note = load(rule, run)
    verdict = (info.get("verdict") or "-").split()[0]
    sev, tone = colors(rule, verdict)
    rule_line = f"{code(rule)}  {info.get('meaning', '')}".rstrip()
    verdict_line = info.get("verdict", "-")
    packets, names = {}, {}
    for key, es in group(entries):
        fid = flow_id(key)
        packets[fid] = packets_panel(es, rule_line, verdict_line, sev, tone, hms, stamp)
        p, src, dst, ifc, who = key
        names[fid] = f"{p} {src} -> {dst}  {ifc}  uid {who}"
        packets[fid]["head"] = [
            (f"flow  {names[fid]}", "value"),
            (f"{len(es)} line{'s' if len(es) != 1 else ''}, first {stamp(es[0].ts)}, "
             f"last {stamp(es[-1].ts)}   (oldest first)", "note")]
    flows = flows_panel(entries, sev, tone, stamp)
    flows["head"] = head(rule, info, len(entries), note, sev)
    return {"rule": rule, "code": code(rule), "lines": len(entries), "flows": flows,
            "packets": packets, "names": names}
