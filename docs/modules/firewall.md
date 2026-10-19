# firewall module

hostfw + Proton WireGuard status. `modules/firewall/`.
Parsers (`nft.py`, `journal.py`, `conns.py`, `vpn.py`) are pure. `__init__.py` runs
commands, applies rules, builds the Snapshot.

## Sources

All via `core.run.run()`, timeout 1.0 s each, binaries from `/usr/bin` (fallback `/usr/sbin`).

| what | argv |
|---|---|
| counters | `nft -j list counters table inet hostfw` |
| live mode | `nft -j list chain inet hostfw enforce` |
| fwmark set | `nft -j list set inet hostfw wg_fwmark` |
| log lines | `journalctl _TRANSPORT=kernel -o json --output-fields=MESSAGE -q --no-pager --after-cursor=<c>` |
| tunnel | `wg show proton0 latest-handshakes`, `transfer`, `endpoints`, `fwmark` |
| routes | `ip -j -4 route show default`, `ip -j -6 route show default` |
| connections | `ss -tunapH state established` |

Files (root-owned, not g/o writable, `O_NOFOLLOW`, max 4 KiB):
`/etc/hostfw/mode` (boot mode), `/run/hostfw/rollback` (rollback deadline, see below).

- No `wg show ... dump`: first line is the private key. Per-field subcommands never print it.
- No `journalctl -g`: HFW lines are filtered in `journal.py`, so the cursor moves past
  every kernel entry. With `-g` a poll with no match returns no cursor and the next poll
  scans the same entries again.
- Journal start: `init()` takes the cursor of the newest kernel entry (`-n 1`), so old
  lines are not replayed. No entry -> `--since=@<start time>`.
- Output cut (timeout / 1 MiB): only complete lines used, cursor = last complete entry,
  next tick continues from there. Shown as `journal: behind`.
- MESSAGE as byte array (non-UTF-8 / control chars) decoded with `errors="replace"`.
  Null MESSAGE (too large) skipped, cursor still moves.

## Severity

Log kind = counter name: `HFW-OUT-LEAK` -> `out_leak`, `HFW-FWD-VM-LAN` -> `fwd_vm_lan`
(name part may have dashes). Old prefix `HFW-FWD-KS` (hostfw before 2026-10-19) -> `fwd_vm_ks`.

| sev | kinds |
|---|---|
| crit | out_leak |
| warn | out_dns, in_lan, in_vpn, fwd_vm_lan, fwd_in |
| info | out_ks, out_disco, out_share, out_lan, fwd_vm_ks, unknown kinds |
| hidden | in_noise (counter only, no event, no audit row) |
| ok | out_dns_vpn, out_wg, out_probe, out_router_admin, out_lan_allow, out_new, fwd_vm_new (allowed) |

- Status comes from counter deltas, not totals: totals since boot include the
  pre-connect window. First tick never alarms.
- New packets keep their kind's severity in status for `hold` s (default 60).
- Counter lower than last tick (table reloaded) -> its new value counts as new.

Checks:

| check | sev |
|---|---|
| table missing / nft error | crit |
| fwmark live not in `wg_fwmark` set (tunnel up) | crit |
| handshake > 180 s while tx grows | crit |
| handshake > 180 s, idle | ok (shown "idle") |
| handshake never, tx grows / idle | warn / info |
| mode observe / unknown | warn |
| tunnel down | warn |
| lowest-metric default route not kill switch or tunnel | warn |
| journal / ss / ip error, parse error, mode file unreadable | warn |
| rollback armed (deadline in the future) | info |

Handshake: WireGuard does not handshake on an idle tunnel, so age alone is not a
failure. Keys are rejected after 180 s, so age > 180 s with traffic going out = broken.

## Panels

hostfw (kv), vpn (kv), hostfw counters (table: pkts, new this tick, bytes; zero counters
hidden, count in the title), blocked / tick (spark, deny kinds except hidden),
out_leak / tick (spark), audit (table, see below), connections (table, max 50).

Screen: firewall (`core/screens.py`), no events box: the audit box shows the same lines.

## Audit

One row per HFW log line, newest first, last 200 kept (in state). Hidden kinds (in_noise)
skipped. Row severity = kind severity, allowed = ok.
out_new / fwd_vm_new (every new flow) go to the audit box only, not to events.

| column | value |
|---|---|
| time | local HH:MM:SS of the journal entry |
| dir | out, in, fwd (from the prefix) |
| verdict | allow (allowed kinds), drop (out_ks, fwd_vm_ks), zone (in_*: hostfw logs, firewalld zone decides), block / pass (deny kinds, live mode enforce / observe) |
| proto | PROTO, lower case |
| uid | UID (OUT rules with `skuid`), else `-` |
| prog | out: process from `ss` with the same proto + src + dst (open flows only), else `?`; fwd_vm_*: `vm`; in: `-` |
| src, dst | address:port, IPv6 compressed (`[v6]:port`) |
| iface | out: OUT, in: IN, fwd: IN>OUT |

- Row detail (`enter`): rule (kind + hostfw counter comment), verdict meaning, full local
  time, log prefix, every non-empty log field in log order (IN, OUT, MAC, SRC, DST, LEN, TTL,
  PROTO, ports, UID ...), flags (DF, SYN ...).
- Blocked lines are samples (hostfw rate limit 10/min per rule), allowed new flows
  5/s burst 50. Counters stay exact.
- Program for blocked flows: mostly `?` (rejected connect closes before the next poll).
  Planned: Linux audit `connect` records (docs/architecture.md).
- Verdict uses the mode at collect time: lines logged just before a mode switch may show the new mode.

Summary: `enforce | proton0 up | hs 20s | leak 4`, plus first 3 warn / crit checks.

## Options

```toml
[modules.firewall]
tunnel = "proton0"
ks_ifaces = ["pvpnksintrf0", "pvpnksintrf1"]
hold = 60
```

Interface names `[A-Za-z0-9_.-]{1,15}`. Unknown option -> init error, module disabled.

## Rollback file

`/run/hostfw/rollback`, written by hostfw.sh `rollback_arm`, removed by `rollback_clear`:
line 1 deadline (epoch seconds), line 2 rollback command.
Shown as `armed, 2m 05s left -> <command>`. Other content -> `armed`.

The file stays after the timer fired (removed only by confirm / observe / apply / remove,
or reboot: `/run`). Deadline in the past -> `deadline passed 3m ago -> <command>`,
not armed, no check. `hostfw status` asks systemd for the timer, so it is always right.

## Fixtures

`tests/fixtures/firewall/` from my host, 2026-10-19, enforce mode, tunnel up.

- Public IPs replaced with RFC 5737 ranges, peer key with a dummy, TV MAC and
  link-local with dummies. LAN 192.168.8.0/24 and CGNAT 100.85.0.1 kept.
- journal.json: real OUT-KS / IN-NOISE lines, 3 fields kept, cursors rewritten.
  OUT-LEAK, OUT-DNS, IN-VPN and the non-HFW line are synthetic (format from real logs).
- nft-observe.json: nft-enforce.json without the reject rule.
- journal-audit.json: synthetic, one line per kind (format from hostfw.nft log rules),
  OUT-NEW tcp line = brave flow in ss.txt.
