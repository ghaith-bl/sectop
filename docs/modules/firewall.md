# firewall module

hostfw + Proton WireGuard status. `modules/firewall/`.
Parsers (`nft.py`, `journal.py`, `conns.py`, `vpn.py`) are pure. `__init__.py` runs
commands, applies rules, builds the Snapshot.

## Sources

Binaries from `/usr/bin` (fallback `/usr/sbin`), timeout 1.0 s each. nft and wg need
CAP_NET_ADMIN even to read: the net unit (`core/netd.py`, sectop-net.service) runs them and
writes each result to `/run/sectop-net/<name>.json`; the module reads the last one
(`netd.Reader`, same Result as `core.run.run()`). Missing, unsafe, other command or older
than 30 s (slow ones 90 s) -> a failed result that says why, shown like any command
error. The rest runs in the collector via `core.run.run()` as user sectop.

Every tick (4 commands):

| what | argv |
|---|---|
| counters + live mode | `nft -j -t list table inet hostfw` |
| tunnel | `wg show proton0 latest-handshakes`, `transfer` |
| open sockets (peers, prog) | `ss -tunaH --cgroup state established` |

Log lines: core's journal follower (`core/journal.py`, docs/module-interface.md,
Journal). `JOURNAL = {"groups": [["_TRANSPORT=kernel"]], "fields": ["MESSAGE"]}`: every
kernel entry since the last collect in `ctx.journal`, HFW lines picked in `journal.py`.

Slow (every 30 s, and at once when the tunnel goes up / down):

| what | argv |
|---|---|
| endpoint, live fwmark | `wg show proton0 endpoints`, `fwmark` (tunnel up only) |
| fwmark set | `nft -j list set inet hostfw wg_fwmark` |
| routes | `ip -j -4 route show default`, `ip -j -6 route show default` |

- Why few: sectop v1 ran as root from my login, so every command was an audit record
  (rule `root_cmds`, ~7 journal entries each). Was 11 commands per tick. See
  docs/architecture.md, Privilege split.
- Net unit timing: fast (table, handshakes, transfer) every half module interval, slow
  (endpoints, fwmark, fwmark set) every 15 s: each tick reads a fresh sample. Counters are
  cumulative: a sample read twice gives delta 0 now and the full delta next tick.
- `-t` (nft(8): "Omit contents of sets"): counters and the enforce chain without the
  set elements (Proton entry IPs: thousands). wg_fwmark elements come from the slow set call.
- Mode from the table: only rules of chain `enforce` count; no chain `enforce` = unknown.
- Slow items and their checks are kept and shown every tick until the next slow run.
  A changed endpoint, fwmark or default route shows within 30 s (a reconnect at once).

Once in `init()` (boot scan, timeout 5 s each, see out_leak box):

| what | argv |
|---|---|
| first tunnel flow | `journalctl -b 0 _TRANSPORT=kernel -o json --output-fields=MESSAGE -q --no-pager --grep=^HFW-OUT-NEW: -n +1` |
| leak lines | `journalctl -b 0 _TRANSPORT=kernel -o json --output-fields=MESSAGE -q --no-pager --grep=^HFW-OUT-LEAK:` |

Files (root-owned, not g/o writable, `O_NOFOLLOW`, max 4 KiB):
`/etc/hostfw/mode` (boot mode), `/run/hostfw/rollback` (rollback deadline, see below).
`/proc/uptime`: boot time for the leak context.

- No `wg show ... dump`: first line is the private key. Per-field subcommands never print it.
- Live lines: every kernel entry (no `-g`), HFW lines picked in `journal.py`. The boot
  scan runs once in `init()`, so it uses `-g`. `-n +1` = oldest match. rc 1 with no
  output = no match.
- The follower starts at collector start (`--since`), before `init()`: a leak line seen
  by the boot scan and again live is skipped (boot scan cursors).
- `log reader` item: `ok`; the follower's note (dropped, bad lines, restarted) and
  `N bad entries` (no time / cursor) -> info; follower down -> warn + check `log_reader`
  "log reader down" (detail: why, restart in N s). Entries read before it went down are
  still used.
- MESSAGE as byte array (non-UTF-8 / control chars) decoded with `errors="replace"`.
  Null MESSAGE (too large) skipped.

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

- Alerts come from counter deltas, not totals: totals since boot include the
  pre-connect window. First tick never alarms.
- New packets of a deny kind = check `new:<kind>`, n = packets this tick, hold = `hold` s
  (default 60). The alert engine keeps the alert `hold` s after the last tick with new
  packets (docs/module-interface.md, Alerts). Module status = this tick only. Counter rows
  keep the kind's color for `hold` s (display).
- Context decides (2026-10-20):
  - out_leak: crit, info while `pre-connect` (tunnel down, no tunnel flow yet this boot).
    Same context as the out_leak box (live rule). Title `new out_leak (<context>)`.
  - in_vpn: warn, info when every in_vpn line of the tick is from a peer this host talked
    to (an allowed flow logged, or a socket open now): late replies after a flow closed.
    No line this tick (rate limit, lag) -> warn, source unknown.
- Counter lower than last tick (table reloaded) -> its new value counts as new.

Checks (Snapshot v2, key = rule + subject, `t` = tunnel name):

| key | check | sev |
|---|---|---|
| `table` | table missing / nft error | crit |
| `fwmark_set` | `wg_fwmark` set missing (tunnel up) | crit |
| `fwmark` | fwmark live not in `wg_fwmark` set (tunnel up) | crit |
| `handshake_stale:t` | handshake > 180 s while tx grows | crit |
| - | handshake > 180 s, idle | none (shown "idle") |
| `no_handshake:t` | handshake never, tx grows / idle | warn / info |
| `new:<kind>` | new packets of a deny kind (Severity) | kind / context |
| `mode` | mode observe / unknown | warn |
| `tunnel_down:t` | tunnel down | warn |
| `route:v4`, `route:v6` | lowest-metric default route not kill switch or tunnel | warn |
| `route_unknown:v4`, `..v6` | ip error | warn |
| `log_reader`, `ss`, `boot_mode`, `rollback_file` | source error, file unreadable | warn |
| `parse:<source>` | parse error (nft, journal, counters, wg, fwmark, routes, ...) | warn |
| `rollback` | rollback armed (deadline in the future) | info |

- Same key twice in a tick (one source failing in two places): one check, the worse
  severity wins, n adds up.
- handshake stale detail: age, and `kill switch dropped +N pkt this tick (fail closed)`
  when out_ks grew (WireGuard transport routed to the dummy after a network change,
  firewall/docs/observe-log.md 2026-10-19).

Handshake: WireGuard does not handshake on an idle tunnel, so age alone is not a
failure. Keys are rejected after 180 s, so age > 180 s with traffic going out = broken.

## Panels

hostfw (kv), vpn (kv), hostfw counters (table: pkts, new this tick, bytes; zero counters
hidden, count in the title), out_leak (table, see below), blocked / tick (spark, deny
kinds except hidden; severity = worst `new:<kind>` check of the tick), programs (table,
see below), peers (table, see below), audit (table, see below; `width` full: a row of its
own at the bottom, it has the most columns and gets the leftover lines).

- Colors (`tone`): audit, out_leak and counter rows by verdict: allow blue, drop (kill
  switch) red, block yellow, zone / pass / deny plain. Healthy kv values green (table
  loaded, mode enforce, boot mode = live, log reader ok, tunnel up, handshake fresh,
  fwmark in set, default route = kill switch / tunnel). Problems keep their severity color.
- hostfw `log reader` = state of core's journal follower for this module (ok / note /
  down), not a log view.
  System journal view: security screen (phase 4).
- vpn `recv / sent` = bytes received / sent through the tunnel since it came up
  (`wg show transfer`, summed over peers, 1000-based units). Reset on every reconnect.

## Programs box

Who goes out and comes in, per program (2026-10-20). From the same log lines as the audit
box (hidden kinds skipped) and the open sockets (`ss`). 100 kept, least recently seen out
first. Order: with open sockets first, then newest, ties by key.
Title: `programs <rows>  <n> with open sockets`.

| column | value |
|---|---|
| prog | program from the socket's cgroup (`ss --cgroup`, see below); `?` = no ss match (one row per uid); `(inbound)`, `vm`, `(forward)` = lines without a program |
| uid | UIDs of its lines (OUT rules with `skuid`), max 3 then `+`, else `-` |
| open | open sockets now |
| out | allowed lines (new flows, exceptions), out and forward |
| block | drop / block / pass / deny lines, out and forward |
| in | inbound lines (`(inbound)` row) |
| peers | remote addresses (lines + sockets, max 50 kept per program) |
| last | last log line or now while a socket is open |

- Tone: blue = allowed flows or open sockets, red = only dropped / blocked lines.
- Row detail: note (for `?` / inbound / vm rows), open sockets (max 10), logged counts,
  kinds (`out_new 12, out_ks 3`), peers by lines (`(socket)` = open, no line yet), uids,
  first / last seen.
- Row `filter` (keys `f` / `x`, docs/module-interface.md, Screen): the name; `? <uid>` for
  unknown programs (`?` when no uid); `zone` for (inbound), `vm`, `fwd_in` for (forward).
  Only when it is printable ASCII (the filter prompt's chars): else no filter.
- Same limit as the audit `prog` column: a flow that closes before the next `ss` poll
  (6 s) has no program. Blocked flows: mostly `?`. No audit `connect` rule (volume).

Program name (2026-10-20, privilege split): the collector runs as user sectop, `ss -p`
would need CAP_SYS_PTRACE. `ss --cgroup` works without privilege (tested as my user:
NetworkManager, systemd-resolved, libvirtd, chronyd, Brave). Program = innermost systemd
unit of the socket's cgroup (`conns.program()`):
- desktop app: `app[-<launcher>]-<ApplicationID>-<RANDOM>.scope` or
  `...[@<RANDOM>].service` (systemd.io DESKTOP_ENVIRONMENTS) -> the ApplicationID, e.g.
  `com.brave.Browser`. One word: `x` works for every program.
- other units: name without `.service` / `.scope`, template instance and random part
  (`NetworkManager`, `chronyd`, `getty`, `session`). `\xNN` escapes decoded.
- terminal commands: the tab's scope, `vte-spawn` (not `curl`): the price of no ptrace.
- `cgroup:unreachable:<id>` or no unit -> no program (`?` row).

## Row addresses (`ip`, key `w` = whois)

audit: the other side (dst for out / fwd, src for in), out_leak: dst, peers: the peer,
vpn: the endpoint (kv item). Counters: none.

## Peers box

One row per remote address the host talks to (replaces the connections box): from
audit lines (dst for out / fwd, src for in; hidden kinds skipped) and open sockets
(`ss` peer). Loopback, multicast, broadcast, unspecified left out. 200 kept, least
recently seen out first. Order: with open sockets first, then newest, ties by address.
Title: `peers <addresses>  <sockets> open`, `(ss: <error>)` if ss failed.

| column | value |
|---|---|
| peer | address |
| open | open sockets now (`ss` established) |
| new | logged allowed new flows (`*-NEW`, exceptions) since sectop started |
| drop | logged drop / block / zone lines (samples, rate limit) |
| prog | programs from `ss` and matched log lines, max 3 then `+`, else `?` |
| last | last log line or now while a socket is open |

- Tone: blue = open or allowed flows, red = only dropped / blocked lines.
- Row detail: scope (public, private, shared (CGNAT), link-local, unique local (ULA)),
  open sockets (proto local -> peer program, max 10), logged counts, verdict counts,
  first / last seen, programs, uids, ports (remote side), ifaces.
- Counts are log lines, not packets: hostfw logs the first packets of a flow and
  samples blocked ones. Exact packets per address would need a counter per address in
  hostfw (dynamic set with counters), not done.

## Counter detail

`enter` on a counter row: meaning (hostfw rule comment), match (from hostfw
`docs/rules.md`, kept in `MATCH`), verdict, what new packets do (alert key, severity,
hold; `no alert` for allowed and hidden kinds), log rate,
exact bytes, since (table load), then the last 10 log lines of that kind since sectop
started (also in_noise, which is hidden elsewhere). out_dns_vpn / out_wg / out_probe are
counted only, never logged: no lines.

## out_leak box

Leak lines of this boot, newest first, last 8 shown (100 kept). Title: `out_leak <counter>`,
`(newest 8 of N lines)` when more, `(boot scan: ...)` on a scan problem.

- Boot scan in `init()`: the live reader starts at the newest entry, so lines from before
  sectop started (the pre-connect window) need one look back. Cursors from the scan are
  skipped by the live reader (no double rows).
- First tunnel flow = first `HFW-OUT-NEW` line of the boot (scan), else the first one the
  live reader sees.
- Columns: time, uid, proto, dst, iface, context.

| context | when | sev |
|---|---|---|
| pre-connect | before the first tunnel flow (scan), or tunnel down and no flow yet (live) | info (expected: DoH fallback before Proton connects) |
| tunnel up | live, tunnel up at that tick | crit |
| tunnel down | live, tunnel down after the first flow (reconnect window) | crit |
| after connect | scan, after the first flow (tunnel state then unknown) | crit |
| unknown | first-flow query failed | crit |

- Row detail: meaning of the context, time after boot, then the audit detail of the line.
- Limit: hostfw reloaded mid-boot -> `HFW-OUT-NEW` starts later, older leaks may show
  `pre-connect`. Alerts still come from counter deltas (Severity).

Screen: firewall (`core/screens.py`), no events box: the audit box shows the same lines.

## Audit

One row per flow, repeats grouped, newest flow first, last 200 flows kept (in state).
Hidden kinds (in_noise) skipped. Row severity = kind severity, allowed = ok.
out_new / fwd_vm_new (every new flow) go to the audit box only, not to events.
Title: `audit <flows> flows  (<lines> lines)`, lines = all since sectop started.

- Flow = same kind, dir, proto, uid, src, dst, iface. src / dst leave out the larger of
  the two ports: it is the ephemeral one (out: src port; inbound to a service: src port;
  late reply from :443: dst port). Equal ports or no ports: both kept.
- A new line of a flow moves it to the top. Row `id` = the flow key, so the cursor stays
  on the flow.

| column | value |
|---|---|
| last | local HH:MM:SS of the newest line |
| n | lines of this flow |
| dir | out, in, fwd (from the prefix) |
| verdict | allow (allowed kinds), drop (out_ks, fwd_vm_ks), zone (in_*: hostfw logs, firewalld zone decides), block / pass (deny kinds, live mode enforce / observe) |
| proto | PROTO, lower case |
| uid | UID (OUT rules with `skuid`), else `-` |
| prog | out: every process seen with `ss` for a line of the flow (same proto + src + dst, open flows only), max 3 then `+`, else `?`; fwd_vm_*: `vm`; in: `-` |
| src, dst | address[:port], IPv6 compressed (`[v6]:port`) |
| iface | out: OUT, in: IN, fwd: IN>OUT |

- Row detail (`enter`): count + first line time, the left-out ports (last 10, newest
  first), all programs, then the newest line:
  rule (kind + hostfw counter comment), verdict meaning, full local time, log prefix,
  every non-empty log field in log order (IN, OUT, MAC, SRC, DST, LEN, TTL, PROTO, ports,
  UID ...), flags (DF, SYN ...).
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
- nft-table-terse.json: `nft -j -t list table inet hostfw`, 2026-10-20, as is (no set
  elements, nothing to replace). Collect tests build the table answer from
  nft-counters.json + nft-enforce.json / nft-observe.json (same shape, known values).
- journal-audit.json: synthetic, one line per kind (format from hostfw.nft log rules),
  OUT-NEW tcp line = brave flow in ss.txt.
- ss-cgroup.txt: `ss -tunaH --cgroup state established` as my user, 2026-10-20 (live
  test of the split): NetworkManager, Brave and Telegram (Flatpak scopes). Public IPs
  replaced with RFC 5737 ranges. Other unit kinds (vte-spawn, getty, session, escaped
  names, unreachable) are tested with paths in test_firewall.py (TestCgroup).
