# firewall module

hostfw + VPN tunnel (Mullvad WireGuard) status. `modules/firewall/`.
Parsers (`nft.py`, `journal.py`, `conns.py`, `vpn.py`) and `track.py` are pure. `__init__.py` runs
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
| tunnel | `wg show wg0-mullvad latest-handshakes`, `transfer` |
| open sockets (peers, prog) | `ss -tunaeH --cgroup state established` |

Only when a UDP line matches no established socket (QUIC), once per tick:
`ss -tuaneH --cgroup state closed` (unconnected UDP sockets, matched by local port).
`-t` too: with one protocol ss leaves out the Netid column (host 2026-11-03).

Log lines: core's journal follower (`core/journal.py`, docs/module-interface.md,
Journal). `JOURNAL = {"groups": [["_TRANSPORT=kernel"]], "fields": ["MESSAGE"]}`: every
kernel entry since the last collect in `ctx.journal`, HFW lines picked in `journal.py`.

Slow (every 30 s, and at once when the tunnel goes up / down):

| what | argv |
|---|---|
| endpoint, live fwmark | `wg show wg0-mullvad endpoints`, `fwmark` (tunnel up only) |
| fwmark set | `nft -j list set inet hostfw wg_fwmark` |
| kill switch | `nft -j -t list table inet mullvad` (filter chain policies) |
| vpn api | the same table (Mullvad's API rule), `nft -j list set inet hostfw vpn_api4` |

Userspace tunnel (2026-10-30): Mullvad with DAITA runs WireGuard in the daemon (GotaTun)
on a tun device, so `wg show` has no device. `wg show` fails + `/sys/class/net/<tunnel>/tun_flags`
exists (tun device; kernel WireGuard has none) + `flags` has IFF_UP -> tunnel `up
(userspace)`, item `wg data: none`, no `tunnel_down` check. No handshake, transfer,
endpoint or live fwmark then; the fwmark set is shown, no mismatch claim (no live mark).
Change between kernel and userspace = slow sources run again at once.

- Why few: sectop v1 ran as root from my login, so every command was an audit record
  (rule `root_cmds`, ~7 journal entries each). Was 11 commands per tick. See
  docs/architecture.md, Privilege split.
- Net unit timing: fast (table, handshakes, transfer) every half module interval, slow
  (endpoints, fwmark, fwmark set, kill switch table, vpn_api4 set) every 15 s: each tick reads a fresh
  sample. Counters are cumulative: a sample read twice gives delta 0 now and the full
  delta next tick.
- `-t` (nft(8): "Omit contents of sets"): counters and the enforce chain without the
  set elements. wg_fwmark elements come from the slow set call.
- Mode from the table: only rules of chain `enforce` count; no chain `enforce` = unknown.
- Slow items and their checks are kept and shown every tick until the next slow run.
  A changed endpoint, fwmark or kill switch table shows within 30 s (a reconnect at once).
- Reconnect (2026-11-03, host: false `fwmark mismatch` crit for 30 s after a reconnect):
  the slow run at the change read the net unit's samples from before it (tunnel down,
  "Unable to access interface"). Now: the time of the fast sample that showed the change
  is kept; while the endpoint, live fwmark or wg_fwmark sample is older
  (`netd.Reader.stamp()`), item `fwmark: waiting for a net unit sample newer than the
  tunnel change`, no endpoint, no fwmark check, slow sources again next tick (at most
  ~15 s, the net unit's slow period).
- Live fwmark unreadable (wg rc != 0): `fwmark live: <why>` info, no mismatch claim.
  Parse error: warn + check `parse:wg` (as before).
- Kill switch: the VPN app's own nftables table (Mullvad: `inet mullvad`, kept while
  disconnected by lockdown mode). On = a filter chain with policy drop on input, output
  and forward (route / nat chains ignored). Rules not read. Missing or open: warn, hostfw
  still rejects leaks in enforce.
- vpn api (2026-11-03): Mullvad allows its API outside the tunnel with one rule in
  `inet mullvad` chain output, only while not connected: exactly `ip daddr <addr> tcp
  dport 443 meta skuid 0 accept` (the relay rule has a mark, not skuid; same match as
  `hostfw api-update`). The address is kept from the last time seen (memory, until
  sectop restarts): connected, the rule is gone. In `vpn_api4` -> ok; not seen yet ->
  ok, set shown; not in the set -> warn: the daemon's API calls outside the tunnel are
  blocked (out_leak) until `mullvad disconnect; sudo hostfw api-update; mullvad
  connect`. No automatic update: hostfw opens nothing on its own.

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
(name part may have dashes).

| sev | kinds |
|---|---|
| crit | out_leak (warn when blocked: enforce, 2026-11-04), out_split (always blocked, still crit) |
| warn | out_dns, in_lan, in_vpn, fwd_vm_lan, fwd_in, out_noscope |
| info | out_disco, out_share, out_lan, unknown kinds |
| hidden | in_noise (counter only, no event, no audit row) |
| ok | out_dns_vpn, out_wg, out_vpn_api, out_router_admin, out_lan_allow, out_new, fwd_vm_new (allowed) |

- Alerts come from counter deltas, not totals: totals since boot include the
  pre-connect window. First tick never alarms.
- New packets of a deny kind = event check `new:<kind>`, n = packets this tick, `at` =
  the tick (wall clock). Hold by severity (core/alerts.py EVENT_HOLD: crit 10 min, warn
  5 min, info 1 min), option `hold` = seconds for every kind. The alert engine keeps the
  alert that long after the last tick with new packets (docs/module-interface.md,
  Alerts). Module status = this tick only. Counter rows keep the kind's color as long
  (display).
- Context decides (2026-10-20):
  - out_leak: crit, info while `pre-connect`, warn when hostfw blocked it (mode enforce,
    verdict `block`): an attempt, nothing left outside the tunnel; title
    `new out_leak (<context>, blocked)`, detail says so (2026-11-04: every wifi drop gave
    chronyd / brave leak lines, all blocked, all red). observe / mode unknown: crit, the
    packet may have left. Context = the worst context of this tick's
    leak lines (out_leak box, each at its own time). No line this tick (rate limit, lag):
    tunnel up at both ends of the tick window = `tunnel up`; first tunnel flow in the
    window or later = `pre-connect`; else `tunnel down`. Title `new out_leak (<context>)`.
  - in_vpn: warn, info when every in_vpn line of the tick is from a peer this host talked
    to (an allowed flow logged, or a socket open now): late replies after a flow closed.
    No line this tick (rate limit, lag) -> warn, source unknown.
- Counter lower than last tick (table reloaded) -> its new value counts as new.
- out_split (hostfw 2026-11-05): split tunneling (ct mark 0xf41, or the relay mark on a
  non-root socket: `mullvad-exclude` is setuid root, any local user can run a program
  outside the tunnel) not to a VM bridge.
  Own reject in hostfw, no `jump enforce`: verdict `block` in every mode (ALWAYS_BLOCK).
  crit all the same: blocked, but someone tried to leave the tunnel.
- out_noscope (hostfw 2026-11-03): new flows from GNOME Shell's cgroup (an app without
  its own scope). Own switch in hostfw, chain `enforce_noscope` (`hostfw noscope observe
  | enforce`), read from the same table (`nft.mode(text, "enforce_noscope")`): verdict
  pass / block from it, not from the global mode. hostfw box item `noscope`: observe /
  enforce, `-` for a ruleset without it (no claim). Program of its lines: the socket's
  (sockets of that cgroup: org.gnome.Shell/<comm>, Programs box).

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
| `killswitch` | VPN kill switch table missing / nft error, or no drop policy on input / output / forward | warn |
| `vpn_api` | Mullvad's API address (last seen while not connected) not in `vpn_api4` | warn |
| `log_reader`, `ss`, `boot_mode`, `rollback_file` | source error, file unreadable | warn |
| `parse:<source>` | parse error (nft, journal, counters, wg, fwmark, killswitch, ...) | warn |
| `rollback` | rollback armed (deadline in the future) | info |

- Same key twice in a tick (one source failing in two places): one check, the worse
  severity wins, n adds up.
- handshake stale detail: age, tx growing.

Handshake: WireGuard does not handshake on an idle tunnel, so age alone is not a
failure. Keys are rejected after 180 s, so age > 180 s with traffic going out = broken.

## Panels

hostfw (kv), vpn (kv), hostfw counters (table: pkts, new this tick, bytes; zero counters
hidden, count in the title), out_leak (table, see below), blocked / tick (spark, deny
kinds except hidden; severity = worst `new:<kind>` check of the tick), programs (table,
see below), peers (table, see below), audit (table, see below; `width` full: a row of its
own at the bottom, it has the most columns and gets the leftover lines).

- Colors (`tone`): audit, out_leak and counter rows by verdict: allow blue, block yellow,
  zone / pass / deny plain. Healthy kv values green (table loaded, mode enforce, boot
  mode = live, log reader ok, tunnel up, handshake fresh, fwmark in set, kill switch
  drop, vpn api in set). Problems keep their severity color.
- hostfw `log reader` = state of core's journal follower for this module (ok / note /
  down), not a log view.
- Column types (right-aligned, docs/module-interface.md): counters pkts / new / bytes;
  programs open / out / block / in / peers; peers open / new / drop; audit n. Ages:
  programs, peers and audit `last`, out_leak `age`.
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
  kinds (`out_new 12, out_lan 3`), peers by lines (`(socket)` = open, no line yet), uids,
  first / last seen.
- Row `filter` (keys `f` / `x`, docs/module-interface.md, Screen): the name; `? <uid>` for
  unknown programs (`?` when no uid); `zone` for (inbound), `vm`, `fwd_in` for (forward).
  Only when it is printable ASCII (the filter prompt's chars): else no filter.
- Same limit as the audit `prog` column: a flow that closes before the next `ss` poll
  has no program. Blocked flows: mostly `?` (a rejected SYN never has a socket). No
  audit `connect` rule (volume).

Program of a log line (2026-11-03, my ask: no unexplained `?`), first match wins, one
answer per line and tick (every box shows the same):
1. established socket, same proto + both addresses + ports (`ss`)
2. UDP: unconnected socket on the line's local port (exact local address or wildcard),
   from the lazy `ss ... state closed` call (QUIC often sends unconnected)
3. guess `<name>?`: exactly one program had sockets to the line's peer (now, or earlier
   in the peers box). Own row (`brave?`, note `guess: ...`), never on a card (`progs`),
   not fed back into the peers box. Two or more programs: `?`.
4. `?` (row `? uid N`)
   Why `?` (2026-11-07), in the audit row detail `why ?` and the `? uid N` note:
   not tcp / udp (`ss` lists tcp / udp only: IGMP, ICMP), no uid in the line (kernel,
   no socket owner), multicast / broadcast destination (discovery: one short send),
   else a short flow of uid N that closed before the ss poll.

Shared cgroup (2026-11-03): an app GNOME starts can land in GNOME Shell's own unit
(`org.gnome.Shell@<x>.service`) when its launcher forks before GNOME moves it into its
scope (host: Brave rpm, fixed by silverblue-cis-hardening appunit). Its sockets' cgroup
says `org.gnome.Shell`. Socket name then (`core/proc.py` shared / own / strays):
- user helper (`core/userd.py`, sectop-user@<user>.service) knows the socket inode:
  GNOME's own process (gnome-shell, Xwayland, bwrap, glycin-*,
  mutter-x11-frames) -> `org.gnome.Shell`,
  another -> `org.gnome.Shell/<comm>` (e.g. `org.gnome.Shell/brave`)
- no helper answer: `org.gnome.Shell/?` while the cgroup holds other processes
  (`cgroup.procs` + `/proc/<pid>/comm`, readable by every user), else `org.gnome.Shell`
- such rows: yellow (`sev` warn) while a socket is open, detail `shared cgroup` (what
  else is in there; red line while open), `fix` / `user helper` (why no name). Never a
  guess (`<name>?`) for them. Card (`c`) = org.gnome.Shell. The alert
  is the system module's check `shared_cgroup:<unit>` (screen 3): the firewall rows
  only show it. Names from the helper are display only (a process sets its own comm).

Program name (2026-10-20, privilege split): the collector runs as user sectop, `ss -p`
would need CAP_SYS_PTRACE. `ss --cgroup` works without privilege (tested as my user:
NetworkManager, systemd-resolved, libvirtd, chronyd, Brave). Program = innermost systemd
unit of the socket's cgroup (`conns.program()`):
- desktop app: `app[-<launcher>]-<ApplicationID>-<RANDOM>.scope` or
  `...[@<RANDOM>].service` (systemd.io DESKTOP_ENVIRONMENTS) -> the ApplicationID, e.g.
  `brave-browser` (rpm, `app-gnome-brave\x2dbrowser-<n>.scope`, host 2026-11-02) or
  `com.valvesoftware.Steam` (Flatpak). One word: `x` works for every program.
- other units: name without `.service` / `.scope`, template instance and random part
  (`NetworkManager`, `chronyd`, `getty`, `session`). `\xNN` escapes decoded.
- terminal commands: the tab's scope, `vte-spawn` (not `curl`): the price of no ptrace.
- `cgroup:unreachable:<id>` or no unit -> no program (`?` row).
- `-e`: `ino:<n>` (socket inode) kept with the cgroup: the user helper names sockets of
  the shared cgroup by inode.

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

Row detail of a counter: meaning (hostfw rule comment), match (from hostfw
`docs/rules.md`, kept in `MATCH`), verdict, what new packets do (alert key, severity,
hold; `no alert` for allowed and hidden kinds), kind, log rate,
bytes (`30.7K (30697)`), since (table load), then the last 10 log lines of that kind since
sectop started (also in_noise, which is hidden elsewhere). Searched by `/`, shown by `enter`
only for volume counters (no lines, no card).

Kind (2026-11-07): from the ruleset in the same `nft -j -t list table` call (nft.logs()),
not a fixed list. event = a log statement follows the counter before the first verdict
(same rule, or the next match-free rules of the chain: hostfw's `counter name x` then
`limit ... log`); the log rate shown is the rule's own limit. volume = counted only
(out_dns_vpn, out_wg, out_vpn_api today). A counter no rule shows (older output): the old
fixed list `NOT_LOGGED`. Before, a hostfw change of what is logged needed a sectop change.

## Counter card (log card, 2026-11-04)

`enter` on any other counter row (row `logs` = the counter name, in_noise too): every
line hostfw logged for it this boot, read when the card opens (modules/firewall/logcard.py,
in the UI process, core/logs.py). Why: the detail had 10 lines since sectop started, no
order; host 2026-11-04 `fwd_vm_lan 20` needed `journalctl -g` to see what they were.

- Query: `journalctl -b 0 _TRANSPORT=kernel -o json --output-fields=MESSAGE -q
  --no-pager --grep=^HFW-<RULE>: -n 3000`, 5 s, 4 MiB. The rule must match
  `[a-z][a-z0-9_]{0,39}` (no typed text in the argv). Newest 3000 lines; a cut read or
  bad lines: said in the card head (warn color).
- Head: `counted N` (counter, since the hostfw table load) vs `logged M` (lines, this
  boot), then what the difference means (N > M: rate limit, the rest counted only;
  N < M: table reloaded this boot), verdict (rule's severity color), meaning, match.
- Flows (box `logflows`): one row per proto, src, dst, iface, uid (journal.flow(): the
  ephemeral port left out), newest first. Cols: last, first, n, proto (`icmp 8 echo`,
  `icmpv6 135 neighbor solicit`), src, dst, iface (`virbr0>wlo1`), uid (`vm` for VM
  kinds). Row detail: lines, first, last, source ports seen (first 20).
- Packets (enter on a flow, box `logpkts`): every line of the flow, oldest first. Head:
  the flow, count, first / last. Cols: time, proto, src:port, dst:port, TCP flags, len,
  ttl, iface.
- Fields (enter on a packet): rule, verdict, full time, then every field with a label
  (`source port (SPT)`). Colors: addresses, ports, proto, ifaces, uid in the value color,
  flags orange (high), verdict in the rule's severity color (allowed: cyan).
- Row colors as the counter row: sev = the kind's severity (allowed: ok), tone = the
  verdict (allow blue, block yellow), in_noise dim. Mask on: public IPs masked in the
  tables, real in the fields (like every detail). `w` on a flow / packet: whois of the far
  side. `/` filters flows / packets. Esc goes one level up, then closes.

## out_leak box

Leak lines of this boot, newest first, last 8 shown (100 kept). Title: `out_leak <counter>`,
`(newest 8 of N lines)` when more, `(boot scan: ...)` on a scan problem.

- Boot scan in `init()`: the live reader starts at the newest entry, so lines from before
  sectop started (the pre-connect window) need one look back. Cursors from the scan are
  skipped by the live reader (no double rows).
- First tunnel flow = first `HFW-OUT-NEW` line of the boot (scan), else the first one the
  live reader sees.
- Columns: age, uid, proto, dst, iface, context. Age = epoch seconds in the cell (column
  type `age`): the screen shows `12s` / `4m`, the detail the full local time.

| context | when | sev |
|---|---|---|
| pre-connect | line before the first tunnel flow of the boot (scan and live), tunnel not seen up around it | info (expected: programs that start before the VPN connects) |
| tunnel up | live, tunnel up at the ticks before and after the line | crit, warn when blocked |
| tunnel down | live, after the first flow, tunnel down or switching around the line (reconnect window) | crit, warn when blocked |
| after connect | after the first flow, before sectop watched the tunnel (scan, or a live line older than the first tick) | crit, warn when blocked |
| unknown | first-flow query failed | crit, warn when blocked |

- Blocked (verdict `block`): context cell `<context>, blocked`, detail line `blocked`.
  Box sev = worst row (info rows do not count).
- Row `ref` = its audit flow key (`fw:` + the audit row `id`): the alerts view shows a
  leak line and its audit flow as one row (docs/module-interface.md, Rows).

- Context at line time (2026-10-27): `modules/firewall/track.py` keeps the tunnel state
  per tick; between two ticks with different states it is "switching". A line is read
  a tick (or more) after it was written, so the state at read time is wrong: on
  2026-10-26 pre-connect lines read on the tick the tunnel came up showed `tunnel up`
  (crit). First tunnel flow = the earliest `HFW-OUT-NEW` of the tick, before its leak
  lines (journal order is not time order). A live line up to 5 s older than the first
  tick still gets the first tick's state (journal lag).
- Row detail: meaning of the context, time after boot, then the audit detail of the line.
- Limit: hostfw reloaded mid-boot -> `HFW-OUT-NEW` starts later, older leaks may show
  `pre-connect`. Alerts still come from counter deltas (Severity).

Screen: firewall (`core/screens.py`), no events box: the audit box shows the same lines.

## Audit

One row per flow, repeats grouped, newest flow first, last 200 flows kept (in state).
Hidden kinds (in_noise) skipped. Row severity = kind severity, allowed = ok; out_leak
blocked = warn (detail line `blocked`). Row `ref` = `fw:` + `id` (alerts view merge).
out_new / fwd_vm_new (every new flow) go to the audit box only, not to events.
Title: `audit <flows> flows  (<lines> lines)`, lines = all since sectop started.

- Flow = same kind, dir, proto, uid, src, dst, iface. src / dst leave out the larger of
  the two ports: it is the ephemeral one (out: src port; inbound to a service: src port;
  late reply from :443: dst port). Equal ports or no ports: both kept.
- A new line of a flow moves it to the top. Row `id` = the flow key, so the cursor stays
  on the flow.

| column | value |
|---|---|
| last | age of the newest line (type `age`: epoch seconds, full time in the detail) |
| n | lines of this flow |
| dir | out, in, fwd (from the prefix) |
| verdict | allow (allowed kinds), zone (in_*: hostfw logs, firewalld zone decides), block / pass (deny kinds, live mode enforce / observe) |
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

Summary: `enforce | wg0-mullvad up | hs 20s | leak 4`, plus first 3 warn / crit checks.

## Options

```toml
[modules.firewall]
tunnel = "wg0-mullvad"
# hold = 60        # optional: seconds for every kind; default by severity
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

`tests/fixtures/firewall/` from my host, 2026-10-19, enforce mode, tunnel up; moved to
Mullvad 2026-10-26.

- Public IPs replaced with RFC 5737 ranges, peer key with a dummy, TV MAC and
  link-local with dummies. LAN 192.168.8.0/24 kept.
- nft-table-terse.json, nft-counters.json, nft-wg-fwmark.json: firewall/hostfw.nft
  (Mullvad) loaded with nft 1.0.9 in a network namespace, counter values from the
  2026-10-19 host capture.
- nft-mullvad-terse.json: my host's `nft list table inet mullvad` (2026-10-26, relay
  address masked) loaded the same way.
- nft-mullvad-disconnected.json: chain output = my host's `nft list chain inet mullvad
  output` while not connected (2026-11-03, API address 192.0.2.10), other chains from
  nft-mullvad-terse.json without the tunnel rules; loaded the same way.
- nft-vpn-api4.json: `nft -j list set inet hostfw vpn_api4` of firewall/hostfw.nft with
  one element 192.0.2.10, same way.
- journal.json: real IN-NOISE lines, 3 fields kept, cursors rewritten. OUT-LAN (MLDv1
  report), OUT-LEAK, OUT-DNS, IN-VPN and the non-HFW line are synthetic (format from
  real logs).
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
