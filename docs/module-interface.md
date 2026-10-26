# Module interface

sectop v1. Core loads modules, calls them on a timer, renders their output.
Modules collect data only. They never draw.

## Layout

- `modules/<name>/__init__.py`. `NAME` must equal `<name>`.
- Registered in `core/registry.py`: `MODULES`, import names `modules.<name>`.
  Static list, no dynamic loading from config paths.
- Placed on exactly one screen in `core/screens.py` (see Screen).

## Loading (`core/registry.py`)

- Config table for a module not in `MODULES` -> `ConfigError`, refuse to start.
- `enabled = false` -> module not imported at all.
- Per module: import -> `check_module()` + NAME check -> `init(cfg)`.
  `cfg` = deep copy of the options. Interval = config `interval`, else module INTERVAL.
- Any failure -> that module disabled, error `<stage>: <ExcType>: <message>`
  (stage: import, check, init). Other modules still load.
  `SystemExit` from a module is caught too. `KeyboardInterrupt` is not.
- `close()`: only modules whose init succeeded, reverse order.
  Errors collected, the rest still closed.

## Module API

```python
NAME = "firewall"     # unique, [a-z0-9_]+
INTERVAL = 2.0        # seconds; config can override, min 1.0
JOURNAL = {...}       # optional: journal entries the module reads (see Journal)

def init(cfg: dict) -> object: ...
def collect(state: object, ctx: Context) -> dict: ...   # returns Snapshot
def close(state: object) -> None: ...     # optional
```

- `init`: once at start. `cfg` = `[modules.<name>]` table (may be empty).
  Returns module state (any object). Raise -> module disabled, error shown.
- `collect`: every INTERVAL. Returns Snapshot. Raise -> see Errors.
  `ctx` (`core.module.Context`, frozen): `journal` (entries since the last collect),
  `journal_up`, `journal_note` (see Journal). Empty for a module without JOURNAL.
  Planned: `visible` (screen shown or not).
- `close`: on exit, if defined.
- Single thread. No threads, no long-lived child processes in modules. The journal:
  declare JOURNAL, core runs one follower for all modules.
- External commands only via `core.run.run()`.
- Module keeps its own history (spark series, counter deltas) in state.

## Snapshot (v1, v2)

```json
{
  "v": 1,
  "status": "ok",
  "summary": "enforce | proton0 up | leak 0",
  "panels": [],
  "events": []
}
```

| key | type | rule |
|---|---|---|
| v | int | 1 or 2 |
| status | str | ok, info, warn, crit, unknown |
| summary | str | one line, module header |
| panels | list | Panel, max 8 |
| events | list | Event, new since last collect only, max 100 |
| checks | list | v2 only, required. Check, max 50 (see Checks) |

- Only dict, list, str, int, float, bool, None.
  Core checks with `json.dumps`. Needed for the later split
  (root collector service -> unprivileged UI).
- v2 = v1 + `checks`. v1 still accepted (no checks) until all modules move to v2.

## Severity

`ok < info < warn < crit`. `unknown` = no valid data.
v1: module sets status. v2: header status = worst open / held alert of the module
(not noise), so header and alert bar agree; the Snapshot `status` is the module's view of
this tick. Core overrides both for stale / error (see Errors).

## Panels

Common keys: `id` (unique in module), `title`, `type`. `sev` optional, default ok.
`width` optional (layout hint): `auto` (default) or `full` = a grid row of its own.
All displayed values are str. Module formats numbers.

kv:

```json
{"id": "mode", "title": "hostfw", "type": "kv",
 "items": [{"k": "mode", "v": "enforce", "sev": "ok"},
           {"k": "rollback", "v": "-"}]}
```

table (rows max 200):

```json
{"id": "conns", "title": "Connections", "type": "table",
 "columns": ["proc", "uid", "dst", "port", "iface"],
 "rows": [{"cells": ["firefox", "1000", "10.2.0.1", "53", "proton0"], "sev": "ok",
           "detail": [{"k": "TTL", "v": "64"}]}]}
```

`types` optional (column hint, one per column): `text` (default, left), `num` (right),
`age` (right; the cell is epoch seconds as text, e.g. `"1792410745.120"`, or `-` / empty
for none; shown as `12s` `4m` `2h` `3d`, the detail and the filter use the full local
time). Wrong length / type, or an age cell that is not epoch seconds -> invalid.

Row `detail` optional: extra k / v pairs shown on `enter` under the cells (max 40).
Row `id` optional (str): stable key of the row (e.g. a grouped flow). The cursor follows
it when the row moves or its text changes. Not shown.
Row `filter` optional (str, 1..60 printable ASCII, not blank): filter text for keys `f` /
`x` on that row (e.g. a program name). Not shown.
Row `progs` optional (list of 1..5 str, each 1..64 printable ASCII without space): the
programs the row belongs to (core/proc.py names: unit / app id of the cgroup). Key `c`
opens the card of the first one. Not shown. Only names that are sure: a pid read later
than its record counts only when the process started before it (2026-10-26).

`ip` optional on kv items and table rows: the address of that line (a valid IPv4 / IPv6
address, stored normalized). Core can look it up on key `w` (whois, see Screen).

`tone` optional on kv items and table rows: `plain`, `red`, `blue`, `yellow`, `green`,
`dim`. A color for meaning (a verdict, a healthy state, a less important row), not a
severity. See Screen (color).

spark (values max 120, numbers):

```json
{"id": "rate_leak", "title": "out_leak / tick", "type": "spark",
 "values": [0, 0, 1, 0], "unit": "pkt", "sev": "warn"}
```

## Events

```json
{"ts": 1760870780.123, "sev": "crit", "code": "HFW-OUT-LEAK",
 "msg": "uid 1000 tcp 192.168.8.102:46866 -> 149.112.112.11:443 wlo1"}
```

- `ts`: float, epoch seconds.
- `sev`: info, warn, crit. Hidden kinds (e.g. IN-NOISE) are dropped by the module.
- `code`: short stable id, used for filter.
- `msg`: one line.
- Core adds `src` = module NAME. Shared feed, last 500, newest first.
  Shown in the events box of the module's screen (if that screen has one).

## Checks (v2)

Conditions that are true now. Core turns them into alerts (see Alerts).
A condition that is not true any more is left out.

```json
{"key": "handshake_stale:proton0", "sev": "crit", "title": "proton0 handshake stale",
 "detail": "last handshake 4m 10s ago, sending", "n": 0, "hold": 60}
```

| key | type | rule |
|---|---|---|
| key | str | rule + subject, 1..128 of `A-Z a-z 0-9 _ . : / @ % + -`, unique in the Snapshot |
| sev | str | info, warn, crit (no ok: a check is a problem) |
| title | str | one line |
| detail | str | optional, default "" |
| n | int | optional, default 0, max 10^9. New occurrences since the last collect (e.g. packets) |
| hold | number | optional, seconds 0..3600, default 60. Alert keeps firing this long after the check is gone |

- Max 50 per Snapshot. More: the worst 50 kept (severity, then module order).

## Alerts (`core/alerts.py`)

- Pure: `step(state, module, checks, now) -> new state`. No I/O, no clock, input not
  changed. State = plain JSON, so the collector can hand it to the UI after the split.
- `core/collector.py` steps it after each successful collect of a module, `now` = wall
  clock.
  A module that fails is not stepped: its alerts keep their state.
- Alert key = `<module NAME>/<check key>`.
- open: reported in the last step of its module. held: not reported any more, still
  firing until `hold` s after it was last reported. closed: hold over.
- Reported again while held = same alert (`since` kept). After closed = new firing
  period (`since` = now), same record (`first`, `count` kept).
- count: + max(n, 1) when the check turns true, + n while it stays true.
- Latest sev / title / detail / hold win. A held alert keeps the last ones.
- `active(state, now, noise)`: open and held alerts, each with `state` and `noise`
  (reason of the matching noise entry, else None). Noise last, then worst first, open
  before held, newest `since` first, then key.
- Records max 500: closed out first, then held, oldest last seen first. Open never.
- Not here: ack (UI, docs/architecture.md, Alerts).

## Errors (`core/collector.py`)

- `collect` raises (incl. `SystemExit`) or returns an invalid Snapshot -> module state error.
  Header shows exception type + message. Last good panels kept, marked stale.
  Other modules unaffected. `KeyboardInterrupt` and SIGTERM stop the collector.
- 3 errors in a row -> interval x2, each further error x2 again, max 60 s
  (never below the configured interval). Reset on first success.
- Last good Snapshot older than 3 x interval (configured, not backed off) -> status unknown.
- `collect` slower than interval -> marked slow, next run a full interval after it ended.
  Keep `run()` timeouts below interval.
- Module not loaded (registry error) -> status unknown, header shows the error.
  Disabled -> shown as OFF.
- Collector -> UI: `/run/sectop/state.json` (State files) after every collect and every
  5 s. UI (`core/app.py`): no new state for 3 x the state's `interval` (min 15 s),
  no file, a bad file, user sectop missing or no access -> crit alert `core/collector`
  "collector: <why>" (the bar shows titles only, so the title says why), last good data
  kept, modules marked stale (status unknown). User sectop is looked up again on every
  poll until it exists (install while the UI runs).
- Collector and UI refuse to run as root (rc 2).

## Screen (`core/render.py`, `core/screens.py`, `core/ui.py`)

- Screens are static in `core/screens.py`: name, modules (box order), events box yes / no,
  note while empty, box focused at start. Each screen uses the whole terminal.
- Start screen: `sectop [SCREEN]`, name or number, default 1. Unknown -> usage, rc 2.
- Lines, top to bottom:
  - tabs, PAUSED, mask state, clock
  - alert bar (`core/render.py` `_alerts`), alerts from all screens:
    - engine alerts (Alerts, `active()`) with sev warn / crit, not noise:
      `TAG title` + ` xN` when count > 1. Held alert (condition gone, within hold): dim title.
    - module problems the engine does not cover: status unknown (not loaded, stale,
      error), crit / warn of a v1 module: `TAG name`. Not while waiting for the first collect.
    - Not acked first, then acked (dim tag). Each group: crit, warn, unknown, engine
      order inside.
    - Right: `N alerts  K acked  I info  Z noise` (info and noise alerts are counted, not
      listed). Too long: alerts cut (`~`), counts stay.
  - one header per module on this screen: `[STATUS] name  summary  | flags`
  - box grid
  - key help
- Box grid: one box per panel, in module order, then the events box.
  - Width: a box joins the row while its least width fits, extra width shared in the row.
    Panel `width` full: a row of its own (like events / note).
    Natural content width: kv = key + value (24..56 cells), table = its columns (min 24),
    kv / table at least the title, spark 40, events / note = full row.
    Sparks share a row only with sparks.
  - Least width: kv 24, table = column floors (each column: its header, at least 6 cells,
    never more than natural), spark 40. A row wider than the screen takes cells from the
    box with the most room above its least width. In a shrunk table the widest column
    loses a cell first; cut cells end in `~`, `enter` shows them whole.
  - Height: each row gets its content height. Leftover lines go to the last row with a
    table, events or note. Too few lines: the tallest row shrinks first (lower row on a tie).
    A row that cannot get one line is not drawn.
  - Table header stays, rows scroll. Top border: title left (with the module's own
    count), right: `/ <filter>  <shown> of <all>`, detail search, `first-last/total` when
    cut. No room for that: the counts only; still none: left out, never over the title.
  - Stale module: `(stale)` in each box title.
- Look (2026-10-25, docs/architecture.md, Look): rounded outer corners; severity column
  first in tables, kv boxes and events: `!!` crit, `!` warn, `i` info, empty ok, in the
  severity color (WCAG 2.2, 1.4.1: color is not the only means); the row keeps its color
  as before (severity, `tone`). Table header bold + underlined (labels only), 2 spaces
  between columns. Ages count from now; paused: from the pause moment (frozen).
  Column width: natural, max 40 cells; free room in the box goes to a cut column, the
  last one first (2026-10-25: full-width commands box, command line cut at 40).
  Events: glyph, age, source + code, message; detail: full local time + age.
- Focus: focused title `[title]` in reverse. Start: screen `focus`, else first table /
  events box, else first box. Gone -> same rule.
- Cursor: each box has a selected line, shown in reverse in the focused box; the box
  scrolls to keep it visible. Line 0 follows the newest line. Below line 0 the cursor
  stays on the same row when new lines arrive above it: row `id`, else its raw cells
  (ages move, the anchor does not); kv: the key; events: time + source + code + message
  (found nearest to the old index; not found -> same index, clamped).
- Filter (`/`, table and events boxes): type words, applied while typing; `enter` keeps
  it, `Esc` goes back to the filter before. Every key is text while typing (q does not
  quit). A line is shown when all words are in it and no `!word` is; case-insensitive,
  searched in the cells, the row `detail` values (e.g. rule name `out_ks`), raw and
  masked text (`160.79.x.x` works too). Title: `/ <filter>  <shown> of <all>`. `Esc`
  outside typing clears the focused box's filter. Cursor back to line 0 on each change.
  Max 60 chars.
- `enter`: detail of the selected line in one overlay box: table row = column / cell pairs,
  severity, row `detail`; kv item, spark values, event fields. Long values wrap.
  Real IPs: the detail is opened on purpose, so it is not masked. While mask is on the
  title says `real IPs shown` (screenshots of the detail show them). Secrets stay masked
  while mask is on (see Display safety).
  Opening it pauses; closing resumes (unless paused before).
  Scroll: the line keys (`j` `k` / arrows, `space` `PgDn` / `PgUp`, `g` `G` / `Home` `End`);
  the footer lists them. Help scrolls the same way. 2026-10-22: a detail longer than the
  box could not be scrolled (every frame took the first line as the anchor and went back
  to it); the overlay text has no row identity now, tests run key, layout and update
  together (`TestDetailLoop`).
  Search (`/` in a detail): lines whose key + value contain the text (case-insensitive,
  searched on the pair, so a wrap never cuts a match; real or masked text, like the table
  filter: `160.79.x.x` as a table shows it with mask on) are bold, the view jumps to the first
  one, applied while typing. `enter` keeps it, `Esc` goes back to the text before (and its
  first match), empty text = no search. `n` / `N`: next / previous match, wraps; with no
  current match (scrolled by hand) from the top line. The current match is reverse. Title:
  `/ <text>  <n>/<matches>` or `no match`. Opened from a table with exactly one positive
  filter word (`!words` ignored), the detail starts at the first line with it. The UI asks
  (`ui.seek`), the renderer moves (it knows the wrapped lines) and reports the current
  match (`BoxInfo.mark`, a pair index: stable when the width changes). Max 60 chars.
- whois (`w`, `core/lookup.py`, `core/rdap.py`): on a line with `ip` (or in its detail)
  opens the detail and looks the address up with RDAP (RFC 9224 bootstrap from IANA,
  RFC 9083 answer), the modern WHOIS. Public addresses only. Detail shows `whois` then
  name, handle, range, cidr, type, country, parent, org, abuse, dates, remark, whois
  server, source URL, or the error.
  - Socket service, never my user: the UI connects to `/run/sectop-whois.sock`
    (root:sectop 0660), sends the IP line, reads one JSON line (max 64 KiB, max 20
    fields, values cut to 200). systemd starts one `sectop-whois@.service` per connection
    (`Accept=yes`): `python3 -I -B core/rdap.py`, stdin / stdout = the connection, own
    dynamic user, network and nothing else. Network data is parsed only there.
  - HTTPS only (redirects to other schemes refused), 4 s per request, body max 1 MiB,
    whole lookup max 12 s (UI side; the unit has `RuntimeMaxSec=15`).
  - Blocks the UI while it runs, after a frame that says `looking up`. Only on key press,
    one lookup per address per session (last 100 kept). Goes out via the tunnel like
    any program (audit shows the flows, uid of the dynamic user).
- Pause (`p`): the screen keeps the view from the moment of pausing, collecting goes on.
  Resume shows the current view.
- Keys: `1-9` screen; `tab` / right / `l` next box, `shift-tab` / left / `h` previous box;
  down / up / `j` `k` line; `space` `PgDn` / `PgUp` page; `g` `G` / `Home` `End` first / last;
  `enter` detail; `/` filter (in a detail: search, `n` `N` next / previous match);
  `Esc` clear filter; `f` follow; `x` hide; `c` card; `w` whois; `a` ack; `p` pause;
  `m` mask; `?` help; `q` quit.
- Card (`c`, on a row with `progs`): a table overlay (box key `card`) with every table
  row of every module (all screens) whose `progs` holds the first name of the selected
  row, box by box. Cols: last (its first age cell), box (`<module>/<panel>`), what (its
  other cells); sev and tone kept. Select with the line keys, `/` filters it, `enter`
  opens the row's detail (the box title, every column of its box with full times, its
  own detail; `w` works on its address), `Esc` there goes back to the card, `Esc` in the
  card closes it. Pauses while open (2026-10-26; a selectable table since his first try:
  he wanted to open each line).
- Follow (`f`, on a row with `filter`): that filter on every other filterable box of the
  screen; `f` again (all of them on it): cleared. Hide (`x`, filter of one word): adds
  `!word` to every filterable box of the screen (once; skipped when it would pass 60
  chars). Both are plain filters: shown in the box titles, `Esc` clears a box.
- Ack (`a`, also in help / detail, not while typing a filter): every engine alert in the
  alert bar is acked: key -> (count, sev) at ack (`core/ui.py`). Shown dim, last, until
  its count or severity rises. Acks of alerts no longer in the bar are dropped. Phase 2:
  memory only (sectop still runs as root, no file in my home).
  In help / detail / card: `Esc` `q` `enter` `?` close, line keys scroll. Esc delay 25 ms.
- Redraw: full after a collect (not while paused) or a key (incl. resize); between those
  only the clock line, once a second.
- Every string goes through `display()`. Width counted in terminal cells (wide chars = 2).
- Color: severity first. ok plain; info, warn, crit, unknown colored. With a `tone`:
  the tone color replaces ok / info / warn, warn adds bold, crit always stays crit
  (bold red). 256-color terminal: soft tones (xterm 210 red, 111 blue, 222 yellow,
  114 green), crit 196. Else the 8 basic colors; no color support: plain. Tone `dim`:
  A_DIM on every terminal.
- Box lines: Unicode box drawing (U+2500 block, rounded corners U+256D..U+2570), written
  as escapes in the source. Legend of glyphs and colors: README.md, Screen legend.

## Journal (`core/journal.py`)

One follower for the whole collector: one long-lived `journalctl -f`, started and
owned by core, read in the collector loop without threads. Why follow, host facts:
docs/architecture.md, Resources.

```python
JOURNAL = {"groups": [["_TRANSPORT=kernel"]], "fields": ["MESSAGE"]}
```

- `groups`: 1..8 groups of 1..8 `FIELD=VALUE` terms, journalctl(1) matches: in a group,
  terms of one field are alternatives, different fields must all match; groups are
  alternatives (`+`). FIELD `A-Z 0-9 _`, VALUE `A-Z a-z 0-9 _ . : / @ % -` (max 64).
- `fields`: 1..32 fields the module reads (`--output-fields`). Also in every entry:
  `__CURSOR`, `__REALTIME_TIMESTAMP`, `__MONOTONIC_TIMESTAMP`, `_BOOT_ID`, `__SEQNUM`,
  `__SEQNUM_ID` (journalctl prints them always) and the fields any module matches on
  (needed to give an entry to the right module).
- Wrong JOURNAL -> `check_module()` error, module not loaded.
- argv: `journalctl -f -o json --output-fields=<union> -q --no-pager <start> <groups of
  all modules, joined by +>`. Binary checked like `run()` (root-owned, not g/o
  writable), same env, cwd `/`, own session.
- Start: `--since=@<collector start>`: lines written while the modules run `init()` are
  kept (a module's own start scan may see some of them again: it skips them).
- Restart after an exit: `--after-cursor=<last entry>`, never with `-n`. Backoff 1 s,
  doubling, max 60 s; 1 s again after 60 s up. A start from a cursor that exits without
  an entry (cursor refused) -> next start from the second of the last entry
  (`--since`), entries already given skipped by cursor (last 256).
- Each entry goes to every module whose groups match it. Buffer per module: 5000
  entries until its next collect, oldest dropped.
- `ctx.journal`: entries since the last collect, journal order, dicts as `-o json` prints
  them (str; byte array for non-UTF-8; list when a field repeats). Given once, also
  when `collect` raises.
- `ctx.journal_up`: journalctl runs. `ctx.journal_note`: what happened since the last
  collect, "" = nothing. Parts (joined by `; `): `N entries dropped (buffer full)`,
  `N bad line(s)` (not JSON, no or bad cursor, longer than 64 KiB),
  `journalctl exited (rc N: <stderr>)`, `journalctl restarted from the last entry` /
  `from time @T`, while down `<why>, restart in N s`.
- Read before each tick and while the collector waits (selectors on the pipe; pipe
  1 MiB, max 4 MiB per read). Collector exit: SIGTERM, 1 s, then SIGKILL.

## Audit events (`core/audit.py`)

For modules that read `_TRANSPORT=audit` entries from `ctx.journal`. JOURNAL fields:
`MESSAGE`, `_AUDIT_ID`, `_AUDIT_TYPE`, `_AUDIT_TYPE_NAME` (`_BOOT_ID` is always there).

- `Assembler().feed(entries, now)` -> complete events, journal order. Keep one in the
  module state. Event = the records with the same `_AUDIT_ID` and `_BOOT_ID`. Complete
  at PROCTITLE (or EOE); a user space record (1100-1199, 2100-2999) alone. No record
  for 2 s (no PROCTITLE ever: BPF without a syscall) or more than 1000 open -> given
  out as it is. Entries without id / type / message: counted in `bad`.
- `Event`: `kind` (SYSCALL, or the first record's name: `AUDIT1123`, `BPF`, ...),
  `get(field)` (decoded; from SYSCALL, else the single record, with the fields inside
  its `msg='...'`), `keys`, `argv` (EXECVE), `cwd`, `proctitle`, `first(name)` /
  `all(name)` (records: `type`, `name`, `message`, `ts`, `raw` fields).
- Decoding rules and host facts: docs/architecture.md, Security screen.
- Fixtures: tests/fixtures/security/ (2026-10-20 and 2026-10-25,
  `tests/journal_fixture.py`, masked), SHA256SUMS checked by the tests.

## Validation (`core/module.py`)

- `validate()` returns a new Snapshot: known keys only, defaults filled
  (`sev` ok, `width` auto, `unit` "", check `detail` "", check `n` 0). Input not changed.
- Missing required key or wrong type -> `InvalidSnapshot`. Also: duplicate panel id,
  table row cell count != columns, non-finite numbers, `v` not int 1 or 2,
  duplicate check key.
- Strings cut to 512 chars (last char `~`).
- Lists cut: panels 8, kv items 50, columns 12 (more = invalid), rows 200 (first kept),
  spark values 120 and events 100 (newest kept), checks 50 (worst kept).
- `check_module()`: NAME, INTERVAL (number >= 1.0), init / collect callable, collect
  takes `(state, ctx)`, close callable if present, JOURNAL valid if set. Else
  `ValueError`, module not loaded.

## Running commands (`core/run.py`)

```python
run(argv: list[str], timeout: float = 1.5) -> Result
# Result(rc: int, out: str, err: str, timed_out: bool, truncated: bool)
```

- `argv[0]` absolute path. No shell. Bad argv or timeout -> `ValueError` (bug in module).
- Binary must be a regular file, owned by root, not group/other writable
  (checked on the symlink target). Else not run, `rc=126`. Missing -> `rc=127`.
- env: `PATH=/usr/sbin:/usr/bin`, `LC_ALL=C`. stdin `/dev/null`. cwd `/`.
- Own session: timeout or limit kills the whole process group (`rc=-9`).
- timeout: wall time, max 30 s. Includes a process that closed its pipes but still runs.
- out / err: max 1 MiB each, decoded utf-8 with `errors="replace"`.
  Over limit -> killed, `truncated=True`, output kept up to the limit.
- Module decides what rc / timed_out / truncated mean.

## Display safety (`core/sanitize.py`)

- Core runs `display()` on every string before drawing: clean -> mask -> truncate.
- clean: tab and space separators -> space, anything else not `str.isprintable()` -> `?`
  (C0 / C1 controls incl. ESC and newline, DEL, bidi / zero-width format chars,
  line / paragraph separators, surrogates).
- Modules pass raw text. No escaping in modules.
- Public IP masking, key `m`, default on: addresses that are `is_global`
  and not multicast are masked (IPv4-mapped v6: checked on the v4 part).
  v4 -> `a.b.x.x`, v6 -> first 2 groups + `::x`.
  Private, CGNAT, link-local, loopback, broadcast, multicast shown as is.
- Mask before truncate, so a cut never shows a partial public IP.
  When unsure, mask (a 4-part version string may get masked).
- Masking is display only. Snapshot data stays unmasked. Exception: the detail overlay
  (see Screen) shows real IPs.
- Secrets (`mask_secrets`, 2026-10-25, commands box): values of `--password` `--passwd`
  `--token` `--secret` `--api-key` (`--flag value` / `--flag=value`), the password in
  `scheme://user:pass@`, values of `*PASSWORD=` `*PASSWD=` `*TOKEN=` `*SECRET=` -> `***`.
  `display()` masks them while mask is on, the detail too (real IPs, masked secrets).
  A module masks its own cells when a secret must never show (security: cmd cell).
  Display only: argv is readable in `/proc/<pid>/cmdline` and stored in audit + journal.

## Config

`/etc/sectop/config.toml`, read with `tomllib` (`core/config.py`).

- File and its directory: owned by root, not group/other writable. File opened with
  `O_NOFOLLOW`, must be a regular file, max 64 KiB. Directory must not be a symlink.
  Else `ConfigError`, refuse to start.
- Missing file or directory -> defaults.
- Strict: unknown tables or `[core]` keys -> error (catches typos).
- `[modules.<name>]`: `enabled` (bool, default true), `interval` (number >= 1.0,
  default module INTERVAL). Other keys are passed to the module `init()` as `cfg`.

```toml
[core]
mask_public_ips = true

[modules.firewall]
enabled = true
interval = 2.0
```

## State files (`core/statefile.py`)

JSON files between sectop's parts (docs/architecture.md, Privilege split).

- `/run/sectop/state.json`: collector -> UI. `{v, ts, interval, modules, feed, alerts}`:
  the module view, the events feed (newest first) and the active alerts
  (`core/alerts.py` active(), noise applied). `interval` = longest time between two
  writes outside a collect: the longest module interval, at most the 5 s heartbeat.
- `/run/sectop-net/<name>.json`: net unit -> collector, one command result
  (`core/netd.py`).
- Write: temp file in the same directory, `fchmod`, then rename over the old file
  (atomic): a reader never sees half a file. JSON compact, ASCII only, no NaN.
- Read: same file checks as config.toml (owner, not group/other writable, regular file,
  `O_NOFOLLOW`, directory owner), max 8 MiB.
- The UI never trusts the content: `check_state()` validates every field it draws.
  Panels pass the Snapshot rules again (core/module.py), alerts and feed events their
  own. Anything wrong -> the whole file is refused, the last good one stays.

## Noise list (`core/noise.py`)

`/etc/sectop/noise.toml`. Known, accepted alerts, kept out of the alert bar.

- Same file checks as config.toml. Missing -> no entries. Anything wrong -> refuse to start.
- Strict: only `[[noise]]` entries with `match`, `reason`, `expires`. Max 200.
- `match`: glob (fnmatch, case-sensitive) on the alert key `<module>/<check key>`. Module
  part literal (`[a-z0-9_]+`, no glob): one entry never covers all modules.
- `reason`: 1..200 chars.
- `expires`: TOML local date, required. Matches through that day (local time), then stops:
  the alert shows again.
- A noise alert is still tracked (count, last seen). `active()` marks it, never drops it.

```toml
[[noise]]
match = "firewall/out_ks:*"
reason = "kill switch NDP from the Proton client"
expires = 2026-12-31
```
