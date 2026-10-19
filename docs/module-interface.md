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

def init(cfg: dict) -> object: ...
def collect(state: object) -> dict: ...   # returns Snapshot
def close(state: object) -> None: ...     # optional
```

- `init`: once at start. `cfg` = `[modules.<name>]` table (may be empty).
  Returns module state (any object). Raise -> module disabled, error shown.
- `collect`: every INTERVAL. Returns Snapshot. Raise -> see Errors.
- `close`: on exit, if defined.
- v1: single thread. No threads, no long-lived child processes in modules.
  Follow-style sources (journal) are polled with a cursor.
- External commands only via `core.run.run()`.
- Module keeps its own history (spark series, counter deltas) in state.

## Snapshot (v1)

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
| v | int | 1 |
| status | str | ok, info, warn, crit, unknown |
| summary | str | one line, module header |
| panels | list | Panel, max 8 |
| events | list | Event, new since last collect only, max 100 |

- Only dict, list, str, int, float, bool, None.
  Core checks with `json.dumps`. Needed for the later split
  (root collector service -> unprivileged UI).

## Severity

`ok < info < warn < crit`. `unknown` = no valid data.
Module sets status. Core overrides only for stale / error (see Errors).

## Panels

Common keys: `id` (unique in module), `title`, `type`. `sev` optional, default ok.
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

Row `detail` optional: extra k / v pairs shown on `enter` under the cells (max 40).
Row `id` optional (str): stable key of the row (e.g. a grouped flow). The cursor follows
it when the row moves or its text changes. Not shown.

`tone` optional on kv items and table rows: `plain`, `red`, `blue`, `yellow`, `green`.
A color for meaning (a verdict, a healthy state), not a severity. See Screen (color).

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

## Errors (`core/app.py`)

- `collect` raises (incl. `SystemExit`) or returns an invalid Snapshot -> module state error.
  Header shows exception type + message. Last good panels kept, marked stale.
  Other modules unaffected. `KeyboardInterrupt` and SIGTERM stop sectop.
- 3 errors in a row -> interval x2, each further error x2 again, max 60 s
  (never below the configured interval). Reset on first success.
- Last good Snapshot older than 3 x interval (configured, not backed off) -> status unknown.
- `collect` slower than interval -> marked slow, next run a full interval after it ended.
  Keep `run()` timeouts below interval.
- Module not loaded (registry error) -> status unknown, header shows the error.
  Disabled -> shown as OFF.

## Screen (`core/render.py`, `core/screens.py`, `core/ui.py`)

- Screens are static in `core/screens.py`: name, modules (box order), events box yes / no,
  note while empty, box focused at start. Each screen uses the whole terminal.
- Start screen: `sectop [SCREEN]`, name or number, default 1. Unknown -> usage, rc 2.
- Lines, top to bottom:
  - tabs, PAUSED, mask state, clock
  - alert bar: modules on any screen with status crit, warn or unknown, worst first.
    Not while waiting for the first collect. (Phase 2: alert engine.)
  - one header per module on this screen: `[STATUS] name  summary  | flags`
  - box grid
  - key help
- Box grid: one box per panel, in module order, then the events box.
  - Width: a box joins the row while its least width fits, extra width shared in the row.
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
  - Table header stays, rows scroll. Cut box: title shows `first-last/total`.
  - Stale module: `(stale)` in each box title.
- Focus: focused title `[title]` in reverse. Start: screen `focus`, else first table /
  events box, else first box. Gone -> same rule.
- Cursor: each box has a selected line, shown in reverse in the focused box; the box
  scrolls to keep it visible. Line 0 follows the newest line. Below line 0 the cursor
  stays on the same row when new lines arrive above it: row `id`, else the same text
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
  title says `real IPs shown` (screenshots of the detail show them).
  Opening it pauses; closing resumes (unless paused before).
- Pause (`p`): the screen keeps the view from the moment of pausing, collecting goes on.
  Resume shows the current view.
- Keys: `1-9` screen; `tab` / right / `l` next box, `shift-tab` / left / `h` previous box;
  down / up / `j` `k` line; `space` `PgDn` / `PgUp` page; `g` `G` / `Home` `End` first / last;
  `enter` detail; `/` filter; `Esc` clear filter; `p` pause; `m` mask; `?` help; `q` quit.
  In help / detail: `Esc` `q` `enter` `?` close, line keys scroll. Esc delay 25 ms.
- Redraw: full after a collect (not while paused) or a key (incl. resize); between those
  only the clock line, once a second.
- Every string goes through `display()`. Width counted in terminal cells (wide chars = 2).
- Color: severity first. ok plain; info, warn, crit, unknown colored. With a `tone`:
  the tone color replaces ok / info / warn, warn adds bold, crit always stays crit
  (bold red). 256-color terminal: soft tones (xterm 210 red, 111 blue, 222 yellow,
  114 green), crit 196. Else the 8 basic colors; no color support: plain.
- Box lines: Unicode box drawing (U+2500 block), written as escapes in the source.

## Validation (`core/module.py`)

- `validate()` returns a new Snapshot: known keys only, defaults filled
  (`sev` ok, `unit` ""). Input not changed.
- Missing required key or wrong type -> `InvalidSnapshot`. Also: duplicate panel id,
  table row cell count != columns, non-finite numbers, `v` not int 1.
- Strings cut to 512 chars (last char `~`).
- Lists cut: panels 8, kv items 50, columns 12 (more = invalid), rows 200 (first kept),
  spark values 120 and events 100 (newest kept).
- `check_module()`: NAME, INTERVAL (number >= 1.0), init / collect callable,
  close callable if present. Else `ValueError`, module not loaded.

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
