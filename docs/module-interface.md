# Module interface

sectop v1. Core loads modules, calls them on a timer, renders their output.
Modules collect data only. They never draw.

## Layout

- `modules/<name>/__init__.py`
- Registered in `core/registry.py`. Static list, no dynamic loading from config paths.

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
 "rows": [{"cells": ["firefox", "1000", "10.2.0.1", "53", "proton0"], "sev": "ok"}]}
```

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

## Errors

- `collect` raises or returns an invalid Snapshot -> module state error.
  Header shows exception type + message. Last good panels kept, marked stale.
  Other modules unaffected.
- 3 errors in a row -> interval x2, max 60 s. Reset on first success.
- Last good Snapshot older than 3 x INTERVAL -> status unknown.
- `collect` slower than INTERVAL -> marked slow. Keep `run()` timeouts below INTERVAL.

## Validation (`core/module.py`)

- Missing required key or wrong type -> invalid Snapshot.
- Unknown keys ignored.
- Strings cut to 512 chars, lists cut to the limits above.

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
- Masking is display only. Snapshot data stays unmasked.

## Config

`/etc/sectop/config.toml`, read with `tomllib`.
Must be owned by root and not group/other writable, else refuse to start.
Missing file -> defaults.

```toml
[core]
mask_public_ips = true

[modules.firewall]
enabled = true
interval = 2.0
```
