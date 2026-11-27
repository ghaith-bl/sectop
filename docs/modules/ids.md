# Module ids (screen 1, firewall)

Suricata alerts: what the IDS saw on the uplink and the VM bridges, counted exactly.
Code: modules/ids/__init__.py (collector), core/idsd.py + core/eve.py (sectop-ids.service).
Tests: tests/test_ids.py (real eve lines in tests/fixtures/ids/eve-local-rules.json).

## Source

- `/var/log/suricata/harden-ids/eve.json` (silverblue-privacy-hardening section ids,
  suricata 0640), read by `sectop-ids.service` only: system user sectop-ids, group
  suricata (read only, `ProtectSystem=strict`), primary group sectop-feed, no
  capabilities, no network. Its own user, not suricata: it can never write Suricata's
  files or rules (NIST SP 800-53 AC-6).
- install.sh enables and starts the unit only when group suricata exists (an unknown
  group in `SupplementaryGroups=` stops a unit, 216/GROUP); without it the unit is off.
  Install Suricata later: run install.sh again. The collector is not in group suricata
  (an older install's drop-in `sectop.service.d/ids.conf` is removed).
- Every alert line is counted: no `limit` / `threshold` inside Suricata for this, and
  eve.json stays as Suricata wrote it (NIST SP 800-53 AU-7 b: reduction never alters the
  original records; SP 800-92 event aggregation: one entry with its count). Decision
  2026-11-27 (Ghaith): one alert per rule + source per hour, with the count.
- Counts per rule (sid) + source address in clock-hour buckets: `24 h` = the last 24 clock
  hours, `hour` = since hh:00. At start: yesterday's file (`eve.json.1`, logrotate
  `delaycompress`) and today's from their start (max 64 MiB each), so a restart keeps the
  24 h counts. Then followed live (kept open; logrotate rename: the old file to its end,
  then the new one from its start; truncated: from the start; 4 MiB per read; lines over
  64 KiB and lines that are not a JSON object: skipped and counted).
- Summary: `/run/sectop-ids/summary.json` (0640 sectop-ids:sectop-feed, write + rename,
  at least every 30 s). The collector reads it when it changed, checks every field (owner,
  mode, size 1 MiB, types, lengths, addresses), and shows "stale" (warn check
  `ids:stale`) when it is older than 120 s. Max 200 groups (the leak / scan ones kept
  first, pushed-out groups counted), 50 tail lines.
- Symlink at eve.json: refused (O_NOFOLLOW). Not readable: header + warn check
  `ids:no_access`. No file: "no eve.json", status info. No summary: "no ids summary".

## Boxes

| box | rows |
|---|---|
| ids | `alerts last 24 h, per rule + source`: last, 24 h, hour, rule (local / ET Open), sev (the rule's own: signature severity + priority p1..p4), type (local kind in words, or the ET category), signature, from, to (newest destination, `+N` more). Worst first, then newest |
| eve | `last N alert lines (any age, oldest ... ago)`: the newest 50 lines, newest first |
| ids key | what red / yellow / white mean, how counts and alerts work, the ET groups |

Detail (`enter`): signature, sid, rule, ET group (the word after `ET` and what it
means), type, kind, rule severity, colour, target, confidence, from, to (up to 5), proto
/ app, 24 h, this hour, first, last. `w` on a row: whois of the source.

## Colour (decision 2026-11-27)

| alert | colour |
|---|---|
| local leak, scan (tunnel leak, scan of this laptop) | red (crit, alert bar) |
| local probe, vm_lan, vm_probe | yellow (warn) |
| ET: `signature_severity` Critical, or priority 1 not marked low | red |
| ET: marked Informational / Minor, no dangerous type, not priority 1 | white (info, row only, no alert) |
| ET: a dangerous type (category or ET group: malware, trojan, C2 / CNC, exploit, attack, credential, phishing, coin mining, DROP / CINS lists ...), priority 1 / 2, or Major | yellow |
| ET: other | white |

Example: sid 2027758 `ET DNS Query for .cc TLD` (host 2026-11-27: category Potentially Bad
Traffic, priority 2, signature_severity Informational) = white.

## Checks

One event check per group with new lines (red / yellow), key `ids:<sid>:<source>`,
`at` = newest line, `hold` 3600 s: within the hour new lines add to the same alert's
count (core/alerts.py), no new alert. n = the new lines. A summary read again opens
nothing older than the hold.
