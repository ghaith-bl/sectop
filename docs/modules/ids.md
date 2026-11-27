# Module ids (screen 1, firewall)

Suricata alerts from eve.json: what the IDS saw on the uplink and the VM bridges.
Code: modules/ids/__init__.py. Tests: tests/test_ids.py (real eve lines in
tests/fixtures/ids/eve-local-rules.json).

## Source

- `/var/log/suricata/harden-ids/eve.json` (silverblue-privacy-hardening section ids,
  suricata:suricata 0640). Option `path` in `[modules.ids]` for another file.
- Read by the collector through group `suricata`: install.sh writes
  `/etc/systemd/system/sectop.service.d/ids.conf` (`SupplementaryGroups=suricata`, added
  to the unit's list) only when the group exists; no group = no drop-in (an unknown group
  stops the unit, 216/GROUP). Install Suricata later: run install.sh again.
- Only `event_type` alert is shown; other types (anomaly, dhcp) are counted in the header.
- Kept open between collects. logrotate rename: the old file is read to its end, then
  the new one from its start. Truncated: from the start. At start: the last 4 MiB only.
  Max 2 MiB per collect; lines over 64 KiB and lines that are not a JSON object: skipped.
- Symlink at the path: refused (O_NOFOLLOW). Not readable: header + warn check
  `ids:no_access`. No file: header "no eve.json", status info, no check.

## Boxes

| box | rows |
|---|---|
| ids | last 24 h, one row per rule (sid) + source address: last, n, kind, signature, from, to (newest destination, `+N` more). Worst first, then newest |
| eve | the newest 50 alert lines, newest first |

`kind` = the hardening rule's `metadata: harden <kind>`, `et` for ET Open rules. Detail
(`enter`): signature, sid, rule (local / ET Open), kind, severity (ET), category, from,
to (up to 5), proto / app, count, first, last. `w` on a row: whois of the source.

## Severity

| alert | sev |
|---|---|
| harden leak, scan (tunnel leak, scan of this laptop) | crit (alert bar, red) |
| harden probe, vm_lan, vm_probe | warn |
| ET: rule severity 1 or `signature_severity` Critical | crit |
| ET: severity 2 or Major | warn |
| ET: other | info (row only, no check) |

## Checks

One event check per group with new lines (crit / warn), key `ids:<sid>:<source>`, `at` =
newest line, so lines read again at start (backlog) never open an alert older than its
hold (core/alerts.py). n = new lines since the last collect.
