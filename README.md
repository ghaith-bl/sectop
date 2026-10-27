# sectop

Terminal security dashboard for my Silverblue workstation.
Python 3 stdlib only (curses, tomllib). No third-party packages.

Status: in progress (phase 3: privilege split, docs/architecture.md).

## Design

- core: config, module registry, safe subprocess runner, sanitizer, alert engine + noise list,
  collector (service), state file, screens, curses renderer (UI)
- screens: 1 firewall, 2 security, 3 processes. Each uses the whole terminal
  (docs/architecture.md)
- modules: collectors, return a JSON-serializable Snapshot
  (see docs/module-interface.md)
- collector = non-root service, UI = my user, no sudo. Neither runs as root
  (docs/architecture.md, Privilege split)
- alert bar on every screen (alert engine, warn / crit), key a acks what it shows
- public IPs masked by default, toggle with key m. The detail view (enter) shows them
- w: whois (RDAP) of the selected IP, by a socket service with its own dynamic user
- c: program card, every row of every screen that belongs to the selected row's program
  (firewall flows, root commands, logins, SELinux denials, logs)

## Modules

- firewall: hostfw mode + counters, kernel log (HFW-*), programs, peers (remote IPs),
  WireGuard (docs/modules/firewall.md)
- security: commands run as root after a login (sudo, pkexec, su, setuid programs), from
  the audit records in the journal, rated by `/etc/sectop/watch.toml` (crit / warn /
  info); auth box: sudo / su / unlock / polkit passwords, faillock locks, sudo refusals
  (docs/modules/security.md); kernel box: new taint bits, module loads / removals /
  blocked loads, SELinux denials, kernel log errors / warnings, new USB devices; logs
  box: journal errors / warnings and audit file watches grouped, noise rows dim
- posture: is my hardening baseline still true, checked every 5 min against
  `/etc/sectop/posture.toml` (SELinux, audit, firewalld, accounts, sysctls, LUKS,
  system image, listeners, ...): pass / fail / accepted / unknown
  (docs/modules/posture.md)

## Screen legend

Severity column (first column of every table, kv box and the events box):

| glyph | severity |
|---|---|
| `!!` | crit |
| `!` | warn |
| `i` | info |
| (empty) | ok |

The glyph says the severity without color (WCAG 2.2, 1.4.1 Use of Color). Colors are the
same on every screen:

| color | meaning |
|---|---|
| red, bold | crit |
| yellow | warn |
| cyan | info |
| magenta | unknown (no data, module not loaded) |
| plain | ok |
| blue | allowed (firewall verdict) |
| soft red | only blocked lines (a program or peer the firewall stopped) |
| soft yellow | blocked by hostfw (enforce) |
| green | healthy state (table loaded, tunnel up, ...) |
| dim | sudo / pkexec / su without a root command (sudo -k, sudo -l, denied sudo) |

Tones (blue, soft red, soft yellow, green, dim) carry a meaning, not a severity: crit
stays red, warn adds bold. 256-color terminal: soft tones, else the 8 basic colors.

- Time in a row: age (`12s` `4m` `2h` `3d`); the detail (enter) shows the full local
  time. Paused: ages stay as they were at the pause.
- Table header: bold + underlined. Numbers and ages right-aligned.
- `[title]` in reverse: the focused box. Reverse line: the selected line. Dim: acked or
  held alerts, keys, hints, launch rows (above).
- Secrets in a command line (`--password` / `--token` / ... values, `user:pass@` in URLs,
  `*_PASSWORD=` / `*_TOKEN=` / `*_SECRET=`): `***` in rows always, in the detail while
  mask is on (key m shows them there).
- Top border right: `/ <filter>  <shown> of <all>`, detail search, `first-last/total`
  when the box is cut.

## Install

    sudo ./install.sh            # git HEAD -> /usr/local/lib/sectop, users, units
    sudo ./install.sh --remove

Parts: sectop-net.service (nft / wg, CAP_NET_ADMIN only), sectop.service (collector),
sectop-whois.socket (RDAP), UI as my user. See docs/install.md.

## Run

    sectop [SCREEN]     # firewall | security | processes | 1-3

No sudo: collector, net unit and UI refuse to run as root.

## Tests

    python3 -I -m unittest discover -s tests -t .

## Notes

- Test fixtures come from my own host, made with tests/journal_fixture.py (journalctl
  -o json -> fields kept, cursors renumbered, public IPs, MACs, names, ids, USB serials,
  wifi names, NetworkManager profile uuids, LUKS uuids masked). Usage in the file.
  Check the result before commit.
- Hand-written test lines use fake or documentation values only (MACs 02:00:00:...,
  IPs 192.0.2.x / 198.51.100.x / 203.0.113.x), never values copied from my host.
