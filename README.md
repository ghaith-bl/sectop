# sectop

Terminal security dashboard for my Silverblue workstation.
Python 3 stdlib only (curses, tomllib). No third-party packages.

Status: in progress (phase 2: alert engine, docs/architecture.md). Runs in dev mode.

## Design

- core: config, module registry, safe subprocess runner, sanitizer, alert engine, screens,
  curses renderer
- screens: 1 firewall, 2 security, 3 processes. Each uses the whole terminal
  (docs/architecture.md)
- modules: collectors, return a JSON-serializable Snapshot
  (see docs/module-interface.md)
- v1 runs as root. Phase 3: non-root collector service, UI as my user
  (docs/architecture.md, Privilege split)
- public IPs masked by default, toggle with key m. The detail view (enter) shows them
- w: whois (RDAP) of the selected IP, in a child process as user nobody

## Modules

- firewall: hostfw mode + counters, kernel log (HFW-*), peers (remote IPs), WireGuard
  (docs/modules/firewall.md)

## Run (dev)

    sudo python3 -B -m core.app [SCREEN]     # firewall | security | processes | 1-3

`-B`: no root-owned `__pycache__` in the repo.

## Tests

    python3 -I -m unittest discover -s tests -t .

## Notes

- Test fixtures come from my own host. Mask public IPs before commit.
