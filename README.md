# sectop

Terminal security dashboard for my Silverblue workstation.
Python 3 stdlib only (curses, tomllib). No third-party packages.

Status: v1 in progress, not usable yet.

## Design

- core: config, module registry, safe subprocess runner, sanitizer, curses renderer
- modules: collectors, return a JSON-serializable Snapshot
  (see docs/module-interface.md)
- v1 runs as root. Later: collectors in a hardened root service, UI unprivileged
- public IPs masked by default, toggle with key m

## Modules

- firewall: hostfw mode + counters, kernel log (HFW-*), connections, WireGuard
  (docs/modules/firewall.md, planned)

## Run (dev)

    sudo python3 -m core.app

## Tests

    python3 -m unittest discover -s tests

## Notes

- Test fixtures come from my own host. Mask public IPs before commit.
