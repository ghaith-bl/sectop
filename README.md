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

## Modules

- firewall: hostfw mode + counters, kernel log (HFW-*), programs, peers (remote IPs),
  WireGuard (docs/modules/firewall.md)

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

- Test fixtures come from my own host. Mask public IPs before commit.
