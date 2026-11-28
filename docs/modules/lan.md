# Module lan (screen 1, firewall)

The network this laptop is on: is the router still the one I trust, does a second device
answer for it, does a second DHCP server hand out addresses. Two of the four red alerts
of step 11 (design 2026-11-24: tunnel leak, rogue DHCP, router MAC change, scan of this
laptop; the other two are Suricata rules, docs/modules/ids.md).
Code: modules/lan/__init__.py (collector), core/lan.py (reading, ids, accept),
core/idsd.py + core/eve.py (DHCP answers counted by sectop-ids.service).
Tests: tests/test_lan.py.

## What it can see (and cannot)

- On Wi-Fi the laptop sees its own traffic, broadcasts and the ARP / DHCP traffic that
  reaches it: not other devices' private traffic. An attacker on the same network who
  poisons this laptop's ARP cache changes the MAC this laptop has for the router: that
  is what this box watches.
- First visit of a network: nothing to compare with. The first MAC seen is trusted for
  this run only (trust on first use) until the network is accepted.
- Answers to other devices are seen only when they are broadcast (DHCP answers sent to
  a client's own MAC on Wi-Fi are not).

## Sources

All read only, every 5 s, in the collector (user sectop, no capability, no network):

| what | source |
|---|---|
| uplink + router | `/proc/net/route`: the IPv4 default route with the lowest metric, not on a tunnel (`wg*`, `tun*`) or a bridge (`virbr*`, `br-*` ...); subnet = the connected route on that device holding the router's address. Main table only: Mullvad's routes are in its own table |
| router MAC | `/proc/net/arp`: complete entries (ATF_COM), router address on the uplink device |
| own addresses | `/proc/net/fib_trie`: `/32 host LOCAL` |
| Wi-Fi name | nl80211 over generic netlink (`NL80211_CMD_GET_INTERFACE` dump, the question `iw dev` asks; no privilege needed; `AF_NETLINK` is allowed in sectop.service) |
| DHCP answers | `/run/sectop-ids/summary.json`, part `dhcp`: sectop-ids counts Suricata's DHCP records per interface + server (src_ip of the answer: Suricata writes DHCP records in packet direction), hour buckets, last 24 h. Suricata's DHCP logging (not `extended`) writes ACKs only: one per lease and renewal |

## Privacy

- A MAC address and a Wi-Fi name never leave the collector process: both go into
  HMAC-SHA256 with a local key, only the result is kept.
  - network id = HMAC(key, `net1` kind Wi-Fi-name subnet router-address); kind wifi /
    cable (no Wi-Fi name: cable).
  - router id = HMAC(key, `mac1` MAC)
- The box and the alerts show the first 8 hex digits of the network id, the router's
  address (a private address) and the device name. Never a MAC, never a Wi-Fi name.
- `/etc/sectop/lan.key`: 32 random bytes (hex), root:sectop 0640, made by the first
  accept. Without it the ids are made with a random key of this run (not kept).
- `/etc/sectop/lan-known.txt`: `<network id> <router id> <date>` lines, root:sectop
  0640. Both read with the config's file checks (root-owned, not group / other writable,
  no symlink), read again when they change.
- DHCP: the client's MAC, address, name and id in Suricata's record are never read
  (core/eve.py `parse_dhcp`).

## Rules

| what | sev | alert |
|---|---|---|
| router MAC not one accepted for this network | crit | `gw_changed:<id8>`, held 1 h after the last time it was seen |
| network not accepted: router MAC not the first one seen for it since sectop started | crit | same |
| the router's MAC also in the ARP table for another address on the uplink (one device answering for two) | crit | `mac_dup:<address>`, held 1 h |
| DHCP server on the uplink that is not the router | crit | `dhcp_rogue:<iface>:<server>`, event check (`at` = its newest answer), count = new answers, held 1 h |
| DHCP server on a VM bridge (`virbr*`) that is not this host | crit | same |
| network not accepted yet | info (row) | none |
| a Wi-Fi name / file / summary that cannot be read | warn (row, header) | none |

- Uplink DHCP: only answers since this network came up count (minus 60 s: the answer
  that brings a network up comes before its route). An answer from before (another
  network on the same device) is shown as `before this network (not checked)`.
- Fine besides the router (a Pi-hole, a second router): `[modules.lan] dhcp_ok =
  ["<address>"]` in `/etc/sectop/config.toml` (max 20).
- Router MACs seen per network are kept for this run of the collector (max 20 networks):
  the `MACs seen` row stays red for the run once an untrusted one was seen.

## Accept

On a network I trust (my own, or the owner agrees), when no attack is suspected:

    sudo ./install.sh --lan-accept

Root-owned code (`/usr/local/lib/sectop/bin/sectop-lan --accept`, core/lan.py accept())
reads the same sources, shows the network id, the router's address and whether this
router is already accepted, then asks `1 accept / 0 stop` (numbered, asked again on a
wrong answer, 3 tries). 1 = the pair (network id, router id) is added to the list; the
first accept makes the key. More than one router per network is fine (a replaced
router: accept the new one; the old one stays accepted). The collector reads the list
at its next collect.

## Boxes

| box | rows |
|---|---|
| lan | network (kind + id8), router (address, device, subnet), this laptop (its own address(es) in that subnet from fib_trie + the device; none found: info row), router MAC (accepted + date / not accepted yet / CHANGED), MACs seen this session (how many not trusted), same MAC (another address with the router's MAC), accept hint, DHCP 24 h (servers, rogue), notes |
| dhcp | servers that answered in the last 24 h: last, 24 h, hour, where (interface), server, is (the router / this host / fine (config) / NOT the router / NOT this host / before this network / another network) |

Header: `Wi-Fi <id8>: router accepted | DHCP <n> server(s)`; `CHANGED` / `ROGUE` when red.

## Limits

- Trust on first use: an attack already running at the first visit of a network is
  learned as normal for that run (and accepted, if I accept then).
- Same Wi-Fi name, same subnet, same router address on two networks: one network id.
  Each router accepted for it is fine there.
- No Wi-Fi name readable (nl80211 error, shown as a note): ids from subnet + router
  address only, so two networks with the same router address look the same.
- IPv4 only (IPv6 is off on Wi-Fi / cable in silverblue-privacy-hardening).
- Rogue DHCP that answers only clients' own MACs on Wi-Fi: not seen. Suricata
  `extended` DHCP logging would add offers (seen at this laptop's own connect even when
  the rogue server loses the race), with more data about other devices: not on.
