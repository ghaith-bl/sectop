# posture module

Screen 2, below the security boxes. `modules/posture/`. Phase 4 step 6 (2026-10-26).
Is my baseline (silverblue-cis-hardening) still true. Design: docs/architecture.md,
Security posture.

## Source

- Policy `/etc/sectop/posture.toml` (`policy.py`), defaults `deploy/posture.toml`, put
  there by install.sh when missing, never over mine (log `kept` when mine differs). Same
  file checks as config.toml (root-owned, not group / other writable, no symlink). Read
  once in init: `sudo systemctl restart sectop.service` after a change. Missing: no
  checks, summary `no posture.toml`. Bad file: init fails, module off, header says why.
- Kinds (`checks.py`): fixed code. The policy picks a kind, its file / unit / values,
  the sev and the ref. No commands in the policy.
- Files where a file exists. Commands only where there is none, fixed argv, run as user
  sectop (core/run.py): `systemctl show` (one call for all units), `systemctl
  list-units --state=failed`, `firewall-cmd --get-default-zone`, `nmcli` (1 + one per
  profile, max 32, per check), `hostnamectl --json=short`, `resolvectl status
  --no-pager`, `rpm-ostree status --json` (once a day, cached). WireGuard
  listen-port: the net unit's file (`wg show <tunnel> listen-port`, every 1 s).
- Audit counts: journal CONFIG_CHANGE (1305) of this boot. One scan in init
  (`journalctl -b _TRANSPORT=audit _AUDIT_TYPE=1305`, 5 s), then core's follower:

      JOURNAL = {"groups": [["_TRANSPORT=audit", "_AUDIT_TYPE=1305"]],
                 "fields": ["MESSAGE", "_AUDIT_TYPE"]}

  The follower starts at the collector start, the scan runs in init a moment later:
  entries the scan saw are skipped by cursor (cursors kept 1 h, max 20000).
- Every 300 s (INTERVAL). Commands 5 s timeout each, rpm-ostree 15 s. Time of one
  collect on my host: not measured yet (check after install).
- Readable as user sectop in the sectop.service sandbox: host check 2026-10-26 (nsenter
  into the unit as sectop). Not readable, so not checked: `/etc/firewalld/firewalld.conf`
  (dir 0750: zone from firewall-cmd instead), `net.core.bpf_jit_harden` (0600),
  `/etc/shadow` content (stat only), sudoers, auditd.conf, `auditctl -l`.

## Box

Cols: check, result, have, want. Full width. Title:
`posture <rows>  (<n> fail, <n> unknown, <n> accepted; every 5 min, last <time>)`.
Summary `pass <n> | fail <n> | unknown <n> | accepted <n>`.

- result: `pass`, `fail`, `accepted` (fail with a ref), `unknown` (could not read: the
  error is `have`).
- Row sev: fail = the check's sev, unknown = warn, accepted / pass = ok. accepted: tone
  dim.
- Order: fail crit, fail warn, fail info, unknown, accepted, pass; then policy order.
- Detail: why, kind, source, ref, kind lines (differs, missing, not allowed, unread ...),
  checked.
- Alerts (decided 2026-10-25: red only): a crit fail without ref -> check `<id>`
  (alert `posture/<id>`), title `<why>: <have>`. Open while it fails (each collect
  reports it again). warn / info: row color only.
- A kind that raises (bug): that row unknown, the others go on.

## Policy

    [[check]]
    id = "selinux-enforcing"        # a-z 0-9 -, 1..32, unique: alert key, noise match
    kind = "file"
    sev = "crit"                    # crit | warn | info: when it fails
    why = "SELinux enforcing now"   # 1..120 printable ASCII
    path = "/sys/fs/selinux/enforce"
    want = "1"
    # ref = "..."                   # accepted deviation: dim, no alert (1..120)

| kind | keys | pass when |
|---|---|---|
| file | path, want, key?, op? | value of `key = v` / `KEY=v` (last wins, `#` `;` comments) or the first line, op `=` `!=` `>=` `<=` `in` (want `a` or `b` written `a|b`). Missing file: fail |
| lines | path, want (list) | every line is in the file (spaces folded, `#` lines not counted) |
| sysctl | values (table) | every `/proc/sys` value = want. Unreadable: unknown |
| cmdline | want (list) | every word in `/proc/cmdline` |
| units | units (table unit = state) | active / inactive / failed: ActiveState; masked / enabled / disabled / static: UnitFileState |
| failed-units | - | `systemctl list-units --state=failed` empty |
| listeners | allow (list), wireguard?, tunnel_owner? | every TCP listener and unconnected UDP socket outside loopback matches an allow glob `<tcp or udp> <addr>:<port>` (IPv6 `[addr]`), or is `udp 0.0.0.0` / `udp [::]` on the listen-port of the wireguard tunnel (`wg show <tunnel> listen-port` from the net unit, core/netd.py: wg needs CAP_NET_ADMIN). Tunnel down or net unit file missing: no port allowed, the reason in the detail. tunnel_owner (needs wireguard): no kernel port (userspace tunnel, tun device: Mullvad DAITA) and the tunnel interface exists -> `udp 0.0.0.0` / `udp [::]` sockets owned only by this program are the tunnel's. Detail names the program of every socket (`ss -Htuln --cgroup`, innermost unit, no CAP_SYS_PTRACE; none if ss shows no cgroup); ss error: a `programs` line, check still runs |
| taint | want (letters) | `/proc/sys/kernel/tainted` letters all in want (fewer is fine) |
| luks | path | the mount's device-mapper device (or one under it: LVM) has uuid `CRYPT-LUKS*`. Matched by dm name (`/sys/block/dm-*/dm/name`): the sandbox has no `/dev/mapper` (PrivateDevices) |
| secureboot | - | efivar SecureBoot value 1 (4 bytes attributes, then the value) |
| lockdown | want | `/sys/kernel/security/lockdown` `[mode]` in want |
| audit-rules | want (number) | add_rule - remove_rule this boot >= want |
| audit-enabled | - | no `audit_enabled=0` this boot |
| uid0 | want (list) | the accounts with UID 0 (`/etc/passwd`) = want |
| group | group, want (list) | every member is in want (`[]` = must be empty) |
| perms | path, mode, owner | stat: no mode bit beyond mode, owner = `user:group` |
| ostree-unlocked | - | no overlay mounted on `/usr` (`ostree admin unlock`, `rpm-ostree usroverlay`) |
| ostree-staged | - | no `/run/ostree/staged-deployment` |
| ostree-age | max_days | booted commit not older (rpm-ostree, once a day) |
| ostree-gpg | - | no remote in `/etc/ostree/remotes.d/*.conf` with gpg-verify off (default on) |
| firewalld-zone | want | `firewall-cmd --get-default-zone` = want |
| wifi-ipv6 | want | every wifi profile ipv6.method = want. Never names: UUIDs in the detail |
| nm-props | types (list), props (table property = want) | every NetworkManager profile of these types has each property in want (`a|b`, `""` = empty). One `nmcli -g` per profile. UUIDs in the detail |
| mac-local | - | every physical link that is up (`/sys/class/net/<if>/device`, type 1, operstate up) has a locally administered MAC (bit 0x02 of the first byte). The address is never shown |
| dns-servers | allow (list of links) | `resolvectl status`: DNS servers only on the allowed links, none global (`DNS=`), no fallback list. No server anywhere (tunnel down): pass. No `Global` section: unknown |
| hostname | want | `hostnamectl --json=short`: Hostname, StaticHostname, DefaultHostname = want, PrettyHostname empty. Not `/proc/sys/kernel/hostname`: sectop.service has `ProtectHostname=yes` (its own copy from its start) |

Limits: 100 checks, 64 items per list / table, paths `A-Z a-z 0-9 _ . @ % + : / -`
without `..`.

## Defaults (deploy/posture.toml)

From silverblue-cis-hardening (harden-workstation.sh, docs/deviations.md,
docs/verification.md) and CIS / RHEL STIG where the hardening follows them. Agreed
2026-10-26.

    crit  SELinux enforcing now; audit=1 + backlog in kernel args; audit not switched
          off; auditd, firewalld running; firewalld zone drop; only root UID 0; wheel =
          me; /var on LUKS; system image not unlocked; ostree remotes verify; listeners;
          Secure Boot on; no hardware MAC on a link that is up; hostname localhost
    warn  SELinux config enforcing + targeted; audit rules >= 70; journald audit
          socket; su closed (sugroup empty, pam_wheel); faillock 5 / 900 s; pwquality 14
          / 4 classes; shadow, gshadow, passwd, group perms; sysctls of
          90-hardening.conf (kernel, IPv4, IPv6); no taint; CIS module blocks;
          lockdown integrity; crypto policy not LEGACY; masked units;
          no failed units; core dumps off; journal persistent; GNOME locks; wifi IPv6
          off; booted system <= 14 days; random MAC config; dhcp-send-hostname 0 on
          every Wi-Fi / cable profile; LLMNR + mDNS off; fallback hostname kernel arg;
          DNS servers only on the tunnel; no DNS in Wi-Fi / cable profiles; chronyd
          running; chrony NTS only (authselectmode require, minsources 2)
    info  update staged, waiting for a reboot

- hostfw mode / boot mode: not here, the firewall screen checks them (alerts there).
- Listeners (host 2026-10-26, `ss -Htuln`): loopback only for resolved (127.0.0.53 /
  .54:53) and chronyd (:323); libvirt default network dnsmasq on 192.168.122.1:53 (tcp,
  udp) and DHCP 0.0.0.0:67 bound to virbr0; the VPN tunnel's WireGuard (wg0-mullvad)
  on 0.0.0.0 / [::] with a port that can change on every connect (`wg show all
  listen-port`): allowed by the port the net unit reads, not by a port glob (a glob
  would let any program on any UDP port pass). Not by "kernel socket" either: checked
  2026-10-26, WireGuard's sockets have an inode in /proc/net/udp (51638, 51639) like any
  other.
  dnsmasq answers only its own network (libvirt uses --bind-dynamic since
  CVE-2012-3411); LAN reach to 192.168.122.1 is closed by the firewalld drop zone and
  hostfw.
- wifi IPv6: NetworkManager makes every new wifi profile `ipv6.method auto`, and
  NetworkManager.conf(5) `[connection]` defaults cannot change that (ipv6.method is not
  in its list). Host 2026-10-26: 4 of 6 profiles were auto (fixed with nmcli); the
  check catches the next new network.
- Network identity (2026-10-27, silverblue-cis-hardening `netprivacy`). Host checks
  (sandbox, user sectop): config files readable; links `type=1`, the one that is up has
  bit 0x02 set, the hardware one (down) not; `hostnamectl --json=short` gives the names,
  PrettyHostname `null`; `nmcli -g ipv4.dhcp-send-hostname` prints `0` for no, `-1` for
  the default. NetworkManager 1.56.1 ignores the global dhcp-send-hostname default (tested
  with tcpdump), so a new network's profile (-1) fails `dhcp-no-hostname` (warn, no
  alert: hostname `localhost` is not sent at all) until netprivacy runs again. crit only
  where a network could see me: hardware MAC, a real hostname.
- Secure Boot, lockdown, taint: step 9 done 2026-10-26 (silverblue-cis-hardening:
  akmod-nvidia removed, akmods MOK key deleted, Secure Boot on, lockdown integrity,
  taint 0). The refs are gone: Secure Boot off is crit now (it can only be switched off
  in the firmware, behind the admin password). Lockdown stays warn: it follows Secure
  Boot, one alert is enough. Taint want "" (any bit = warn; new bits since sectop start
  are the kernel box's crit).
- DNS only in the tunnel (2026-10-31, silverblue-cis-hardening `netprivacy`). Host:
  2 profiles had a static resolver, the others took the router's from DHCP. resolved
  used the uplink server while the tunnel had none (reconnect): uid 990 to port 53 on
  the uplink, blocked by hostfw (`out_dns`). Two checks: `dns-tunnel-only` (live, what
  resolved uses now) and `nm-no-dns` (every profile, also networks not joined now; a new
  network fails until netprivacy runs again). warn: hostfw blocks it. `resolvectl
  status` as user sectop in the sandbox: not checked on the host yet. "Current DNS
  Server:" and "Fallback DNS Servers:" lines are not indented.
- Time (2026-10-31, silverblue-cis-hardening `time`): chrony NTS only, Netnod + PTB.
  Config checked, not the live state: `chronyc -N authdata` needs root (501 Not
  authorised as a user), `chronyc sources` shows no authentication. `authselectmode
  require` is the guard: a source without NTS is never selected.
