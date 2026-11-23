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
- `"@admin"` in a want list (groups wheel, sectop, mullvad; 2026-11-05 account split):
  install.sh writes the sudo user there. The repo file names no user. Group checks
  `sectop-group` (admin only), `sectop-feed` (no members), `mullvad-group` (admin only):
  warn.
- Kinds (`checks.py`): fixed code. The policy picks a kind, its file / unit / values,
  the sev and the ref. No commands in the policy.
- Files where a file exists. Commands only where there is none, fixed argv, run as user
  sectop (core/run.py): `systemctl show` (one call for all units), `systemctl
  list-units --state=failed`, `firewall-cmd --get-default-zone`, `nmcli` (1 + one per
  profile, max 32, per check), `hostnamectl --json=short`, `resolvectl status
  --no-pager`, `rpm-ostree status --json` (once a day, cached), `journalctl -b -o json
  --output-fields=MESSAGE -n 400 _SYSTEMD_UNIT=<unit>` (audit-rules.service,
  auditd.service: the unit's own lines this boot; `_SYSTEMD_UNIT` is set by journald, a
  process outside the unit cannot write such a line). WireGuard
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
| file | path, want, key?, op?, sep? | value of `key = v` / `KEY=v` (last wins, `#` `;` comments), with sep `"space"` (needs key) of `KEY v` (login.defs), or the first line, op `=` `!=` `>=` `<=` `in` (want `a` or `b` written `a|b`). Missing file: fail |
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
| audit-rules | want (number), setuid_key?, setuid_rules? (1 or 2, default 1) | add_rule - remove_rule this boot >= want. With setuid_key: rules of the other keys >= want, and the rules with that key = setuid_rules x the setuid / setgid files under /usr (regular files, one file system, like `find /usr -xdev -type f -perm /6000`; scanned once per sectop start, /usr only changes with a new deployment = a reboot). Detail: counts, a fix hint, the files. /usr not readable: unknown |
| audit-enabled | - | no `audit_enabled=0` this boot |
| audit-locked | - | last `audit_enabled` set this boot is `2` (`-e 2`) |
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
| fwupd-reports | path (directory) | no `*.conf` in it has an active `ReportURI` / `SecurityReportURI` or `AutomaticReports` / `AutomaticSecurityReports` = true. No directory (no fwupd): pass |
| hostname | want | `hostnamectl --json=short`: Hostname, StaticHostname, DefaultHostname = want, PrettyHostname empty. Not `/proc/sys/kernel/hostname`: sectop.service has `ProtectHostname=yes` (its own copy from its start) |
| audit-load | - | audit-rules.service ran this boot (`ExecMainStartTimestampMonotonic` not 0), `Result=success`, `ExecMainStatus=0`, and none of its own journal lines this boot has the word `error`. Detail: result, the error lines (time + text), a fix hint |
| auditd-logging | - | auditd.service's own journal lines this boot: no `suspending logging` / `logging suspended` / `Could not reopen a log after resume` after the last `Init complete, auditd` or `resume logging` line. Detail: the space / write-error lines |
| setuid-known | path | every setuid / setgid file under /usr (the `audit-rules` scan, once per start) is on the list in path (root-owned, not group / other writable, no symlink: core/config.py `read_file`; one path per line, `#` comments; read every collect). Not on it: fail, `new` lines + fix hint. On it, not under /usr: `gone` lines only. No list: fail. Unsafe list: unknown |
| harden-check | path | the last result of silverblue-privacy-hardening's root drift check (aidecheck.service: `aide --check`, then `harden-check`; read like setuid-known: root-owned, not group / other writable). Lines `time`, `check<TAB>id<TAB>status<TAB>summary`, `item<TAB>id<TAB>text`. A failed check: fail, have = its summary, detail = failed / not checked checks and their items, `more` when cut, a fix hint (`sudo harden-check --accept`) when `aide` fails. Older than 26 h: fail, unknown in the first 15 min after boot (the timer runs 5 min after boot). No result: fail |
| home-watch | path | the home watch's report (sectop-home@<user>.service, `/run/sectop-home/<user>/report.json`, owner sectop-home, max 180 s old) against the accepted list in path (root-owned, like setuid-known; lines `user<TAB>name`, `entry<TAB>path<TAB>sig`). New / changed / gone / unreadable entries: fail, have = count + the first, detail = each (`changed` names the fields: mode, size, ctime, link target, ...), `more` when cut, fix hint `--home-accept`. No list or no fresh report: fail. Unsafe list: unknown |
| free-space | path, min_mb | `statvfs(path)`: free blocks for users (`f_bavail`) x `f_frsize` >= min_mb MiB. Search on the parent folders is enough (`/var/log/audit` itself is root 0700) |

Limits: 100 checks, 64 items per list / table, paths `A-Z a-z 0-9 _ . @ % + : / -`
without `..`.

## Defaults (deploy/posture.toml)

From silverblue-cis-hardening (harden-workstation.sh, docs/deviations.md,
docs/verification.md) and CIS / RHEL STIG where the hardening follows them. Agreed
2026-10-26. 76 checks.

    crit  SELinux enforcing now; audit=1 + backlog in kernel args; audit not switched
          off; auditd, firewalld running; auditd not suspended; firewalld zone drop; only root UID 0; wheel =
          the admin; /var on LUKS; system image not unlocked; ostree remotes verify; listeners;
          Secure Boot on; no hardware MAC on a link that is up; hostname localhost; fwupd
          sends no reports
    warn  SELinux config enforcing + targeted; audit rules >= 53 + 2 per setuid file; audit locked
          (-e 2); audit rules loaded without an error; >= 2 GiB free on /var; no setuid
          / setgid program I have not seen; no file changed since I accepted it and
          the root checks pass (harden-check, daily); start places in the desktop home
          as accepted (home-watch); firmware metadata every second day; journald audit
          socket; su closed (sugroup empty, pam_wheel); faillock 5 / 900 s; pwquality 15
          / 4 classes; login.defs min age >= 1 (new accounts: existing ones are in
          /etc/shadow, root only); shadow, gshadow, passwd, group perms; sysctls of
          90-hardening.conf (kernel, KSPP, IPv4, IPv6); no taint; CIS module blocks;
          lockdown integrity; crypto policy not LEGACY; masked units;
          no failed units; core dumps off; journal persistent; GNOME locks; IPv6 off
          on every wifi and cable profile; booted system <= 14 days; random MAC config;
          dhcp-send-hostname 0 on every Wi-Fi / cable profile; LLMNR + mDNS off;
          fallback hostname kernel arg; DNS servers only on the tunnel; NetworkManager
          hands resolved no DNS; no DNS in Wi-Fi / cable profiles; Mullvad
          socket only for group mullvad; sectop, sectop-feed, mullvad groups; kernel
          args (AF_ALG off, page shuffle, no initrd shell, init_on_free, iommu.strict,
          KSPP: hash_pointers, proc_mem, module.sig_enforce, intel_iommu, debugfs,
          bdev_allow_write_mounted);
          chronyd running; chrony NTS only (authselectmode require, minsources 2)
    info  update staged, waiting for a reboot

- hostfw mode / boot mode: not here, the firewall screen checks them (alerts there).
- Listeners (host 2026-10-26, `ss -Htuln`): loopback only for resolved (127.0.0.53 /
  .54:53) and chronyd (:323); libvirt default network dnsmasq on 192.168.122.1:53 (tcp,
  udp) and DHCP 0.0.0.0:67 bound to virbr0; network browse (2026-11-14) the same on
  192.168.123.1:53 and 0.0.0.0:67 bound to virbr-browse; the VPN tunnel's WireGuard (wg0-mullvad)
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
  check catches the next new network. Since 2026-11-20 silverblue-privacy-hardening
  `netprivacy` turns it off on Wi-Fi and cable, a new profile on its first connect (NM
  dispatcher hook): `wifi-ipv6` + `cable-ipv6` (nm-props) fail only if the hook did not
  run. Host 2026-11-18: the one cable profile was auto.
- Network identity (2026-10-27, silverblue-cis-hardening `netprivacy`). Host checks
  (sandbox, user sectop): config files readable; links `type=1`, the one that is up has
  bit 0x02 set, the hardware one (down) not; `hostnamectl --json=short` gives the names,
  PrettyHostname `null`; `nmcli -g ipv4.dhcp-send-hostname` prints `0` for no, `-1` for
  the default. NetworkManager 1.56.1 ignores the global dhcp-send-hostname default (tested
  with tcpdump), so a new network's profile (-1) fails `dhcp-no-hostname` (warn, no
  alert: hostname `localhost` is not sent at all) until netprivacy's dispatcher hook
  fixes it on the first connect (2026-11-20; before: until netprivacy ran again). crit only
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
  network: fixed by netprivacy's dispatcher hook on its first connect). warn: hostfw
  blocks it. 2026-11-20: `nm-dns-off` = NetworkManager hands resolved no DNS at all
  (`dns=none` + `systemd-resolved=false`: `dns=none` alone still sends it,
  NetworkManager.conf(5)); Mullvad sets its link through resolved itself. `resolvectl
  status` as user sectop in the sandbox: not checked on the host yet. "Current DNS
  Server:" and "Fallback DNS Servers:" lines are not indented.
- Time (2026-10-31, silverblue-cis-hardening `time`): chrony NTS only, Netnod + PTB.
  Config checked, not the live state: `chronyc -N authdata` needs root (501 Not
  authorised as a user), `chronyc sources` shows no authentication. `authselectmode
  require` is the guard: a source without NTS is never selected.
- AF_ALG off (2026-11-01, silverblue-cis-hardening `kargs`): `af-alg-off`, cmdline
  `initcall_blacklist=af_alg_init`. warn: nothing used AF_ALG in 2 days of audit (rule
  key af-alg, logs box), a missing arg opens an attack surface, not a hole by itself.
  Live state not read: a test socket would hit the af-alg rule on every collect.
- Audit rules want 73: 70 CIS + 2 af-alg + 1 setuid file (2026-11-01). The `privileged`
  list (55-privileged.rules) is built from the setuid / setgid files under /usr when the
  `audit-rules` section runs: 28 on the host, new one `/usr/bin/mullvad-exclude`
  (setuid root, mullvad-vpn, installed after the count of 70). The check is a floor
  (`>= want`): a package that adds a setuid file passes, one that removes it fails
  until `want` follows. Split tunneling itself: watch rule `split-tunnel` (warn).
- Audit rules follow the setuid list (2026-11-16): `/usr/bin/userhelper` left the image,
  the host had 74 rules (27 setuid) and `>= 75` failed although nothing was missing.
  Now `want = 47` (every other key) and `setuid_key = "privileged"`: exactly one rule
  per setuid / setgid file sectop finds under /usr. A new setuid program without a rule
  fails (that is the point: it runs as root and nothing logs it), and so do rules for
  programs that left (the `audit-rules` section was not run again). The scan: ~0.5 s
  for 166k entries, once per start. Files under a directory user sectop cannot read
  are missed (the detail counts such directories).
- Two rules per setuid program (2026-11-21): silverblue-cis-hardening writes its audit
  rules in the text scap-security-guide matches, path rules once per arch (b32 + b64;
  one rule without arch covered both, the events stay the same). Now `want = 53` and
  `setuid_rules = 2`. Between the new rules files and the next reboot the old rules stay
  loaded (`-e 2`): the check fails with the reboot hint until then.
- fwupd (2026-11-16, silverblue-cis-hardening `autoupdate` `FIRMWARE_REPORTS=no`):
  `fwupd-no-reports` (fwupd-reports, crit: a report address back means a refresh may
  upload again; lvfs.conf had `AutomaticReports=true`) and `fwupd-schedule` (file: the
  drop-in `50-schedule.conf` `OnCalendar=*-*-1/2`, every second day, warn; first
  `fwupd-daily` on `50-once-a-day.conf`, same day).
- Kernel args 2026-11-01 (silverblue-cis-hardening `kargs`, ideas from secureblue):
  `page-shuffle` (`page_alloc.shuffle=1`) and `initrd-no-shell` (`rd.shell=0
  rd.emergency=halt`), both cmdline, warn: missing = less hardening, not a hole. The
  GRUB password that makes `initrd-no-shell` worth it is not checked: /boot/grub2 is not
  readable for user sectop (not verified on the host).
- Mullvad socket 2026-11-02 (silverblue-cis-hardening `mullvad`): `mullvad-socket`, perms
  of /run/mullvad-vpn, want 760 root:mullvad (host after the change). Without the
  drop-in the daemon makes it 766 root:root (host before): any local user can
  disconnect, turn lockdown off or change settings. stat only, the socket is never
  opened. warn: the tunnel and lockdown are still on.
- Audit lock 2026-11-03 (silverblue-cis-hardening `audit-rules`, `-e 2` in
  99-finalize.rules, DISA STIG RHEL 9 V-258229): `audit-locked`, from the same journal
  CONFIG_CHANGE records as `audit-enabled`. A refused change while locked has res=0 and
  is not counted. warn: rules are loaded, only the lock is missing.
- Kernel args 2026-11-07 (silverblue-cis-hardening `kargs`, after a 4-day trial):
  `init-on-free` (`init_on_free=1`) and `iommu-strict` (`iommu.strict=1`), cmdline,
  warn: missing = less hardening, not a hole.
- Audit load and auditd suspend (2026-11-22, review 2026-11-17 L-2 / L-4; no root
  needed, so not in the root check of D-U1). `audit-load` (warn): with `-c`
  (01-continue.rules) a refused rule is skipped, the others load, auditctl exits 1 and
  audit-rules.service fails (auditctl.c: `continue_error`); the rule is missing until
  the next boot (`-e 2`). `failed-units` showed the unit only; this row names the line.
  An error line stays a fail until the next boot even after a later successful run of
  the unit (with `-e 2` nothing could load it). Line format of the host's boot: admin
  script 46. `auditd-logging` (crit, alert): silverblue-privacy-hardening `auditd` sets
  SUSPEND at `admin_space_left`, a full disk and a write error (not HALT); auditd then
  writes nothing to `/var/log/audit` until `auditctl --signal resume` or a restart
  (auditd-event.c `resume_logging`). The kernel still sends records to the journal
  (journald-audit.socket), so the security screen goes on; `ausearch` and the scanner
  see a gap. A full disk can stop the journal too: `audit-space` (warn, `free-space`
  /var/log/audit >= 2048 MiB) warns long before (the log ring alone can grow to 40 x 32
  MiB; /var also holds the homes). auditd.conf (0640 root) is not readable for user
  sectop: its thresholds stay out of the check.
- Setuid list at boot (2026-11-22, silverblue-privacy-hardening
  `audit-privileged-sync.service`, before audit-rules.service): the `audit-rules` fix
  hint is a reboot now; a failed sync keeps the old list (row `failed-units`).
- New setuid programs (2026-11-22, asked by me with L-1): since the setuid list is written
  at boot, a new setuid program gets its audit rules by itself and `audit-rules` stays
  green: nothing showed it. `setuid-known` (warn) compares the programs with
  `/etc/sectop/setuid-known.txt` and stays yellow until I accept it: `sudo ./install.sh
  --setuid-accept` (shows each new one with its package, owner, mode; y = the list is
  /usr now). The first install writes the list from /usr; an update never does.
- Changed files and root-only values (2026-11-22, review D-U1, asked by me): sectop runs
  without root and cannot read /etc/shadow, sudoers, auditd.conf, bpf_jit_harden or
  hash /boot. silverblue-privacy-hardening's integrity section runs AIDE + harden-check as
  root (aidecheck.timer: 5 min after boot, daily) and writes one result file; row
  `harden-check` (warn) reads it. Any changed file stays yellow until the admin accepts
  it (`sudo harden-check --accept`), changes an OS update explains are grouped, not
  hidden.
- Start places in the daily home (2026-11-23, step 8b2, asked by me): autostart, user
  units, shell files, PATH dirs, ... `home-watch` (warn) compares the home watch's report
  (sectop-home@<daily>, names + metadata) with the list the admin accepted
  (`sudo ./install.sh --home-accept`). silverblue-privacy-hardening's homelock section
  makes the unused places immutable (nothing new there), so a change there is rare and
  loud; the places in use (~/.local/bin, desktop files, ~/.ssh, git config) are watched.
