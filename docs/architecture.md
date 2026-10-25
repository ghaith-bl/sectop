# Architecture

Plan for sectop v2. Agreed 2026-10-19. v1 = one screen, firewall module (done).
Build one phase at a time. This file changes when a decision changes.

## Goal

One terminal tool for my host (Fedora Silverblue): network / firewall, logs + security
posture, system. My own replacement for btop + top. Shows real problems, not noise, so I
can decide from what is on screen. Read-only until the privilege split (phase 3).

## Layers

    shared sources -> modules -> core -> terminal UI
                                          -> actions (last phase, separate path)

- Shared sources: files (`/proc`, `/sys`), one journal follower (core), fixed commands
  via `core.run.run()`.
- Modules: collect only, return a Snapshot. Never draw, never act.
- Core: scheduler, validation, alert engine, screens.
- UI: curses, stdlib only. One screen at a time, whole terminal, grid of boxes.

## Screens

| key | screen | content |
|---|---|---|
| 1 | firewall | hostfw, vpn, counters (non-zero only), out_leak, spark, programs (one row per program), peers (remote IPs), audit (in + out, allowed + blocked, grouped) |
| 2 | security | commands, auth, kernel, posture, logs (grouped). See Security screen |
| 3 | processes | cpu, memory, disk, io, temperatures, top processes, services |

- Each screen uses the whole terminal. Static list in `core/screens.py`.
- Start screen: `sectop [SCREEN]` (name or number). Switch: keys `1-3`.
- Alert bar on every screen: problems from all screens, worst first.
- Events box per screen: raw events of that screen's modules. Firewall: the audit box
  replaces it. Security: none (2026-10-25: the module sends no events, an empty box took
  room; the logs box comes in step 7).

Keys now: `1-3` screen, `tab` / arrows box, `j/k` / arrows select line, `PgDn/PgUp` page,
`enter` detail, `/` filter (in a detail: search, `n` `N` next / previous match), `Esc` clear
filter, `f` follow, `x` hide, `w` whois, `a` ack, `p` pause, `m` mask, `?` help, `q` quit.
Planned: `t` capture (from detail); program card (`enter` on a program, phase 4).

## Firewall screen: network only (2026-10-20)

- Firewall screen = who goes out / comes in. Per program: programs box, keys `f` (follow:
  the other boxes filtered to it) and `x` (hide it, view only). Lasting noise: the noise
  list (root file, edited by hand), never from the UI (one-way, see Privilege split).
- Security screen = who ran what (see Security screen). After the privilege split: now
  sectop's own root polling (~56 root commands / min) would bury my real commands, and
  hiding them by rule would hide anyone's.
- After this: firewall screen done for now. Changes later only from need, architecture
  or new sources (e.g. `ss --cgroup` for program names after the split).

## Firewall audit

Who talks to what, both ways, on the firewall screen.

- Source: hostfw kernel log lines (`HFW-*`), incl. `HFW-OUT-NEW` / `HFW-FWD-VM-NEW`
  (allowed new flows via the tunnel, hostfw 2026-10-19). Blocked lines are samples
  (rate limit), counters are exact.
- Row: time, dir, verdict, proto, uid, program, src, dst, iface. Color = severity.
- Program name: netfilter logs only the UID.
  - now: matched with `ss -p` (same 5-tuple) while the flow is still open
  - after the split: `ss --cgroup`, no CAP_SYS_PTRACE (works as my user, 2026-10-20).
    Socket -> cgroup -> app id / unit: `app-flatpak-com.brave.Browser-<n>.scope`,
    `NetworkManager.service`. systemd.io DESKTOP_ENVIRONMENTS:
    `app[-<launcher>]-<ApplicationID>-<RANDOM>.scope`. One word: also fixes `x` for
    "Web Content".
  - not: audit `connect` rule (every unix socket connect matches too -> volume)
- Detail (`enter`): all fields of the log line, rule, verdict meaning.
- Later, from the detail view: short `tcpdump` on that host, bounded
  (`-n -c 50 -s 128 -Z tcpdump` + run timeout). Fits "no long-lived children".
- Actions phase: block key = destination into a hostfw block set with timeout
  (hostfw can only tighten).

## Lookups (whois)

Read-only, on key press only: `w` = RDAP lookup of the selected address
(docs/module-interface.md, Screen). Not an action: changes nothing on the host. Runs in
sectop-whois@.service (socket, own dynamic user, see Privilege split), so neither the
collector nor my user parses network data. Blocks the UI up to 12 s (v1: no threads).

## Security screen (2026-10-20)

Who ran what as root, who tried to get in, what the kernel did, is the baseline still
true. Built in phase 4, after the privilege split.

    +---------------------------+---------------------------+
    | commands (root / setuid)  | auth                      |
    +---------------------------+---------------------------+
    | kernel                    | posture                   |
    +---------------------------+---------------------------+
    | logs (full width)                                     |
    +-------------------------------------------------------+

Source: the one journal reader. Audit records via journald
(`systemd-journald-audit.socket` enabled + active, 2026-10-20). Not `/var/log/audit` or
`/var/log/sudo.log` (root only).

Audit records in the journal (host sample 2026-10-20: 2 sudo calls, 195 entries):
- One entry per record. Event = entries with the same `_AUDIT_ID`. No EOE records: a
  syscall event is complete at its PROCTITLE.
- Only SYSCALL carries auid / ses / uid / euid. EXECVE, CWD, PATH joined by `_AUDIT_ID`.
- argv from the EXECVE MESSAGE (`a0=` quoted or hex, long args `a1[0]`), not from
  `_AUDIT_FIELD_A*`: journald maps max 64 fields per record (`N_IOVEC_AUDIT_FIELDS`).
- User space types have no name: USER_CMD = `AUDIT1123`. Match `_AUDIT_TYPE=<n>`.
- EXECVE (kernel auditsc.c): `a<n>=` per argument, quoted or hex (space, quote, control
  char, byte > 0x7e); a long one as `a<n>_len=` + chunks `a<n>[i]=`, which may go on in
  the next EXECVE record of the event; encoding once per argument. Encoded fields (cmd,
  cwd, exe, comm, key, name, proctitle, ...): audit-documentation field dictionary,
  format "encoded"; `(null)` = none. Several rule keys: joined by 0x01 (hex). SYSCALL
  a0..a3 are plain hex numbers, not encoded.
- Failed execve in a PATH search (fixture sudo: xargs tries /usr/local/sbin/cat):
  SYSCALL success=no exit=-2, PATH = the tried name, no EXECVE record.
- Every sudo starts root's user manager (pam_systemd, `user@0.service`): ~100 entries
  (BPF, SYSCALL `key=(null)`). No key -> ignored.

### Commands

- Keys: audit uses the first matching rule (auditctl(8): "the event triggers on the first
  matching rule"). Hardening rule order: `user_emulation` before `root_cmds`:
  - `user_emulation` = setuid launch (uid != euid): sudo itself, pkexec, fusermount3
  - `root_cmds` = what runs as root after it (uid = euid = 0, auid = login user)
- Row = one group: who (auid) > as (euid), exe + normalized argv.
  Cols: last, n, who>as, via, cmd. Normalized for grouping only: numbers, hex ids, IPs,
  UUIDs -> placeholder (same as logs).
- Via sudo: the command's ppid is the sudo monitor (fork, no execve, gone at once), and
  `use_pty` gives the command a new pty. Join: `root_cmds` argv == USER_CMD `cmd`, same
  ses, within 5 s -> via `sudo <tty of the sudo launch>`. Else parent = exe of an execve
  already seen (pid), else `ppid <n>`. No `/proc` lookup (2026-10-20): read seconds
  later, the pid may be reused -> wrong parent. `ProtectProc=invisible` stays.
- `unix_chkpwd` under sudo (2 per password prompt): folded into that sudo row.
- Launch without a root child (sudo -k / -l, sudoedit, denied sudo, setuid helpers):
  own row, dim (tone `dim`). Nothing hidden. Built 2026-10-25: the launch is a row at
  once, its root command takes it back (no timer: a 5 s wait turned a slow password
  prompt into a launch without a command). Details: docs/modules/security.md.
- Detail: last 5 distinct full argv, cwd, first / last, ses, pid / ppid, key; via seen
  when a group came in more than one way.
- Secrets: always masked in rows. Detail: masked, `m` shows the raw argv (same key as
  IPs). Masked: values of `--password --passwd --token --secret --api-key`,
  `user:pass@` in URLs, `*_PASSWORD= *_TOKEN= *_SECRET=`. Argv is readable by every user
  in `/proc/<pid>/cmdline` and stored in audit + journal anyway: this only keeps it off
  the screen.
- Alerts: none per command. Watch list `/etc/sectop/watch.toml` (root-owned, same file
  checks as config): commands that weaken the baseline -> warn. Changes nothing on the
  host. First entries: `setenforce 0`, `auditctl -D` / `-e 0`, `nft flush`,
  `systemctl stop|disable|mask` of auditd / hostfw / firewalld, `usermod -aG wheel`.

### Auth

- sudo denied: USER_CMD `res=failed` (sudoers(5) log_denied: "to the system audit log")
  + sudo syslog reason ("user NOT in sudoers", "command not allowed", "N incorrect
  password attempts", "a password is required"; PRIORITY 1) -> warn.
- sudo syslog splits at 980 bytes (sudoers(5) `syslog_maxlen`): command text from audit,
  reason from syslog.
- PAM: USER_AUTH `res=failed` (sudo, gdm, polkit) -> warn. faillock lock -> crit
  (source: check on host).
- Logins: logind "New session", USER_START of gdm-password / login -> info.
- polkit: polkitd lines (authenticated / failed, action id) -> info / warn.

### Kernel

- Taint: `/proc/sys/kernel/tainted` (file). Bit new since the first read this boot:
  W -> warn; D L M B -> crit (docs.kernel.org tainted-kernels: the kernel stays tainted
  after the cause is gone). Boot value decoded in posture. 2026-10-20: 12288 = O + E.
- Modules: audit `kernel_modules` (SYSCALL + KERN_MODULE name). Group: name, syscall,
  exe, result. auid set (manual load) -> warn, auid unset (autoload) -> info.
  Boot 2026-10-20: 38 autoloads ok; 37 failed loads of `nvidia` by kmod, auid 60578
  (GDM greeter, systemd.io UIDS-GIDS: 60578-60705) and 1000, dGPU off (Integrated).
  Noise entry until akmod-nvidia is removed.
- Blocked load (CIS `install <mod> /bin/false`, e.g. `modprobe sctp`): no init_module
  call, so no `kernel_modules` record. Shown in the modules group from the root command
  (modprobe / insmod / rmmod argv) and its result.
- AVC: audit AVC / USER_AVC. Group: comm, scontext type, tcontext type, tclass, perms.
  `permissive=1` -> warn, else info.
  Journal, last 200 (2026-10-14 .. 10-20): 2 groups. `tuned` -> `chcon` capability2
  mac_admin (permissive=0), 156, at boot and later. `lsblk` in `bootupd_t` connectto
  `systemd_machined_t` (permissive=1 on an enforcing host = permissive domain, check:
  `sudo semanage permissive -l`), 44, at boot. Noise entries with reason + expiry, no
  rule change.
- Audit entries carry `_PID`, `_COMM` (from the record), never `_SYSTEMD_CGROUP` /
  `_SYSTEMD_UNIT` / `_UID` (fixture avc 2026-10-20, 200 of 200).
- Kernel log: `_TRANSPORT=kernel`, PRIORITY <= 4, minus `HFW-*` (firewall screen).
  Boot 2026-10-20 (5.3 h): 196 lines, ~39 groups. `NVRM` 84 (akmod-nvidia, dGPU off) and
  ACPI BIOS errors ~70 at boot: noise entries. `nvidia: loading out-of-tree module
  taints kernel` = the O taint.
- USB: "New USB device found" -> idVendor:idProduct + Product -> info.

### Program card (phase 4)

`enter` on a program: everything sectop can tie to it.
- Identity = cgroup app id / unit (Firewall audit, program name). Process -> cgroup:
  `/proc/<pid>/cgroup` while it runs. Audit entries have no cgroup (see Kernel), so this
  needs `/proc` of other users: `ProtectProc=default` for sectop.service in this step,
  with this reason in the commit.
- Network flows; root commands / setuid launches with a parent in it; polkit requests
  from it; its AVC denials; its journal warnings / errors (`_SYSTEMD_USER_UNIT`,
  `_SYSTEMD_UNIT`).
- Not shown: file access and plain (non-root) execs. Not audited (volume).

## Alerts

Alert = state, not event.

- Open while its condition is true. No repeat every tick.
- Key = module + rule + subject. Same key again -> count + last seen, no new alert.
- Hold after clear (2026-10-20): an alert keeps firing `hold` s (default 60) after its
  check was last reported. A flapping condition stays one alert, no close / reopen.
  Same idea as Prometheus `keep_firing_for` (alerting rules docs: "prevent situations
  such as flapping alerts"). No delay before opening: a real problem shows at once.
- Context decides severity. Example: out_leak before the first tunnel flow this boot =
  expected (pre-connect DoH fallback); after connect = crit. The out_leak box already
  shows this context (docs/modules/firewall.md); status follows in phase 2.
- Noise list: `/etc/sectop/noise.toml` (root-owned, same file checks as config). Each entry:
  match (glob on the alert key, module part literal), reason, expires (date, required).
  Expired entries stop matching: the alert shows again. A noise alert is still tracked
  and shown as noise, never dropped. Same idea as an Alertmanager silence (matchers,
  reason, end time). Examples: ACPI BIOS errors, NVRM lines from akmod-nvidia (logs),
  failed `nvidia` loads (kernel).
- Ack: dims the alert, does not delete it. Higher count or severity after ack shows it
  again. Key `a` acks every alert in the bar (2026-10-20). A per-alert list: later, if
  needed.
- Bar: warn / crit only. Info alerts (e.g. out_ks drops) and noise alerts are counted on
  the right, not listed.
- Who decides what: modules report checks (key, sev, title, detail, n, hold) each
  collect (docs/module-interface.md, Checks). Alert engine `core/alerts.py` does open /
  hold / close / count / noise. Pure: checks + time in, alert state (plain JSON) out.
- Where (2026-10-20): phase 2 in the one process, phase 3 in the collector service,
  unchanged. Alerts go on while the UI is closed.
- Ack lives in the UI, not in the engine: key + count + severity at ack. The channel
  stays one-way (collector -> UI): the unprivileged UI never writes to the service that
  holds CAP_NET_ADMIN. Phase 2: in memory (sectop still runs as root, no root writes
  into my home). Phase 3: file in `$XDG_STATE_HOME/sectop/` (XDG Base Directory spec).

## Resources

Target: < 1% CPU, < 30 MiB RSS.

- Read files where a file exists (`/proc`, `/sys/class/hwmon`, `/sys/class/thermal`,
  `/sys/fs/selinux/enforce`, `/proc/sys`). No subprocess for those.
- One journal reader for the whole collector (firewall + security), not one per module.
  Measured 2026-10-20: one `journalctl` run = ~30 ms CPU (user ~7, sys ~25), 3 runs. A
  poll every 2 s = ~1.5% of a core by itself.
- Decided 2026-10-25: follow, not poll (`core/journal.py`). One long-lived
  `journalctl -f -o json`, started by core, read in the collector loop without threads
  (selectors). Host check 2026-10-25 (journal_check.py, systemd 259): idle 0 ms CPU per
  minute, RSS 21 MiB (journal file maps); an entry is in the pipe ~450 ms after logger
  (journald + logger, not the reader); a burst of 300 entries complete and in order;
  follows across `journalctl --rotate`; works under the sectop.service sandbox (user
  sectop, group systemd-journal). Not in journalctl(1), so checked: `-f --after-cursor=C`
  replays after C (255 and 259); `-f --after-cursor=C -n 0` replays nothing on 255, after
  C on 259, so never together; `-f --since=@T` replays all since T (no tail of 10);
  `-f -n 0` replays nothing; bad cursor: exit 1 "Failed to seek to cursor: Invalid
  argument". Same check on systemd 255 (Ubuntu, not my host): the same, except -n 0.
- Hidden screen: only alert-relevant data, longer interval. Heavy detail (process table)
  only while visible.
- Slow checks on their own interval:
  - updates: once per day. Silverblue: `rpm-ostree` (no dnf), plus flatpak.
  - posture: minutes, not seconds.
- Command timeouts below the module interval.

## Security posture

- Baseline = my repo silverblue-cis-hardening. No invented standard.
- Policy file `/etc/sectop/posture.toml` (root-owned): check id, what, expected value,
  source (file / command), optional `ref` into the repo's `docs/deviations.md`.
- Result per check: pass, fail, accepted deviation (has `ref`: shown dim, no alert),
  unknown.
- Every 5 min. Read by the non-root collector (2026-10-20):
  - SELinux: `/sys/fs/selinux/enforce` = 1
  - hostfw: enforce (firewall module check)
  - LUKS: `/sys/dev/block/<maj:min of /var>/dm/uuid` starts `CRYPT-LUKS`
  - listeners: `/proc/net/{tcp,tcp6,udp,udp6}` vs allowlist (addr:port)
  - sysctl: `/proc/sys/*` vs the hardening values
  - audit: `audit=1` in `/proc/cmdline`, auditd active, rules loaded = CONFIG_CHANGE
    `op=add_rule` - `op=remove_rule` this boot (2026-10-20: 70, verification.md ~70)
  - taint: decoded, expected bits in the policy (now O E)
  - failed units: `systemctl list-units --state=failed`
  - updates: `rpm-ostree status --json`, cached only, once per day (collector has no
    network)
  - wifi: `ipv6.method` disabled on every wifi profile (nmcli)
- Open: firewalld default zone without root; flatpak updates without network.
- Needs root, not checked: `auditctl -l` / `-s` (CAP_AUDIT_CONTROL), `/var/run/faillock`.

## Logs

- Journal priority <= warning, plus security sources: sshd, sudo, polkit, audit (AVC),
  USB, kernel.
- Grouped by unit + normalized message (numbers, ids, addresses -> placeholder):
  count, first seen, last seen.
- Noise list applies. Grouping and noise rules are tested with fixtures from my host.
- Own entries (sectop units, `SYSLOG_IDENTIFIER=sectop`): tagged `own`, shown and
  filterable, never dropped.
- Audit keys outside commands / modules (2026-10-20): watch keys (identity, scope,
  MAC-policy, logins, session, time-change, system-locale, perm_chng, usermod,
  privileged, sudo_log_file) and volume keys (mounts, delete, perm_mod, access) -> this
  box, grouped by key + exe. No box of their own.
- Noise candidate 2026-10-20: `pam_systemd(sudo:session): Failed to check if
  /run/user/0/bus exists` (PRIORITY 4, every sudo).
- Audit volume 2026-10-20: key `mounts` (CIS rule) = 99% `exe=/usr/bin/bwrap` (2922 of
  2941 in 2 h). Every Flatpak sandbox start: bubblewrap always creates a new mount
  namespace, invisible from the host (bubblewrap README). Group by exe, noise list
  candidate (phase 4 extends match to log groups). The CIS rule stays (no deviation):
  the audit ring holds a week (hardening repo, 40 x 32 MiB).

## Privilege split

Why (2026-10-20): v1 runs as root from my login, so every command it runs matches the
audit rule `root_cmds` (execve, euid 0, auid >= 1000). Boot 2026-10-19 17:09-21:49:
402826 of 433116 journal entries = audit (93%), execve 4 wg : 3 nft : 2 ip : 1 ss :
1 journalctl = one tick, ~2.9 h of sectop. Two problems:
- my own polling hides real root commands
- it pushes real records out of the audit.log ring (max_log_file 8 MB x num_logs 5)

Not a fix: excluding these commands from the audit rules (anyone running them as root
would be hidden too).

Design (least privilege: NIST SP 800-53 / 800-171 AC-6, systemd.exec(5), capabilities(7)):

    sectop-net.service   user sectop-net, CAP_NET_ADMIN only -> /run/sectop-net/
    sectop.service       user sectop, journal group, no caps -> /run/sectop/state.json
    sectop-whois.socket  one sectop-whois@.service per lookup, DynamicUser, RDAP only
    sectop (UI)          my user, no sudo, reads /run/sectop/state.json

- Collector = system service started by systemd, not from my login. loginuid stays
  unset (pam_loginuid(8): set by login entry points), so rules with `auid>=1000` /
  `auid!=-1` do not match: daemon events, not user events. Audit rules unchanged: the
  same commands from a login are still recorded.
- Users (2026-10-20): static system users `sectop` (collector) and `sectop-net` (net
  unit), group `sectop` (sysusers.d), no login, no home. Two users: the collector cannot
  forge firewall data, the capability never sits next to the parsing code. Not
  `DynamicUser=`: Red Hat, "systemd secure services": with "directories shared with a
  particular group ... dynamic users are probably not the best option".
  Journal via `SupplementaryGroups=systemd-journal` (journalctl(1): this group reads all
  journal files).
- Output: `RuntimeDirectory=sectop`, mode 0750 -> `/run/sectop/state.json` (write +
  rename). My user in group `sectop`, read only. File, not socket: one-way, less code.
  Written after every collect and every 5 s. No update for 3 x the longest module
  interval (min 15 s) -> UI shows crit alert "collector: <why>".
- Capabilities only where the kernel requires them: `nft list` and `wg show` need
  CAP_NET_ADMIN even to read (tested 2026-10-20, transient unit as nobody: works with
  the capability only, "Operation not permitted" without). CAP_NET_ADMIN can also change
  the firewall -> net unit, own user, `AmbientCapabilities=` + the same
  `CapabilityBoundingSet=`. Fixed argv (`modules/firewall/netcmds.py`: argv only, the
  only firewall code it imports), takes no input. Raw result per command:
  `/run/sectop-net/<name>.json` (argv, rc, out, err, ts), group `sectop`. Every half
  firewall interval: nft table, wg handshakes + transfer. Every half SLOW: wg endpoints +
  fwmark, nft set wg_fwmark. Not in the collector: ambient capabilities pass to every
  child (capabilities(7)).
- Program names: `ss -p` needs CAP_SYS_PTRACE (capabilities(7): /proc/pid/fd of other
  users). Too strong for a monitor -> `ss --cgroup` (see Firewall audit).
- No network in collector and net unit: `IPAddressDeny=any`,
  `RestrictAddressFamilies=AF_UNIX AF_NETLINK`.
- whois (2026-10-20): `sectop-whois.socket` (`/run/sectop-whois.sock`, root:sectop 0660,
  `Accept=yes`) -> one `sectop-whois@.service` per lookup, `DynamicUser=yes`. Red Hat:
  dynamic users fit when "the user identity is ephemeral, and no integration with other
  services in the system is needed". Reads one IP, writes the RDAP JSON, exits.
  Network allowed, nothing else. The UI only connects and reads.
- Every part refuses to run as root.
- Install (2026-10-20): code a service runs must not be writable by my user. install.sh
  (sudo, from the repo): `git archive HEAD` -> `/usr/local/lib/sectop` (root-owned;
  Silverblue: `/usr/local` -> `/var/usrlocal`), launcher `/usr/local/bin/sectop`, units in
  `/etc/systemd/system`, `/etc/sysusers.d/sectop.conf`, restorecon. Tests and development
  stay in the repo. Until now sudo ran code from my home as root: anything running as me
  could change what root runs. See docs/install.md.
- hostfw (hardening repo, 2026-10-20): `/run/hostfw` 0755, so the non-root collector reads
  the rollback deadline (deadline + action, nothing secret).
- `NoNewPrivileges=yes`, sandboxing options on ("as many of these options ... as is
  possible", systemd.exec(5)), checked with `systemd-analyze security <unit>` (Red Hat:
  results "should be considered hints").
- SELinux: without a policy the services run as `unconfined_service_t` (RHEL Using
  SELinux, "Writing a custom SELinux policy"). Own policy (`sepolicy generate --init`)
  after the split works, built from its real behavior (AVC).
- UI = my user, no sudo. Reads `/run/sectop/state.json`. One-way: the UI never writes
  to the collector (ack stays in the UI).

Until the split is installed: `/etc/sectop/config.toml` `[modules.firewall] interval =
6.0`, fewer commands per tick (slow sources on their own interval).

## Actions (last phase)

Stop / restart a service, kill a process. Only after the privilege split:

- Collector = non-root service (see Privilege split). UI = my user, unprivileged.
- Actions run as my user via `systemctl`; polkit asks for the password.
- Confirm before every action. Deny list never touched: journald, NetworkManager,
  firewalld, hostfw, Proton daemon, sshd if present.
- Every action logged to the journal.

## Look (2026-10-20)

Modern, clear tables. Phase 4 step 2, every screen. Built 2026-10-25, decisions: glyphs
ASCII (`!!` `!` `i`, `~` noise for the logs box), same width, any font; colors stay as on
the firewall screen (row color = severity or `tone`, glyph in the severity color), so
"one accent" = reverse video for focus + selection (as before); ages from now, frozen
while paused; table column hint `types` (text / num / age) instead of `align`.

- Boxes: rounded corners (U+256D U+256E U+2570 U+256F), title left with row count,
  filter / follow state right.
- Table header: bold + underline. Text columns left, numbers right (column hint
  `align`). Two spaces between columns.
- Severity: own first column, one glyph per level (crit, warn, info, noise) + color.
  Row text stays default color. WCAG 2.2, 1.4.1 Use of Color: color is not the only
  means.
- Time: age in rows (`12s`, `4m`, `2h`), full local time in the detail.
- Colors: one accent for focus + selection, severity colors only for severity.

## Phase 4 plan (2026-10-20)

Best practice decides (Red Hat for the host). Fixtures from my host first
(`tests/journal_fixture.py`).

- Screen 2 modules: `security` (commands, auth, kernel, logs: all from the journal) and
  `posture` (own module, every 300 s: other sources, slow, its errors do not stop the
  other boxes).
- Order:
  1. Journal reader in core: follow (see Resources). Done 2026-10-25: `core/journal.py`,
     `collect(state, ctx)` + `JOURNAL`, firewall moved to it (no poll, no cursor of its
     own); audit events (`core/audit.py`: by `_AUDIT_ID`, EXECVE / USER_CMD), fixtures
     2026-10-20 in tests/fixtures/security/. CPU of sectop.service after install: not
     measured yet.
  2. Look: done 2026-10-25 (see Look)
  3. commands box + watch.toml. Commands box done 2026-10-25 (modules/security,
     docs/modules/security.md). watch.toml: next.
  4. auth box
  5. kernel box
  6. posture module + posture.toml
  7. logs box: groups, noise on groups, audit keys
  8. program card

## Contract changes (Snapshot v2)

- `checks`: conditions for the alert engine. Done (docs/module-interface.md, Checks).
- Panel layout hint `width`: `full` done (audit box). Planned: half, min height.
- `collect(state, ctx)`: done 2026-10-25 (journal entries). Planned in ctx: `visible`
  (screen shown or not).
- v1 Snapshots keep working until all modules move to v2.

## Phases

1. Core v2 UI: screens (whole terminal, start screen), boxes, focus, scroll, alert bar.
   Firewall screen only. Firewall: hide zero counters, audit box, rollback expiry.
2. Alert engine + noise list. Firewall checks move to it.
3. Privilege split (non-root collector service, unprivileged UI). Moved before logs
   2026-10-20: the logs screen reads the audit log and must not show sectop's own commands.
   Then: own SELinux policy for the collector.
4. Logs + posture, and system (read-only). Both required, order free. Security screen:
   commands, auth, kernel, posture, logs; program card. See Phase 4 plan.
5. Actions.
