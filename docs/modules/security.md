# security module

Screen 2. `modules/security/`. Phase 4 steps 3 - 5, 7: commands box + watch list, auth
box (`auth.py`), kernel box (`kernel.py`), logs box (`logs.py`). Posture: own module
(docs/modules/posture.md). Design: docs/architecture.md, Security screen.

## Source

Core's journal follower (docs/module-interface.md, Journal). No commands. Files: the
watch list `/etc/sectop/watch.toml` and the noise list `/etc/sectop/noise.toml` (logs
box), read once in init, and `/proc/sys/kernel/tainted`, read each collect (kernel box).

    JOURNAL = {"groups": [["_TRANSPORT=audit"], ["SYSLOG_IDENTIFIER=sudo", "PRIORITY=1"],
                          ["PRIORITY=0", "PRIORITY=1", "PRIORITY=2", "PRIORITY=3",
                           "PRIORITY=4"],
                          ["_TRANSPORT=kernel", "_KERNEL_SUBSYSTEM=usb"]],
               "fields": ["MESSAGE", "_AUDIT_ID", "_AUDIT_TYPE", "_AUDIT_TYPE_NAME",
                          "_AUDIT_LOGINUID", "_PID", "PRIORITY", "_KERNEL_SUBSYSTEM",
                          "_KERNEL_DEVICE", "SYSLOG_IDENTIFIER", "_COMM", "_SYSTEMD_UNIT",
                          "_SYSTEMD_USER_UNIT"]}

2026-10-26 (logs box): the PRIORITY group is every transport now (kernel lines for the
kernel box, the rest for the logs box). Host 2026-10-26: 127 such lines in 1.75 h
besides the kernel's, so the buffer (5000 per collect) is far away.

Every audit entry since the last collect, assembled into events by `core/audit.py`
(same `_AUDIT_ID`, complete at PROCTITLE; an AVC without a syscall: 2 s timeout, next
collect), plus sudo's syslog alerts, kernel log lines PRIORITY 0..4 and USB lines. Not
the whole `_TRANSPORT=kernel` (the firewall's group): the box shows PRIORITY 0..4 and
USB only (docs/architecture.md, Kernel, 2026-10-20), so the filter is the journalctl
match (journalctl(1): terms of one field are alternatives) and the HFW lines (hostfw
logs at level info, PRIORITY 6) are never parsed here. Not a buffer question (corrected
2026-10-26): hostfw log rules are rate limited (10/minute, burst 20 each). Not from CIS /
Red Hat: own design. Used:

| event | what |
|---|---|
| SYSCALL execve / execveat, key `user_emulation` | setuid exec: a launch (sudo, pkexec, su) or a setuid program running as root |
| SYSCALL execve / execveat, key `root_cmds` | a command as root after a login |
| USER_CMD (1123) | sudo's own record: cmd, terminal, res |
| USER_AUTH (1100) | one PAM authentication: acct, exe, uid, auid, terminal, res (auth box; su launch denied) |
| RESP_ACCT_LOCK (2207) | pam_faillock locked an account (suid) |
| USER_MGMT (1102) `op=faillock-reset` | a lock reset (`faillock --reset`, id) |
| syslog `sudo`, PRIORITY 1 | sudo's policy refusals: user NOT in sudoers, command not allowed |
| SYSCALL init_module / finit_module / delete_module + KERN_MODULE | module load / remove (kernel box) |
| execve of `modprobe` / `insmod` + its child `sh -c -- /bin/false` | blocked module load (kernel box) |
| AVC (1400), USER_AVC (1107) | SELinux denials (kernel box) |
| kernel, PRIORITY 0..4 | kernel log (kernel box), HFW-* left out |
| kernel, `_KERNEL_SUBSYSTEM=usb` | `New USB device found`, Product, Manufacturer (kernel box) |
| journal, syslog, stdout PRIORITY 0..4 (not sudo PRIORITY 1) | logs box |
| SYSCALL with a key no other box takes | audit file watches and exec rules (logs box) |
| SELINUX_ERR (1401) | SELinux errors that are not denials (logs box) |

User space records have no type name in the journal (`_AUDIT_TYPE_NAME=AUDIT1100`):
matched by `_AUDIT_TYPE`. ANOM_LOGIN_FAILURES (2100) comes with every 2207 (same pid,
same moment): not used.

Rule keys come from the hardening audit rules (silverblue-cis-hardening). Module syscalls
are matched by arch + syscall number (x86_64 175 / 313 / 176, i386 128 / 350 / 129), not
by the key: the rule `-F path=/usr/bin/kmod -F perm=x -k kernel_modules` gives execve
records with that key too (lsmod by a user). Keys root_cmds / user_emulation /
kernel_modules: commands and kernel box; every other key: logs box.

## commands box

Cols: last (age), n, who>as, via, cmd. Full width. Newest first. Title:
`commands <rows>  (<root runs> root runs since start)`, plus `(journal: <note>)` when the
follower is down or dropped lines.

- Row = group: who (auid) > as (euid), exe, normalized argv[1:] (secrets, UUIDs, IPs, hex
  ids, numbers -> placeholders). Max 200 groups, least recent dropped.
- via: `sudo <tty>` (root command argv == a sudo USER_CMD `cmd`, same ses, within 5 s,
  res success); the launch in the same pid (pkexec) or the parent pid (su); exe of an
  execve seen before with the parent pid; else `ppid <n>` (`setuid` for a setuid
  program). No `/proc` lookup (pid reuse).
- Launchers = sudo, pkexec, su (exe name): setuid programs that run another command as
  root. Any other setuid exec (nvidia-modprobe, its `modprobe nvidia`, fusermount3, the
  polkit agent helper) is a root run: the program itself runs as root. Host 2026-10-25:
  `modprobe nvidia` showed as a launch, dim, "no root command", but it loaded a module
  as root.
- Launch rows (via = `no root command` / `denied`), tone `dim`: a launch is a row at
  once. Its root command takes it back out of that row (n - 1, row gone at 0) and the
  command row gets its password checks. No timer (2026-10-25): a 5 s wait after the
  launch turned a slow password prompt into a launch without a command.
  `denied`: a USER_CMD with res=failed for that launch (sudo, 3 wrong passwords), or a
  USER_AUTH res=failed in a su launch's own pid (su tries once per run; host 2026-10-25:
  `su sectop-locktest` showed "no root command" after wrong passwords).
- `unix_chkpwd` (either key): never a row. `password checks` on the row of its parent: a
  launch waiting for its command, else the command seen with that pid. Were rows before
  2026-10-25: sudo run by root (install.sh, host) and gdm-session-worker on unlock
  (fixture lock). Parent not seen (started before sectop): counted only
  (`State.lost_checks`).
- Failed execve in a PATH search (success=no, no EXECVE): not a run, counted only.
- Detail: exe, result, denied (`<n> of <rows n>`), argv (last 5 distinct, raw), parents,
  via seen (when more than one), cwd, first, ses, pid / ppid, key, password checks.
- parents (newest run of the row): the chain seen in audit, `exe pid < ... < how the top
  one came in` (its via), e.g. `bash 44494 < su 44491 < sudo pts/0`,
  `nvidia-modprobe 710 < setuid`. Built when the command runs (pids get reused), max 8
  parents then `...`. A parent that never ran a root command is not seen: `ppid <n>`.
- Secrets: cmd cell and grouping always masked (`core/sanitize.py` `mask_secrets`).
  Detail argv raw; the UI masks secrets there while mask is on, `m` shows them.
- Severity: from the watch list (below). Detail `watch  <id>: <why>` when a rule matched.

## auth box

`modules/security/auth.py`. Who tried to get in. Cols: last (age), n, login>user,
service, result, tty. Full width, below the commands box. Newest first. Title:
`auth <rows>  (<failed> failed since start)`; summary `auth fails <n>`.

- Row = group: login (auid) > user (the account whose password was checked: acct, or
  suid / id of the lock records), service (exe: sudo, su, gdm-session-worker -> gdm,
  polkit-agent-helper-1 -> polkit, pkexec, login, sshd, else its name), result.
  Max 200 rows, least recent dropped. Detail: why, first, exe, ran as (uid), pid,
  tty seen.
- Results: `ok`, `failed` (USER_AUTH res); `locked` (2207); `lock reset` (1102); sudo
  policy: `not in sudoers`, `not allowed`, `not on host`. Other sudo alert reasons: the
  reason, warn. `N incorrect password attempts`: left out (its USER_AUTH failures are
  rows already).
- Severity (decided 2026-10-25: red = dangerous or suspicious, worth following up, not
  everything):

      crit  account locked; sudo refused by policy; su by a non-root user
            (su is closed on my host: pam_wheel group=sugroup, empty; I use sudo)
      warn  failed authentication (wrong password, or a locked account trying again)
      info  authentication ok, lock reset

  `sudo su` (root runs su: pam_rootok, uid 0) is ok, not the su alert.
- Alerts: a crit row whose last one is under 1 h old (same window as the watch list) ->
  check `auth:<service>:<result>:<login>:<user>` (chars outside the key set -> `_`,
  longer than 128 -> sha256), title `account locked: <user> (<service>)`,
  `su by <login> to <user>: <result>` or `<service> refused: <user> <result>`, n = new.
  warn / info: row color only.
- Host fixtures 2026-10-25: a locked account still prompts (pam_faillock `preauth
  silent`), each try is a USER_AUTH failure; sudo logs `user NOT in sudoers` also after
  wrong passwords (and twice USER_CMD res=failed); su to another user prints `Permission
  denied` (pam_wheel) but its wrong password still counts for faillock (system-auth
  runs on); gdm unlock is gdm-session-worker on tty1, uid 0, auid = me.
- Not here: logind sessions, polkitd lines (none on my host for a failed polkit
  password: only the agent helper's USER_AUTH), new users (`useradd`: commands box,
  watch rule). Logs box: step 7.

## kernel box

`modules/security/kernel.py`. What the kernel did since sectop started. Cols: last (age),
n, kind, from, what. Full width, below the auth box. Newest first. Title:
`kernel <rows>  (taint at start: <letters>[, now: <letters>])`; summary `kernel <n>`.

| kind | row = group | from | what |
|---|---|---|---|
| taint | one bit set since the first read | kernel | `W  kernel warning` |
| module | action, name, result, login, exe | login (auid), `-` autoload | `load tcp_bbr`, `remove x`, `load nvidia failed ENODEV`, `blocked sctp` |
| avc | comm, scontext type, tcontext type, tclass, perms, permissive | comm (USER_AVC: exe name) | `{ mac_admin } tuned_t -> tuned_t capability2`, `(allowed)` when permissive=1 |
| log | PRIORITY + normalized line (UUIDs, IPs, hex, `[..]`, numbers) | `_KERNEL_SUBSYSTEM`, else kernel | newest line |
| usb | idVendor:idProduct | port (newest) | `045e:0745 <Product> (<Manufacturer>)` |

- Taint: `/proc/sys/kernel/tainted` each collect (a file, no command). Baseline = first
  read since start (a restart of sectop.service takes the value then as baseline).
  Letters: docs.kernel.org admin-guide/tainted-kernels (bit 0 = P). Bits never clear
  until reboot: one row per bit, n 1. Read error: title `taint: <error>`, tried again
  each collect. Host check 2026-10-26: readable in the sectop.service sandbox
  (`ProtectKernelTunables=yes` = read-only, systemd.exec(5)): 12288 as user sectop.
- Modules: result `ok` or `failed <errno>` (exit code). Detail: why, first, exe, cmdline
  (PROCTITLE), syscall, result, pid / ppid, tty, ses. No KERN_MODULE (failed early):
  name `?`.
- Blocked load (CIS `install <mod> /bin/false`, hardening section 1): modprobe /
  insmod run as root (root_cmds / user_emulation execve) is kept 60 s by pid; its child
  `sh -c -- /bin/false` (or `/bin/true`, or the program itself) -> `blocked <mod>`, one
  row per modprobe run. Module = first argument without `-`. Detail: cmdline, install,
  pid / ppid. Autoload of a blocked module (no login): not seen (no root_cmds record).
- AVC: `avc: denied { .. }` only (granted, policy load notices: skipped). Detail:
  record, scontext, tcontext, pid, path / name / exe / capability when present.
- Log: newest 3 distinct lines in the detail (`line`), priority, device. Empty lines
  and `HFW-*`: left out.
- USB: `New USB device found, idVendor=.., idProduct=..` (PRIORITY 6) starts or counts
  the row; `Product:` / `Manufacturer:` lines of the same port fill it in. Serial
  numbers: never read. Disconnects: not rows.
- Severity (table agreed 2026-10-25: red = dangerous or suspicious, worth following up):

      crit  new taint D L M B (oops, lockup, machine check, bad page)
            new taint O E P (out-of-tree / unsigned / proprietary module loaded later)
            kernel log emerg / alert / crit (PRIORITY 0-2)
      warn  module loaded or removed from a login (auid set: modprobe, nvidia-modprobe)
            new taint W (kernel warning); any other new bit (F R S U A C I K X T N J:
            not in the table, decided 2026-10-26)
            SELinux denial allowed (permissive=1: permissive domain or mode)
            kernel log error (PRIORITY 3: NVRM, ACPI BIOS errors)
      info  module autoload (auid unset: udev, kernel request), blocked load, SELinux
            denial blocked (enforcing), kernel log warning (PRIORITY 4), new USB device

- Alerts: a crit row whose last one is under 1 h old (same window as watch list / auth)
  -> check `kernel:taint:<letter>` (title `kernel tainted: <letter>  <meaning>`) or
  `kernel:log:<12 hex>` (sha256 of the normalized line; title `kernel <priority>:
  <line>`), n = new. A taint row stays red after the hour, its alert ends.
- Host fixtures 2026-10-20 (module, avc, kernel-warn, usb): `modprobe tcp_bbr` / `-r`
  warn, `modprobe sctp` blocked (info), Microsoft receiver USB (info); AVC 156 chcon
  tuned_t mac_admin (info), 44 lsblk bootupd_t connectto (allowed, warn); boot kernel
  log 196 lines -> 33 groups (10 warn, 23 info: NVRM 84, ACPI BIOS errors 36 in one
  group), no crit. Built in the test: autoload, failed nvidia load, init_module without
  KERN_MODULE, USER_AVC, PRIORITY 0-2 lines, taint changes.
- Not here: kernel log PRIORITY 5-7 (logs box, step 7), taint value checked against the
  baseline (posture, step 6).

## logs box

`modules/security/logs.py`. What the rest of the system logged. Cols: last (age), n,
from, what. Full width, below the kernel box. Newest first. Title:
`logs <rows>  (<n> lines since start, <n> noise)`; summary `logs <n>`.

| from | row = group | what |
|---|---|---|
| SYSLOG_IDENTIFIER (else _COMM, unit), `(own)` for sectop | identifier + PRIORITY + normalized message (quoted names, UUIDs, IPs, hex, numbers) | newest line |
| `audit <key>` | key + exe + file (mkstemp suffix `.XXXXXX` folded) | `<exe name> <file>` |
| `selinux` | op + invalid context type | `setxattr invalid context <type>` |

- Severity (decided 2026-10-26, red = dangerous or suspicious):

      crit  journal PRIORITY 0-2 (emerg, alert, crit), not sudo's alerts (auth box)
      warn  journal PRIORITY 3 (err)
            file watch written by a program that does not own the file:
              sudo_log_file (sudo), logins (pam: sudo su gdm-session-worker polkit
              helper pkexec login sshd faillock unix_chkpwd), session (sudo su gdm
              gdm-session-worker login sshd systemd-update-utmp systemd-logind),
              system-locale (NetworkManager systemd-hostnamed), time-change
              (systemd-timedated), identity (shadow-utils, passwd, chage, gpasswd,
              systemd-sysusers)
            scope (sudoers) and MAC-policy (SELinux policy files): any writer
      info  journal PRIORITY 4 (warning); a file watch written by its owner; exec rules
            perm_chng usermod privileged; volume keys mounts delete perm_mod access;
            SELINUX_ERR

  Why owners (2026-10-26, fixture logs-2h): each sudo writes /var/log/sudo.log
  (sudo_log_file), /var/run/utmp (session) and its faillock file (logins); NetworkManager
  writes its profiles (system-locale: the 4 wifi profiles fixed that day). As warn,
  every sudo would color 3 rows yellow; the same file written by vi or sed is the
  suspicious case.
- Detail: why, first, last 3 distinct lines, priority, unit (`session-#.scope` for
  sudo / login scopes), user unit; audit: exe, file, login, syscall ok / failed, pid,
  cmdline; `noise key security/log:<12 hex>`; noise reason when one matches.
- Own entries: sectop.service, sectop-net.service, sectop-whois@*.service or
  SYSLOG_IDENTIFIER sectop, sectop-collector, sectop-net: `<id> (own)`, never dropped.
- Noise (`/etc/sectop/noise.toml`, read once in init, same list as the alert engine): an
  entry whose match fits `security/log:<id>` (copy the noise key from the detail) marks
  the row dim with the reason in the detail; the row stays and counts. Expired entries
  stop matching. A crit row in noise: still a check, the engine keeps it out of the bar.
- Alerts: a crit row whose last one is under 1 h old -> check `log:<12 hex>`, title
  `<from> <priority>: <line>`.
- Host fixture logs-2h (2026-10-26, 1.75 h, masked; LUKS uuid of one systemd-escape line
  masked by hand, the tool masks it since): 50 groups, 47 info, 3 warn
  (systemd-tmpfiles `/home` `/root` `/srv` already exist: Silverblue symlinks, noise
  candidate), no crit. Noise candidates: pam_systemd `/run/user/0/bus` (every sudo),
  gsd-smartcard, appstreamcli icons.

## Watch list

`/etc/sectop/watch.toml` (`modules/security/watch.py`). Defaults: `deploy/watch.toml`,
put there by install.sh when the file is missing, never over it (install log: `kept`
when mine differs). Same file checks as config.toml (root-owned, not group / other
writable, no symlink). Read once in init: `sudo systemctl restart sectop.service` after
a change (install.sh restarts it too). Missing: no rules, every row ok, summary
`no watch list`. Bad file: init fails, the module is off, its header shows the error.

    [[rule]]
    id = "selinux-permissive"           # a-z 0-9 -, 1..32, unique
    sev = "crit"                        # crit | warn | info
    cmd = "setenforce 0|[Pp]ermissive"  # program, then words
    why = "SELinux to permissive"

- Levels (decided 2026-10-25, same colors as every screen): crit (red) turns a
  protection off; warn (yellow) changes a security setting; info (cyan) routine change
  of the system; no rule = ok (plain). ok is not a verdict: only what the list knows.
- cmd: the first word is the program: exe name, argv[0] name, or the script an
  interpreter runs (`env bash /usr/local/sbin/hostfw observe` -> hostfw; interpreters
  env sh bash dash zsh python3 python perl). Every other word must match one argument,
  in any order (same idea as the UI filter); `!word`: no argument may match. `a|b` =
  either, each an fnmatch glob (`*` `?` `[...]`), case-sensitive.
- Highest sev wins, then the first rule. The rule id is part of the row group:
  `setenforce 0` (crit) and `setenforce 1` (ok) are two rows, though both normalize to
  `setenforce #`. Launch rows are rated too (tone dim keeps them dim, crit stays red).
- Alerts (decided 2026-10-25: red only): a crit row whose last run is under 1 h old ->
  check `watch:<id>:<12 hex>` (sha256 of who, as and the command from the program on),
  title `<why>: <command>`, n = new runs. The env and the bash exec of one script: one
  alert, n = the most new runs of its rows (one run of the script = 1). 1 h without a
  new run: gone (hold 60 s). Same idea as a Prometheus alert on `increase(...[1h]) > 0`:
  an event fires for a window. warn / info: row color only.
  Noise entry: match `security/watch:<id>:*`. Restart of sectop.service: rows and
  alerts start empty (state in memory). A crit row pushed out of the 200 groups: its
  alert ends.
- Changes nothing on the host (no block, no kill).
- Defaults: 57 rules (15 crit, 33 warn, 9 info) for my baseline (silverblue-cis-hardening:
  SELinux, auditd + CIS rules, firewalld drop zone, hostfw, wheel). Examples from the
  host screenshots 2026-10-25 in tests/test_watch.py (TestDefaults): install.sh commands
  info or ok, `modprobe nvidia` warn, `systemctl stop hostfw-rollback.*` (hostfw
  confirm) ok, `env bash /usr/local/sbin/hostfw observe` crit.

## Limits

Groups 200, pids 4096 (parents), parent chain 8, launches 256 / 600 s, USER_CMD 100, argv
per group 5, uid names 256 (cache, cleared when full). Assembler: core/audit.py (1000 open
events, 2 s timeout). Watch list: 200 rules, 16 words, cmd 200 chars, why 120; checks 50.
Rating cost: ~0.1 ms per root command with the 57 default rules (2026-10-25, 3.14).
Auth box: 200 rows, checks 50. Kernel box: 180 rows + up to 20 taint rows (panel max
200), 3 lines per log row, modprobe runs 64 / 60 s, checks 50. Logs box: 200 rows, 3
lines per row, checks 50.

## Fixtures

`tests/fixtures/security/` (2026-10-20, masked, `tests/journal_fixture.py`): sudo (root
shell via sudo su, sudo id, sudo -k), sudo-denied (3 wrong passwords, then the right
one), sudo-l, pkexec, module (modprobe, blocked sctp load), lock (unlock at the gdm lock
screen). 2026-10-25, auth (re-masked for my wifi name with the fixed tool): unlock-fail
(lock screen: 1 wrong, then right), su-fail (2 x `su sectop-locktest` with a wrong
password, faillock reset), not-sudoers (`sudo -u sectop-locktest sudo -k true`, 3 wrong:
user NOT in sudoers), faillock (6 wrong more: locked at the 5th failure, reset; userdel
refused while user@1001.service ran). Built in the test (same record format): sudo run
by root, nvidia-modprobe -> modprobe nvidia, su. Kernel box: module (modprobe tcp_bbr,
-r, blocked sctp, USB plug lines), usb (disconnect), avc (200), kernel-warn (boot,
PRIORITY <= 4); built in the test: see kernel box. Logs box: logs-2h (2026-10-26,
journal PRIORITY <= 4 + audit without root_cmds / user_emulation / kernel_modules /
mounts, 1.75 h); built in the test: file watches by other writers, PRIORITY 0-2, own
lines, noise.
