# security module

Screen 2. `modules/security/`. Phase 4 step 3: commands box + watch list. Auth, kernel,
logs: next steps (docs/architecture.md, Phase 4 plan). Design: docs/architecture.md,
Security screen.

## Source

Core's journal follower only (docs/module-interface.md, Journal). No commands. One file:
the watch list `/etc/sectop/watch.toml`, read once in init (see Watch list).

    JOURNAL = {"groups": [["_TRANSPORT=audit"]],
               "fields": ["MESSAGE", "_AUDIT_ID", "_AUDIT_TYPE", "_AUDIT_TYPE_NAME"]}

Every audit entry since the last collect, assembled into events by `core/audit.py`
(same `_AUDIT_ID`, complete at PROCTITLE). Used:

| event | what |
|---|---|
| SYSCALL execve / execveat, key `user_emulation` | setuid exec: a launch (sudo, pkexec, su) or a setuid program running as root |
| SYSCALL execve / execveat, key `root_cmds` | a command as root after a login |
| USER_CMD (`AUDIT1123`) | sudo's own record: cmd, terminal, res |

Rule keys come from the hardening audit rules (silverblue-cis-hardening). Other keys and
events: ignored here (logs box, step 7).

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
  `denied`: a USER_CMD with res=failed for that launch (sudo, 3 wrong passwords).
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

## Fixtures

`tests/fixtures/security/` (2026-10-20, masked, `tests/journal_fixture.py`): sudo (root
shell via sudo su, sudo id, sudo -k), sudo-denied (3 wrong passwords, then the right
one), sudo-l, pkexec, module (modprobe, blocked sctp load), lock (unlock at the gdm lock
screen). Built in the test (same record format): sudo run by root, nvidia-modprobe ->
modprobe nvidia, su.
