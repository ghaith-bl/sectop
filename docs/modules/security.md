# security module

Screen 2. `modules/security/`. Phase 4 step 3: commands box. Auth, kernel, logs: next
steps (docs/architecture.md, Phase 4 plan). Design: docs/architecture.md, Security screen.

## Source

Core's journal follower only (docs/module-interface.md, Journal). No commands, no files.

    JOURNAL = {"groups": [["_TRANSPORT=audit"]],
               "fields": ["MESSAGE", "_AUDIT_ID", "_AUDIT_TYPE", "_AUDIT_TYPE_NAME"]}

Every audit entry since the last collect, assembled into events by `core/audit.py`
(same `_AUDIT_ID`, complete at PROCTITLE). Used:

| event | what |
|---|---|
| SYSCALL execve / execveat, key `user_emulation` | setuid launch (sudo, pkexec, polkit helper) |
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
  res success); pkexec (same pid as its launch); exe of an execve seen before with the
  parent pid; else `ppid <n>`. No `/proc` lookup (pid reuse).
- Launch rows (via = `no root command` / `denied`), tone `dim`: a setuid launch is a row
  at once. Its root command takes it back out of that row (n - 1, row gone at 0) and the
  command row gets its password checks. No timer (2026-10-25): a 5 s wait after the
  launch turned a slow password prompt into a launch without a command.
  `denied`: a USER_CMD with res=failed for that launch (sudo, 3 wrong passwords).
- `unix_chkpwd` under a launch: `password checks` on that launch, never a row.
- Failed execve in a PATH search (success=no, no EXECVE): not a run, counted only.
- Detail: exe, result, denied (`<n> of <rows n>`), argv (last 5 distinct, raw), via seen
  (when more than one), cwd, first, ses, pid / ppid, key, password checks.
- Secrets: cmd cell and grouping always masked (`core/sanitize.py` `mask_secrets`).
  Detail argv raw; the UI masks secrets there while mask is on, `m` shows them.
- Severity: all ok. No checks yet: watch.toml (warn) is the next step.

## Limits

Groups 200, pids 4096 (parents), launches 256 / 600 s, USER_CMD 100, argv per group 5,
uid names 256 (cache, cleared when full). Assembler: core/audit.py (1000 open events,
2 s timeout).

## Fixtures

`tests/fixtures/security/` (2026-10-20, masked, `tests/journal_fixture.py`): sudo (root
shell via sudo su, sudo id, sudo -k), sudo-denied (3 wrong passwords, then the right
one), sudo-l, pkexec, module (modprobe, blocked sctp load).
