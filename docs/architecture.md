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

- Shared sources: files (`/proc`, `/sys`), one journal reader (cursor), fixed commands
  via `core.run.run()`.
- Modules: collect only, return a Snapshot. Never draw, never act.
- Core: scheduler, validation, alert engine, screens.
- UI: curses, stdlib only. One screen at a time, whole terminal, grid of boxes.

## Screens

| key | screen | content |
|---|---|---|
| 1 | firewall | hostfw, vpn, counters (non-zero only), out_leak, spark, programs (one row per program), peers (remote IPs), audit (in + out, allowed + blocked, grouped) |
| 2 | security | grouped warnings / errors / security events; posture checks |
| 3 | processes | cpu, memory, disk, io, temperatures, top processes, services |

- Each screen uses the whole terminal. Static list in `core/screens.py`.
- Start screen: `sectop [SCREEN]` (name or number). Switch: keys `1-3`.
- Alert bar on every screen: problems from all screens, worst first.
- Events box per screen: raw events of that screen's modules. Firewall: the audit box
  replaces it.

Keys now: `1-3` screen, `tab` / arrows box, `j/k` / arrows select line, `PgDn/PgUp` page,
`enter` detail, `/` filter, `Esc` clear filter, `f` follow, `x` hide, `w` whois, `a` ack,
`p` pause, `m` mask, `?` help, `q` quit.
Planned: `t` capture (from detail).

## Firewall screen: network only (2026-10-20)

- Firewall screen = who goes out / comes in. Per program: programs box, keys `f` (follow:
  the other boxes filtered to it) and `x` (hide it, view only). Lasting noise: the noise
  list (root file, edited by hand), never from the UI (one-way, see Privilege split).
- Security screen = who ran what: commands as root / via sudo (who: login uid also after
  sudo, what, count, first / last, from which program / tty), kernel (module loads, AVC,
  errors). After the privilege split: now sectop's own root polling (~56 root commands /
  min) would bury my real commands, and hiding them by rule would hide anyone's.
- After this: firewall screen done for now. Changes later only from need, architecture
  or new sources (e.g. audit connect records for program names).

## Firewall audit

Who talks to what, both ways, on the firewall screen.

- Source: hostfw kernel log lines (`HFW-*`), incl. `HFW-OUT-NEW` / `HFW-FWD-VM-NEW`
  (allowed new flows via the tunnel, hostfw 2026-10-19). Blocked lines are samples
  (rate limit), counters are exact.
- Row: time, dir, verdict, proto, uid, program, src, dst, iface. Color = severity.
- Program name: netfilter logs only the UID.
  - now: matched with `ss` (same 5-tuple) while the flow is still open
  - later: Linux audit (`connect` syscall: pid + exe), also for blocked flows.
    Needs a filter (volume); check auditctl docs first
- Detail (`enter`): all fields of the log line, rule, verdict meaning.
- Later, from the detail view: short `tcpdump` on that host, bounded
  (`-n -c 50 -s 128 -Z tcpdump` + run timeout). Fits "no long-lived children".
- Actions phase: block key = destination into a hostfw block set with timeout
  (hostfw can only tighten).

## Lookups (whois)

Read-only, on key press only: `w` = RDAP lookup of the selected address
(docs/module-interface.md, Screen). Not an action: changes nothing on the host. Runs in
a child as user nobody (setpriv, no groups, no_new_privs), so the root process never
parses network data. Blocks the UI up to 12 s (v1: no threads).

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
  reason, end time). Examples: ACPI BIOS errors, NVRM lines from akmod-nvidia (logs).
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
- One journal reader shared by network and logs modules.
- Hidden screen: only alert-relevant data, longer interval. Heavy detail (process table)
  only while visible.
- Slow checks on their own interval:
  - updates: once per day. Silverblue: `rpm-ostree` (no dnf), plus flatpak.
  - posture: minutes, not seconds.
- Command timeouts below the module interval.

## Security posture

- Baseline = my repo silverblue-cis-hardening. No invented standard.
- Policy file `/etc/sectop/posture.toml` (root-owned): check id, what, expected value,
  source (file / command).
- Result per check: pass, fail, accepted deviation (with ref to the repo's
  `docs/deviations.md`), unknown.
- First checks: SELinux enforcing, firewalld default zone drop, hostfw enforce, disk
  encrypted, listening ports vs allowlist, key sysctls, failed units, pending updates.

## Logs

- Journal priority <= warning, plus security sources: sshd, sudo, polkit, audit (AVC),
  USB, kernel.
- Grouped by unit + normalized message (numbers, ids, addresses -> placeholder):
  count, first seen, last seen.
- Noise list applies. Grouping and noise rules are tested with fixtures from my host.
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
- Collector = system service started by systemd, not from my login. loginuid stays
  unset (pam_loginuid(8): set by login entry points), so rules with `auid>=1000` /
  `auid!=-1` do not match: daemon events, not user events.
- Not root: own user (`DynamicUser=` or a system user). Journal via
  `SupplementaryGroups=systemd-journal` (journalctl(1): this group reads all journal files).
- Capabilities only where the kernel requires them: `nft list` and `wg show` need
  CAP_NET_ADMIN even to read. `AmbientCapabilities=` + the same `CapabilityBoundingSet=`.
  CAP_NET_ADMIN can also change the firewall -> the part that holds it stays minimal:
  fixed argv, output handed on, no parsing there.
- Program names via `ss -p` need CAP_SYS_PTRACE (capabilities(7): /proc/pid/fd of other
  users). Too strong for a monitor -> program from audit connect records (journal, same
  group) or uid only.
- `NoNewPrivileges=yes`, sandboxing options on ("as many of these options ... as is
  possible", systemd.exec(5)), checked with `systemd-analyze security <unit>`.
- UI = my user, no sudo. Reads collector output (socket or /run file, group read).
  One-way: the UI never writes to the collector (ack stays in the UI).
- whois child stays separate: own user, no capabilities.

Until then: `/etc/sectop/config.toml` `[modules.firewall] interval = 6.0`, fewer
commands per tick (slow sources on their own interval).

## Actions (last phase)

Stop / restart a service, kill a process. Only after the privilege split:

- Collector = non-root service (see Privilege split). UI = my user, unprivileged.
- Actions run as my user via `systemctl`; polkit asks for the password.
- Confirm before every action. Deny list never touched: journald, NetworkManager,
  firewalld, hostfw, Proton daemon, sshd if present.
- Every action logged to the journal.

## Contract changes (Snapshot v2)

- `checks`: conditions for the alert engine. Done (docs/module-interface.md, Checks).
- Panel layout hint `width`: `full` done (audit box). Planned: half, min height.
- Planned: `collect()` gets a context with `visible` (screen shown or not).
- v1 Snapshots keep working until all modules move to v2.

## Phases

1. Core v2 UI: screens (whole terminal, start screen), boxes, focus, scroll, alert bar.
   Firewall screen only. Firewall: hide zero counters, audit box, rollback expiry.
2. Alert engine + noise list. Firewall checks move to it.
3. Privilege split (non-root collector service, unprivileged UI). Moved before logs
   2026-10-20: the logs screen reads the audit log and must not show sectop's own commands.
4. Logs + posture, and system (read-only). Both required, order free. Security screen:
   commands (sudo / root: who, what, count, when, from where), kernel, posture.
5. Actions.
