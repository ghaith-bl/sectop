# Architecture

Plan for sectop v2. Agreed 2026-10-19. v1 = one screen, firewall module (done).
Build one phase at a time. This file changes when a decision changes.

## Goal

One terminal tool for my host (Fedora Silverblue): network / firewall, logs + security
posture, system. My own replacement for btop + top. Shows real problems, not noise, so I
can decide from what is on screen. Read-only until the privilege split.

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
| 1 | firewall | hostfw, vpn, counters (non-zero only), sparks, audit (in + out, allowed + blocked), connections |
| 2 | security | grouped warnings / errors / security events; posture checks |
| 3 | processes | cpu, memory, disk, io, temperatures, top processes, services |

- Each screen uses the whole terminal. Static list in `core/screens.py`.
- Start screen: `sectop [SCREEN]` (name or number). Switch: keys `1-3`.
- Alert bar on every screen: problems from all screens, worst first.
- Events box per screen: raw events of that screen's modules. Firewall: the audit box
  replaces it.

Keys now: `1-3` screen, `tab` / arrows box, `j/k` / arrows select line, `PgDn/PgUp` page,
`enter` detail, `/` filter, `Esc` clear filter, `p` pause, `m` mask, `?` help, `q` quit.
Planned: `a` ack alert, `t` capture (from detail).

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

## Alerts

Alert = state, not event.

- Open while its condition is true, closed when false. No repeat every tick.
- Key = module + rule + subject. Same key again -> count + last seen, no new alert.
- Cooldown after close: a flapping condition does not reopen at once.
- Context decides severity. Example: out_leak before the first tunnel flow this boot =
  expected (pre-connect DoH fallback); after connect = crit. The out_leak box already
  shows this context (docs/modules/firewall.md); status follows in phase 2.
- Noise list: `/etc/sectop/noise.toml` (root-owned, same file checks as config). Each entry:
  match, reason, expires. Expired entries stop matching. Examples: ACPI BIOS errors,
  NVRM lines from akmod-nvidia.
- Ack: dims the alert, does not delete it. New count after ack shows again.
- Who decides what: modules report current checks (key, sev, title, detail) each
  collect; core alert engine does open / close / cooldown / ack / noise.

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

## Actions (last phase)

Stop / restart a service, kill a process. Only after the privilege split:

- Collector = root service. UI = my user, unprivileged.
- Actions run as my user via `systemctl`; polkit asks for the password.
- Confirm before every action. Deny list never touched: journald, NetworkManager,
  firewalld, hostfw, Proton daemon, sshd if present.
- Every action logged to the journal.

## Contract changes (Snapshot v2, planned)

- `checks`: current conditions for the alert engine (see Alerts).
- Panel layout hint: width (half / full), min height.
- `collect()` gets a context with `visible` (screen shown or not).
- v1 Snapshots keep working until all modules move to v2.

## Phases

1. Core v2 UI: screens (whole terminal, start screen), boxes, focus, scroll, alert bar.
   Firewall screen only. Firewall: hide zero counters, audit box, rollback expiry.
2. Alert engine + noise list. Firewall checks move to it.
3. Logs + posture, and system (read-only). Both required, order free.
4. Privilege split (root collector service, unprivileged UI).
5. Actions.
