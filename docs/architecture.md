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
| 3 | processes | system (cpu, memory, swap, load, pressure, disk, temperatures), services (system units), processes. See Processes screen |

- Each screen uses the whole terminal. Static list in `core/screens.py`.
- Start screen: `sectop [SCREEN]` (name or number). Switch: keys `1-3`.
- Alert bar on every screen: problems from all screens, worst first.
- Events box per screen: raw events of that screen's modules. Firewall: the audit box
  replaces it. Security: none (2026-10-25: the module sends no events, an empty box took
  room; the logs box comes in step 7).

Keys now: `1-3` screen, `tab` / arrows box, `j/k` / arrows select line, `PgDn/PgUp` page,
`enter` detail, `/` filter (in a detail: search, `n` `N` next / previous match), `Esc` clear
filter, `f` follow, `x` hide, `w` whois, `a` ack, `p` pause, `m` mask, `?` help, `q` quit.
Planned: `t` capture (from detail); program card (`enter` on a program, phase 4); `s` sort
and `v` list / tree (processes box).

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
    Socket -> cgroup -> app id / unit: `app-gnome-brave\x2dbrowser-<n>.scope`,
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

Built 2026-10-26: commands, auth, kernel, logs and posture, each full width, one under
the other (the cmd / what columns need the room; when the screen is short the tallest box
gives up lines first, core/render.py).

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
  - `user_emulation` = setuid exec (uid != euid): sudo itself, pkexec, nvidia-modprobe
  - `root_cmds` = what runs as root after it (uid = euid = 0, auid = login user)
- Launch = a setuid launcher (sudo, pkexec, su). Any other setuid program runs as root
  itself (host 2026-10-25: nvidia-modprobe -> `modprobe nvidia`): a root run, via its
  parent if seen, else `setuid`.
- Row = one group: who (auid) > as (euid), exe + normalized argv.
  Cols: last, n, who>as, via, cmd. Normalized for grouping only: numbers, hex ids, IPs,
  UUIDs -> placeholder (same as logs).
- Via sudo: the command's ppid is the sudo monitor (fork, no execve, gone at once), and
  `use_pty` gives the command a new pty. Join: `root_cmds` argv == USER_CMD `cmd`, same
  ses, within 5 s -> via `sudo <tty of the sudo launch>`. Else parent = exe of an execve
  already seen (pid), else `ppid <n>`. No `/proc` lookup (2026-10-20): read seconds
  later, the pid may be reused -> wrong parent. (ProtectProc=default since 2026-10-26
  for the program card, which checks the process start; via / parents unchanged.)
- `unix_chkpwd` (1-2 per password prompt): never a row, folded into its parent's row
  (sudo launch, sudo run by root, gdm-session-worker). Parent not seen: counted only.
- Launch without a root child (sudo -k / -l, sudoedit, denied sudo):
  own row, dim (tone `dim`). Nothing hidden. Built 2026-10-25: the launch is a row at
  once, its root command takes it back (no timer: a 5 s wait turned a slow password
  prompt into a launch without a command). Details: docs/modules/security.md.
- Detail: last 5 distinct full argv, parents (chain of root runs seen, e.g.
  `bash 44494 < su 44491 < sudo pts/0`), cwd, first / last, ses, pid / ppid, key; via
  seen when a group came in more than one way.
- Secrets: always masked in rows. Detail: masked, `m` shows the raw argv (same key as
  IPs). Masked: values of `--password --passwd --token --secret --api-key`,
  `user:pass@` in URLs, `*_PASSWORD= *_TOKEN= *_SECRET=`. Argv is readable by every user
  in `/proc/<pid>/cmdline` and stored in audit + journal anyway: this only keeps it off
  the screen.
- Rating (decided + built 2026-10-25): watch list `/etc/sectop/watch.toml` (root-owned,
  same file checks as config, defaults in deploy/watch.toml). Row sev = its rule: crit
  turns a protection off, warn changes a security setting, info routine change, no rule
  ok. Alert for crit only (red only in the bar), while its last run is under 1 h old.
  Changes nothing on the host. Details: docs/modules/security.md, Watch list.
- Root or normal user: every row ran as root (euid 0); normal-user execs are not
  audited (volume). Users, live process tree, zombies: screen 3 (see Processes screen,
  2026-10-27).

### Auth

Built 2026-10-25 (docs/modules/security.md, auth box). Decided 2026-10-25: red =
dangerous or suspicious, worth following up, not everything.

- PAM: USER_AUTH (sudo, su, gdm, polkit agent helper): failed -> warn, ok -> info.
- faillock: RESP_ACCT_LOCK (2207) -> crit. Host check 2026-10-25 (throwaway user, deny
  5): 2100 + 2207 at the 5th failure, syslog "Consecutive login failures for user ...
  account temporarily locked" (PRIORITY 6, not used); `faillock --reset` = USER_MGMT
  op=faillock-reset -> info.
- sudo refused by policy: syslog PRIORITY 1 "user NOT in sudoers" / "command not
  allowed" / "user NOT authorized on host" -> crit. "N incorrect password attempts":
  not a row (USER_AUTH has them). sudo syslog splits at 980 bytes (sudoers(5)
  `syslog_maxlen`): only the reason and TTY are read.
- su by a non-root user -> crit (su is closed on my host, sudo only).
- Alert = crit row, 1 h window (as the watch list).
- Logins (logind sessions, USER_START) and polkitd lines: not used (logs box, step 7).

### Kernel

Built 2026-10-26 (docs/modules/security.md, kernel box; table agreed 2026-10-25).

- Taint: `/proc/sys/kernel/tainted` (file). Bit new since the first read this boot:
  W -> warn; D L M B -> crit (docs.kernel.org tainted-kernels: the kernel stays tainted
  after the cause is gone). Boot value decoded in posture. 2026-10-20: 12288 = O + E.
  O E P new -> crit (2026-10-25), any other new bit -> warn (2026-10-26). Host check
  2026-10-26: the sectop.service sandbox reads it (`ProtectKernelTunables=yes` makes
  `/proc/sys` read-only, not unreadable; nsenter into the unit as user sectop: 12288).
- Modules: audit `kernel_modules` (SYSCALL + KERN_MODULE name), matched by syscall
  number (the kmod `perm=x` rule gives execve records with the same key). Group: name,
  action, exe, result, login. auid set (manual load) -> warn, auid unset (autoload) ->
  info.
  Boot 2026-10-20: 38 autoloads ok; 37 failed loads of `nvidia` by kmod, auid 60578
  (GDM greeter, systemd.io UIDS-GIDS: 60578-60705) and 1000, dGPU off (Integrated).
  Noise entry until akmod-nvidia is removed.
- Blocked load (CIS `install <mod> /bin/false`, e.g. `modprobe sctp`): no init_module
  call, so no `kernel_modules` record. Shown in the modules group from the root command
  (modprobe / insmod argv): its child `sh -c -- /bin/false` = blocked -> info.
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
  PRIORITY 0-2 -> crit, 3 -> warn, 4 -> info. Grouped by normalized line (`[..]` too:
  ACPI paths).
  Boot 2026-10-20 (5.3 h): 196 lines, 33 groups. `NVRM` 84 (akmod-nvidia, dGPU off) and
  ACPI BIOS errors ~70 at boot: noise entries. `nvidia: loading out-of-tree module
  taints kernel` = the O taint.
- USB: "New USB device found" -> idVendor:idProduct + Product -> info.

### Program card (phase 4)

Built 2026-10-26 (agreed: key `c`, ProtectProc=default for the collector). `c` on any row
that knows its program: every row of every box of every screen with the same program,
as a table: select a row, `enter` = its full detail, `Esc` back (core/render.py card,
docs/module-interface.md, Card). `enter` on a box row stays the detail.
- Identity = core/proc.py program(): innermost unit / app id of the cgroup (moved from
  modules/firewall/conns.py). Login / sudo session scopes are not programs: from such a
  scope the live process tree is walked up (/proc/<pid>/stat ppid, max 8) to the first
  process outside it, e.g. `sudo ./install.sh` -> systemctl -> the terminal (host
  2026-10-26: install.sh commands had no program). A parent that ended hands its
  children to pid 1: the walk stops there, no name.
- Row `progs`: firewall programs / audit / peers (ss --cgroup); security commands,
  auth, kernel (modules, AVC, blocked loads), logs audit keys: the record's pid, else
  its parent, read from `/proc/<pid>/cgroup` in the same collect, only when
  `/proc/<pid>/stat` says the process started before the record (no name rather than a
  wrong one: the 2026-10-20 rule "no /proc lookup, pid reuse" kept for via / parents);
  logs journal lines: `_SYSTEMD_CGROUP` of the entry.
- sectop.service `ProtectProc=default` (was invisible): the collector reads other users'
  `/proc/<pid>/{stat,cgroup}`. The same view as any local user on Fedora (no hidepid);
  environ, fd, mem need ptrace access (no CAP_SYS_PTRACE): closed. Net and whois units
  stay invisible. Screen 3 needs the same.
- Not shown: file access and plain (non-root) execs (not audited, volume); a process
  gone before the collect reads it (short root commands from a terminal: the parent's
  program when it still runs, else none).

## Processes screen (2026-10-27)

What runs, what it costs, how hot. Screen 3. Design agreed 2026-10-27, built step by step
(see Plan below). Read-only: actions stay the last phase.

    +-------------------------------------------------------+
    | system: cpu, memory, swap, load, pressure, disk, temp |
    +-------------------------------------------------------+
    | services (system units)                               |
    +-------------------------------------------------------+
    | processes                                             |
    +-------------------------------------------------------+

Full width, one under the other (as the security screen). Module `system`
(modules/system) in the collector: no new unit, no capability, no root. Files only,
except `systemctl show` (posture runs it already as user sectop).

### Scope

- Services: system units only (`/sys/fs/cgroup/system.slice/**`). User units
  (`user@<uid>.service`, `user.slice`) = my private data: not listed.
- Processes outside `user.slice`: one row per process.
- Processes of a login user: one row per program (core/proc.py, app id / unit), cpu +
  memory only. No argv, no pid list. Root processes in a session scope (sudo, root
  shell): own rows (they run as root).
- argv: system processes only, detail only, masked as the commands box (`m` = raw).
  Never in rows. Read for the shown rows only.
- Temperatures: CPU, NVMe, RAM (hwmon names in config `sensors`, defaults `coretemp`,
  `nvme`, `spd5118`, checked on host 2026-10-27). dGPU not used (Integrated mode): not
  read. Other hwmon (battery, ACPI zone, Wi-Fi, cable NIC, fan curves): not shown.
  - coretemp: `Package id 0` only (per core: hottest core in the detail, not built
    yet). max = crit = 100 C: no warn from the sensor, warn from config (default 75 C
    for 60 s, 2026-10-27).
  - nvme: `Composite` only (max 80.8, crit 84.8). Its other sensors report max
    65261.8 C (not set): a limit over 200 C counts as none.
  - spd5118: one per RAM module (2 on host, max 55, crit 85), no label: named by its
    i2c device (`/sys/class/hwmon/hwmon*/device`), not the hwmon number (changes per
    boot).

### Sources

| box | data | source | every |
|---|---|---|---|
| system | cpu | `/proc/stat` (cpu line, delta) | 5 s |
| system | memory, swap | `/proc/meminfo` (MemAvailable, SwapTotal - SwapFree) | 5 s |
| system | load | `/proc/loadavg` | 5 s |
| system | pressure | `/proc/pressure/{cpu,memory,io}` (some / full avg60) | 5 s |
| system | disk io | `/proc/diskstats` (whole disks only) | 5 s |
| system | disk space | `os.statvfs` of `/var` and `/boot` (Silverblue: `/` is the image) | 60 s |
| system | temperature | `/sys/class/hwmon/hwmon*/{name,temp*_input,_label,_max,_crit}` | 5 s |
| services | cpu, memory, oom | cgroup `cpu.stat` (usage_usec), `memory.current`, `memory.events` | 5 s |
| services | state, restarts | journal: systemd unit messages (`UNIT=`, result, restart counter) | live |
| services | watched units | `systemctl show -p Id,ActiveState,SubState,NRestarts` | 30 s |
| processes | cpu, rss, state, ppid | `/proc/<pid>/stat` | 5 s |
| processes | uid | `os.stat("/proc/<pid>").st_uid` (no open) | 5 s |
| processes | program | `/proc/<pid>/cgroup`, once per pid + start time | new pids |
| processes | argv | `/proc/<pid>/cmdline`, shown system rows only | 5 s |

- sectop.service sandbox: `ProtectKernelTunables=yes` and `ProtectControlGroups=yes`
  make `/sys` and the cgroup tree read-only, not unreadable; `ProtectProc=default`
  (2026-10-26) gives other users' `/proc/<pid>/{stat,cgroup,cmdline}`. To check on host
  inside the unit (nsenter as user sectop), as for the kernel taint.
- CPU % = delta of usage between two reads, of the whole CPU (all cores = 100 %, as
  the services' cgroup numbers). Pid key = pid + start time (pid reuse).
- No per-process disk io: `/proc/<pid>/io` needs ptrace access (no CAP_SYS_PTRACE in
  the collector, kept so). Disk io per service from cgroup `io.stat` instead.

Host checks 2026-10-27 (sandbox: nsenter into sectop.service as user sectop):
- `/proc/pressure/*`, `/sys/fs/cgroup/system.slice/*/memory.current`, hwmon
  `temp*_input`, other users' `/proc/<pid>/stat`: readable. system.slice controllers:
  cpuset cpu io memory pids. 39 system services, 477 processes.
- Pressure idle: all avg60 0.00. Limits after a week of numbers.
- Journal, systemd unit messages (`_PID=1`, user manager the same), `MESSAGE_ID`:
  `39f53479...` started, `7d4958e8...` starting, `98e32220...` main process exited,
  `d9b373ed...` failed (`UNIT_RESULT=`), `5eb03494...` restart scheduled
  (`N_RESTARTS=`), `be02cf68...` failed to start (`JOB_RESULT=failed`), `ae8f7b86...`
  resources consumed (CPU time, memory peak). Stop: to check.
- auditd.conf (root, read once): `space_left = 75`, `admin_space_left = 50` (MB).
- sectop.service before screen 3: anon 19 MiB, file cache 84 MiB (memory peak 128M =
  MemoryMax is cache from the journal files), swap 2 MiB. CPU: to measure per minute.

### Boxes

- system: one row per metric: metric, now, peak 5m, limit, info. Rows: cpu, load,
  memory, swap, pressure cpu / memory / io, io per whole disk, `/var`, `/boot`, one row
  per sensor. Built 2026-10-27:
  - Numbers only, no bars (my call after the first host run 2026-10-27: bars are hard to
    read). peak = highest of the last 60 reads (5 min); limit = size, 100 %, cpus (load),
    crit (temp). The table column type `spark` stays in core (docs/module-interface.md),
    not used here.
  - pressure: some avg60 now, peak of avg10, no limit yet (a week of my host's numbers).
  - io: whole disks from `/sys/block` without loop, ram, zram (swap row), dm (same io as
    the disk under it). Host: nvme0n1.
  - `/boot`: row only, no check.
  - sensor names: cpu, nvme, ram + i2c device when a name is there twice (`ram
    14-0050`). Check key = hwmon name + device + temp number (hwmon number changes).
  - warn limits (config `temp_warn`, per hwmon name): coretemp 75, spd5118 70 (my host:
    37-43 C idle, 50-70 only in a game; sensor max 55 would be yellow in every game).
    nvme: sensor max 80.85. crit always from the sensor.
- services: sev, unit, state, cpu, mem, oom, restarts, last change. Watched units and
  problems first, then by cpu. Detail: last state changes this boot, result, restarts,
  memory peak.
- processes: sev, pid, user, program, comm, state, cpu, mem, age. Top 30, plus every
  zombie and every `D` (uninterruptible) process. Zombie: row names its parent.
  - `s` sort: cpu -> mem -> pid -> program. cpu sorts by the mean of the last ~30 s
    (rows stay put), the cell shows the last tick.
  - `v` view: list <-> tree (children under their parent).
  - Detail: cpu spark, mem, threads, state, running since, parent chain up to pid 1
    (`/proc/<pid>/stat` ppid, max 32), user, argv (system processes, masked).
- Ideas from btop (Apache-2.0, 2026-10-27): tree view, sort switching, a sort that
  follows time, a process detail with its own graph. Ideas only: own code, own keys
  (one meaning on every screen), no btop key bindings. Credit in README.
- programs (built 2026-10-27, before services): one row per program (core/proc.py
  name of the cgroup; a login session: `comm (session)`, no card), kernel threads left
  out. Columns: program, procs, cpu, peak, mem (sum of rss), peak, user. By memory, top
  30. enter = its processes (top 20 by memory: pid, comm, mem, cpu, state, threads,
  user; no argv); c = card. The cpu and memory rows of the system box: their detail
  names the top 8 programs, c = the card of the top one. One /proc scan per collect
  (stat + owner; cgroup once per pid + start): ~9 ms for 460 processes in a test box,
  my host: to measure (step 6).
  Zombies and D processes (my ask, same day): own rows on top of the programs box
  (`comm (zombie, parent X)`, `comm (D)`), info while new, warn + check after 60 s in
  that state (from the first scan that saw it so; a D process that wakes up starts
  over). A zombie is not in its program's sums; c = its parent's card (the parent must
  reap it). Box title counts both. Max 20 rows, 10 checks + one `stuck:more`.
  Strays (2026-11-03, my ask: no app may hide in GNOME Shell's cgroup): a process in
  `org.gnome.Shell@<x>.service` that is not GNOME Shell's own (gnome-shell, Xwayland,
  bwrap, glycin-*; core/proc.py SHELL_OWN). The org.gnome.Shell row lists them first
  (`not GNOME's own: brave x10, cat x2`, pids), info while new, warn + one check per
  cgroup `shared_cgroup:<unit>` after 10 s (a launch moves in ms: one scan may catch
  it). Always shown, even outside the top 30. Fix: silverblue-cis-hardening appunit.
  Enforcement: hostfw rejects network from that cgroup (hardening repo, planned).
- Program card (`c`): rows here carry `progs`, so the card shows a program's processes,
  units and the other screens' rows together.

### Severity (red rule, 2026-10-25)

crit (red, alert):
- temperature >= `temp*_crit` of that sensor (no crit file: never red)
- watched unit not active (stopped, failed, gone). Config `watch_units`, default
  `auditd`, `firewalld`, `hostfw`, `sectop-net`. hostfw is oneshot + RemainAfterExit:
  `active (exited)` = ok. Journal = at once, `systemctl show` = state at start + missed
  lines.
- `/var` free below auditd `admin_space_left`: audit is suspended (hardening repo:
  `admin_space_left_action` + `disk_full_action` = SUSPEND). auditd.conf is root 0640:
  values copied into config, not read.
- OOM kill inside a watched unit

warn (yellow, row; alert only when it lasts):
- OOM kill elsewhere (kernel or systemd-oomd)
- temperature >= warn limit for 60 s: config `temp_warn` (coretemp 75, spd5118 70), else
  `temp*_max` when max < crit
- zombie or `D` process older than 60 s
- process in GNOME Shell's cgroup that is not GNOME's own, for 10 s (`shared_cgroup`)
- unit restarted 3 times in 10 min
- pressure avg60 over the limit for 2 min. Limits set from my host's numbers (step 1),
  not invented.
- `/var` free below auditd `space_left`
- unit failed (not watched): row only, the alert stays with posture `failed-units`

info (cyan): unit restart, start / stop of a unit that is not watched.

One alert per cause: auditd / firewalld down = this module (seconds). Posture
`auditd-active` / `firewalld-active` keep their rows, without a second alert. hostfw mode
stays on the firewall screen.

### Resources

- Budget for the module: < 300 ms CPU per minute (half of the collector's 1%).
- Per tick: one `/proc` scan, `stat` only per pid; `cgroup` for new pids only; `cmdline`
  for shown rows only. No `status`, no `fd`, no `environ`.
- state.json: top 30 processes + zombies / `D`, all system units (count on host).
- Runs always (the collector cannot know the screen is hidden, see Resources). If the
  budget does not hold: process scan every 10 s, system + services stay 5 s.

### Actions

Unchanged (2026-10-27: keep the order): last phase, stop / restart from the services
box via polkit, confirm, deny list (see Actions).

### Plan

1. Host checks: done 2026-10-27 (see Sources). Left: unit stop message, scan time.
   Fixtures in tests/fixtures/system/ (fake trees, privacy rule) with each box.
2. system box + its checks: done 2026-10-27 (modules/system, fixtures
   tests/fixtures/system/host: fake tree, hwmon names and files as on my host).
3. programs box (moved up 2026-10-27, my ask: "enter or c on memory must show what
   takes it"): done (modules/system/procs.py), see Boxes.
4. services box (cgroup, journal, watched units); posture: no second alert.
5. processes view (parent chain) + keys `s`, `v`, inside the programs box. Zombies and
   `D`: done 2026-10-27 (rows on top of the programs box).
6. Measure sectop.service CPU before / after, docs/modules/system.md, README legend.
7. First public release: tools, requirements, dependencies.

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
- Bar: warn / crit only. Info alerts (e.g. out_lan drops) and noise alerts are counted on
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
- Hidden screen: the collector cannot know which screen is shown (one-way: the UI never
  writes to it, see Privilege split). Changed 2026-10-27: no `visible`, every module
  stays cheap enough to run always (process scan: see Processes screen, Resources).
- Slow checks on their own interval:
  - updates: once per day. Silverblue: `rpm-ostree` (no dnf), plus flatpak.
  - posture: minutes, not seconds.
- Command timeouts below the module interval.

## Security posture

Built 2026-10-26 (docs/modules/posture.md): module `posture`, below the security boxes.
Agreed table + host checks (sandbox, user sectop) 2026-10-26; the list below is the
plan of 2026-10-20, kept for history.

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
    `op=add_rule` - `op=remove_rule` this boot (2026-10-20: 70, verification.md ~70; 72 with af-alg 2026-11-01;
    73 with mullvad-exclude in the setuid list)
  - taint: decoded, expected bits in the policy (none since step 9, 2026-10-26)
  - failed units: `systemctl list-units --state=failed`
  - updates: `rpm-ostree status --json`, cached only, once per day (collector has no
    network)
  - wifi: `ipv6.method` disabled on every wifi profile (nmcli)
- Open: flatpak updates without network. Solved 2026-10-26: firewalld default zone
  via `firewall-cmd --get-default-zone` (works as user sectop).
- Needs root, not checked: `auditctl -l` / `-s` (CAP_AUDIT_CONTROL), `/var/run/faillock`.

## Logs

Built 2026-10-26 (docs/modules/security.md, logs box). Changed from the plan below:
grouped by identifier (not unit: every sudo has its own session scope), file watches
rated by their owner program, SELINUX_ERR added, noise marks rows (dim) instead of
hiding them.

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
    sectop-user@<me>     my user, no caps, no network -> /run/sectop-user/<me>/
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
  Written after every collect and every 5 s. No update for 3 x `interval` of the state
  (longest module interval, at most the 5 s heartbeat; min 15 s) -> UI shows crit alert
  "collector: <why>". Capped 2026-10-26: posture runs every 300 s, uncapped the UI would
  notice a dead collector after 15 min.
- Capabilities only where the kernel requires them: `nft list` and `wg show` need
  CAP_NET_ADMIN even to read (tested 2026-10-20, transient unit as nobody: works with
  the capability only, "Operation not permitted" without). CAP_NET_ADMIN can also change
  the firewall -> net unit, own user, `AmbientCapabilities=` + the same
  `CapabilityBoundingSet=`. Fixed argv (`modules/firewall/netcmds.py`: argv only, the
  only firewall code it imports), takes no input. Raw result per command:
  `/run/sectop-net/<name>.json` (argv, rc, out, err, ts), group `sectop`. Every half
  firewall interval: nft table, wg handshakes + transfer + listen-port (posture
  listeners, 2026-10-26). Every half SLOW: wg endpoints + fwmark, nft sets wg_fwmark +
  vpn_api4, nft table inet mullvad. Not in the collector: ambient capabilities pass to
  every child (capabilities(7)).
- Program names: `ss -p` needs CAP_SYS_PTRACE (capabilities(7): /proc/pid/fd of other
  users). Too strong for a monitor -> `ss --cgroup` (see Firewall audit).
- User helper (2026-11-03): the cgroup names no program for processes in GNOME Shell's
  shared cgroup (org.gnome.Shell@<x>.service: an app whose launcher forked before GNOME
  moved it). `sectop-user@<me>.service` (system template unit, `User=%i`) runs as my
  user: same uid = may read the fds of my own processes, no capability. Reads only my
  shared cgroups' processes: comm + socket inodes (`socket:[<ino>]`) ->
  `/run/sectop-user/<me>/socks.json` (dir 0750, file 0640, group sectop set by the
  helper; it refuses to run if my user is not in group sectop). Collector: socket inode
  (`ss -e`) -> process, display only (my user can write anything there, a process sets
  its own comm): never a check. No root service, no CAP_SYS_PTRACE (decided 2026-11-03).
  `PrivateNetwork=yes`, `IPAddressDeny=any`, `AF_UNIX` only, `ProtectProc=default` (my
  own processes), no `RemoveIPC=` (would remove my desktop's IPC objects on stop).
  Not dumpable processes (fd unreadable): `denied`, no name.
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
  firewalld, hostfw, mullvad-daemon, sshd if present.
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

Colors 2026-10-27 (my call after the first screen 3 run: "not only white, the eye must
land on what matters"). 256-color terminal (xterm numbers), else the 8 basic colors:

| role | color | where |
|---|---|---|
| frame | white 255 | box frames |
| title | purple 141, bold | box titles, table headers (+ underline), active tab (reverse) |
| name | lavender 147 | first column, kv keys, detail keys, event source |
| text | pale lavender 189 | other text columns, kv values, detail values, summaries |
| value | cyan 117, bold | numbers of an ok row: safe; `severity ok` in a detail |
| high | orange 215, bold | value at 75 %+ of its limit, before any warn (row `level`) |
| peak | pink 212 | peak columns |
| note | grey 246 | limits, ages, hints, inactive tabs, key help |
| info | blue 111 | info (was cyan: cyan is safe now) |
| warn | yellow 222 | warn only |
| crit | red 196, bold | crit only |
| unknown | magenta 201 | no data |

Tones: blue (allowed) and green (healthy) are both safe now: cyan. Soft red, soft yellow,
dim unchanged. A warn / crit row: whole row in its color; its detail shows the row's
cells and the module's problem lines (`sev` on a detail pair) in that color, so the eye
lands there first. Preview scripts were run in my terminal before (not in the repo).
Selected line (after the first run with colors, 2026-10-27): one reverse bar the whole
width, plain, or the row's own color when it has one (severity / tone): a color per
column made a patchy bar.

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
  3. commands box + watch.toml: done 2026-10-25 (modules/security,
     docs/modules/security.md).
  4. auth box: done 2026-10-25 (modules/security/auth.py, fixtures 2026-10-25).
  5. kernel box: done 2026-10-26 (modules/security/kernel.py).
  6. posture module + posture.toml: done 2026-10-26 (modules/posture,
     docs/modules/posture.md).
  7. logs box: groups, noise on groups, audit keys: done 2026-10-26
     (modules/security/logs.py).
  8. program card: done 2026-10-26 (key c, core/proc.py, ProtectProc=default).
- Then screen 3 (processes): design decided 2026-10-27, see Processes screen.

## Contract changes (Snapshot v2)

- `checks`: conditions for the alert engine. Done (docs/module-interface.md, Checks).
- Panel layout hint `width`: `full` done (audit box). Planned: half, min height.
- `collect(state, ctx)`: done 2026-10-25 (journal entries). ctx `visible` dropped
  2026-10-27: the collector cannot know (see Resources).
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
   System = screen 3, see Processes screen (plan). Then the first public release.
5. Actions.
