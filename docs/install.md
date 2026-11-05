# Install

sectop runs as separate parts (docs/architecture.md, Privilege split):

| part | user | rights | writes |
|---|---|---|---|
| sectop-net.service | sectop-net | CAP_NET_ADMIN only, no network | /run/sectop-net/*.json |
| sectop.service (collector) | sectop | groups systemd-journal + sectop-feed, no capabilities, no network | /run/sectop/state.json |
| sectop-whois.socket + sectop-whois@.service | dynamic, per lookup | network only | the answer, on the socket |
| sectop-user@<desktop user>.service | desktop user, group sectop-feed (unit `Group=`) | no capabilities, no network; reads its own processes' fds in GNOME Shell's cgroup | /run/sectop-user/<desktop user>/socks.json |
| sectop (UI) | admin (the sudo user), no sudo | group sectop: reads /run/sectop, connects to the whois socket | nothing |

Two accounts (admin on the text console, daily user in GNOME, no sudo):
`sudo ./install.sh --desktop-user <daily>` from the admin. One account: `sudo ./install.sh`,
admin and desktop user are the same.

## Check first

    sudo ./install.sh --check

Changes nothing. Must-haves (missing = install stops before writing anything): systemd
as init, /usr/bin/python3 >= 3.11, git, journalctl, systemctl, systemd-sysusers.
Extras (missing = warning, the install goes on, boxes stay empty): journald audit
socket, auditd + rule key root_cmds, nft / ss / ip, table inet hostfw, wg, restorecon.
`sudo ./install.sh` runs the same check first.

## Install / update

    cd ~/my-project/sectop                   # the admin's own clone
    sudo ./install.sh --desktop-user null    # two accounts: run by the admin, daily user null
    sudo ./install.sh                        # one account

- Installs git HEAD: commit first. Uncommitted changes -> warning, not installed.
- `git archive HEAD` (as the sudo user) -> `/usr/local/lib/sectop`, without tests/. Root-owned,
  dirs 0755, files 0644, bin/* 0755, byte-compiled. Old tree replaced in one rename.
  Silverblue: `/usr/local` -> `/var/usrlocal`, kept across rpm-ostree updates.
- `/usr/local/bin/sectop` -> `/usr/local/lib/sectop/bin/sectop` (symlink).
- `/etc/sysusers.d/sectop.conf` = deploy/sectop.sysusers + `m <admin> sectop`, then
  `systemd-sysusers`: groups sectop + sectop-feed (no members), system users sectop and
  sectop-net (no login, home /). sysusers adds, never removes: a desktop user still in
  group sectop (older install) -> warning, `sudo gpasswd -d <daily> sectop`, then it logs
  out and in.
  `/etc/sysusers.d` is created first: Silverblue does not have it (first install
  2026-10-20 stopped there: "No such file or directory").
- `/etc/sectop`: 0755, `*.toml` 0644 root:root (read by the sectop users; no secrets).
- `/etc/sectop/watch.toml` (security screen, rating of root commands): copied from
  deploy/watch.toml when missing, never over mine. Mine differs from the shipped one:
  `kept` in the log (`diff` it to see new defaults).
- `/etc/sectop/posture.toml` (security screen, posture checks): same as watch.toml,
  from deploy/posture.toml when missing, never over mine. `"@admin"` in its want lists
  (wheel, sectop, mullvad members) -> the sudo user, in the installed copy
  (`/usr/local/lib/sectop/deploy/posture.toml`), before the compare.
- Units from deploy/ -> `/etc/systemd/system`, daemon-reload, enable, restart:
  sectop-net.service, sectop.service, sectop-whois.socket, sectop-user@<desktop>.service
  (user helper; optional: without it sockets from GNOME Shell's shared cgroup stay
  `org.gnome.Shell/?`). A helper instance of another user is stopped and disabled.
- `--desktop-user NAME`: login account (uid >= 1000), not root. Warnings when NAME is in
  wheel or sectop.
- SELinux labels: restorecon on everything it wrote.
- First install: the admin is new in group sectop -> log out and in once.

## Run

    sectop [SCREEN]          # firewall | security | processes | 1-3

Collector, net unit and UI refuse to run as root (rc 2). No more
`sudo python3 -m core.app`: that ran code from my home as root.

## Check

    systemctl status sectop-net.service sectop.service sectop-whois.socket
    systemctl status sectop-user@null.service          # the desktop user
    ls -l /run/sectop /run/sectop-net /run/sectop-whois.sock /run/sectop-user/null
    # want: /run/sectop-user/null null:sectop-feed 0750, socks.json 0640
    id null                                            # want: no sectop, no sectop-feed
    journalctl -b -u sectop-net -u sectop -u 'sectop-whois@*'
    systemd-analyze security sectop.service sectop-net.service sectop-whois@x.service
    # sectop's own commands are no longer root_cmds (expect 0 after the install time):
    journalctl --since "<install time>" _TRANSPORT=audit -g 'key="root_cmds"' -o cat \
      | grep -cE 'exe="/usr/(s)?bin/(nft|wg|ss|ip|journalctl)"'

Offline rating 2026-10-20 (`systemd-analyze security --offline=yes`, systemd 255):
sectop 1.1, sectop-net 1.3, sectop-whois 1.2 (OK). Stricter syscall filters for the
collector and the net unit after the live test (nft, ss, journalctl: EPERM in the journal).

## Remove

    sudo ./install.sh --remove

Stops and removes the units (every sectop-user@ instance too), `/usr/local/lib/sectop`,
the launcher and the sysusers file.
Kept: `/etc/sectop`, users sectop / sectop-net and groups sectop / sectop-feed
(`userdel sectop; userdel sectop-net; groupdel sectop; groupdel sectop-feed` by hand).
