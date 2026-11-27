# Install

sectop runs as separate parts (docs/architecture.md, Privilege split):

| part | user | rights | writes |
|---|---|---|---|
| sectop-net.service | sectop-net | CAP_NET_ADMIN only, no network | /run/sectop-net/*.json |
| sectop.service (collector) | sectop | groups systemd-journal + sectop-feed, no capabilities, no network | /run/sectop/state.json |
| sectop-whois.socket + sectop-whois@.service | dynamic, per lookup | network only | the answer, on the socket |
| sectop-user@<desktop user>.service | desktop user, group sectop-feed (unit `Group=`) | no capabilities, no network; reads its own processes' fds in GNOME Shell's cgroup | /run/sectop-user/<desktop user>/socks.json |
| sectop-home@<desktop user>.service | sectop-home, group sectop-feed | no capabilities, no network; lstat + list of the desktop home's start places (ACL entries the desktop user sets), never file content | /run/sectop-home/<desktop user>/report.json |
| sectop-ids.service (only when Suricata's group suricata exists) | sectop-ids, group sectop-feed + suricata | no capabilities, no network; reads Suricata's eve.json, read only, counts alerts per rule + source | /run/sectop-ids/summary.json |
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
    # helper "activating (auto-restart)", status=226/NAMESPACE: systemd could not set up
    # its mount namespace. journalctl -u sectop-user@null names the path, and
    # ausearch -m AVC -ts recent shows an SELinux denial if that was the cause
    id null                                            # want: no sectop, no sectop-feed
    journalctl -b -u sectop-net -u sectop -u 'sectop-whois@*'
    systemd-analyze security sectop.service sectop-net.service sectop-whois@x.service
    # sectop's own commands are no longer root_cmds (expect 0 after the install time):
    journalctl --since "<install time>" _TRANSPORT=audit -g 'key="root_cmds"' -o cat \
      | grep -cE 'exe="/usr/(s)?bin/(nft|wg|ss|ip|journalctl)"'

Offline rating 2026-10-20 (`systemd-analyze security --offline=yes`, systemd 255):
sectop 1.1, sectop-net 1.3, sectop-whois 1.2 (OK). Stricter syscall filters for the
collector and the net unit after the live test (nft, ss, journalctl: EPERM in the journal).

## New setuid / setgid programs

    sudo ./install.sh --setuid-accept

`/etc/sectop/setuid-known.txt` (root:root 0644): the setuid / setgid programs under /usr I
have seen. The first install writes it from /usr (`find /usr -xdev -type f -perm /6000`);
after that only this option changes it. It lists every new program with its package
(`rpm -qf`), owner and mode, and every one that left, then asks; y = the list is /usr now.
Posture `setuid-known` is yellow while a program is not on the list.

## Home watch

Posture `home-watch`: the places in the desktop user's home a program can set itself to
run again from (core/homed.py `SPOTS`: autostart, user units and manager config,
environment.d, shell start files, ~/bin and ~/.local/bin, D-Bus services, GNOME Shell
extensions, Files scripts, completions, desktop files, podman, git config, ~/.ssh, ...).
Type, mode, owner, size, mtime, ctime, inode, link target; never content. Changed /
new / gone / unreadable: yellow until the admin accepts it.

Read access: user sectop-home needs `x` on each folder on the way and `r-x` on the
watched folders, given by the desktop user's own account (root never reads the home).
silverblue-privacy-hardening's `homelock` section sets it; by hand, as the desktop user:

    setfacl -m u:sectop-home:x ~ ~/.config ~/.local ~/.local/share
    setfacl -m u:sectop-home:rx ~/.config/autostart ~/.local/bin   # each watched folder

Without it every place shows `unreadable` (the row still works: an ACL taken away later
shows as a change). The home's mode shows 710 then (ACL mask), group still gets nothing.

First list and every change seen:

    sudo ./install.sh --home-accept

Lists what differs from `/etc/sectop/home-known.txt` (root:sectop 0640), then asks; y =
the list is the report now. Root reads the report in /run, not the home.
Limit: a program running as the desktop user can change a place (shown) or take the
access away (shown), not the report; one running as root can do anything (silverblue-
privacy-hardening AIDE watches `/etc/sectop`).

## LAN: trusted routers

The lan box (screen 1, docs/modules/lan.md) compares the router's MAC with the routers
accepted for the network. On a network I trust (my own, or the owner agrees), once:

    sudo ./install.sh --lan-accept

Shows the network id (8 hex digits, no Wi-Fi name), the router's address and whether it
is already accepted, then asks `1 accept / 0 stop`. The first accept makes
`/etc/sectop/lan.key` (32 random bytes); the list is `/etc/sectop/lan-known.txt`; both
root:sectop 0640, ids only (HMAC-SHA256, no MAC, no Wi-Fi name). A replaced router:
accept again on that network. silverblue-privacy-hardening's AIDE watches `/etc/sectop`:
both files show up once after the first accept.

A DHCP server that is fine besides the router (a Pi-hole):
`[modules.lan] dhcp_ok = ["<address>"]` in `/etc/sectop/config.toml`.

## Remove

    sudo ./install.sh --remove

Stops and removes the units (every sectop-user@ / sectop-home@ instance too), `/usr/local/lib/sectop`,
the launcher and the sysusers file.
Kept: `/etc/sectop` (config, lists, lan.key), users sectop / sectop-net / sectop-home and groups sectop /
sectop-feed (`userdel sectop; userdel sectop-net; userdel sectop-home; groupdel sectop;
groupdel sectop-feed` by hand; the desktop user: `setfacl -R -x u:sectop-home ~`).
