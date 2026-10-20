# Install

sectop runs as separate parts (docs/architecture.md, Privilege split):

| part | user | rights | writes |
|---|---|---|---|
| sectop-net.service | sectop-net | CAP_NET_ADMIN only, no network | /run/sectop-net/*.json |
| sectop.service (collector) | sectop | group systemd-journal, no capabilities, no network | /run/sectop/state.json |
| sectop-whois.socket + sectop-whois@.service | dynamic, per lookup | network only | the answer, on the socket |
| sectop (UI) | my user, no sudo | group sectop: reads /run/sectop, connects to the whois socket | nothing |

## Install / update

    cd ~/my-project/sectop
    sudo ./install.sh

- Installs git HEAD: commit first. Uncommitted changes -> warning, not installed.
- `git archive HEAD` (as my user) -> `/usr/local/lib/sectop`, without tests/. Root-owned,
  dirs 0755, files 0644, bin/* 0755, byte-compiled. Old tree replaced in one rename.
  Silverblue: `/usr/local` -> `/var/usrlocal`, kept across rpm-ostree updates.
- `/usr/local/bin/sectop` -> `/usr/local/lib/sectop/bin/sectop` (symlink).
- `/etc/sysusers.d/sectop.conf` = deploy/sectop.sysusers + `m <my user> sectop`, then
  `systemd-sysusers`: group sectop, system users sectop and sectop-net (no login, home /).
  `/etc/sysusers.d` is created first: Silverblue does not have it (first install
  2026-10-20 stopped there: "No such file or directory").
- `/etc/sectop`: 0755, `*.toml` 0644 root:root (read by the sectop users; no secrets).
- Units from deploy/ -> `/etc/systemd/system`, daemon-reload, enable, restart:
  sectop-net.service, sectop.service, sectop-whois.socket.
- SELinux labels: restorecon on everything it wrote.
- First install: my user is new in group sectop -> log out and in once.

## Run

    sectop [SCREEN]          # firewall | security | processes | 1-3

Collector, net unit and UI refuse to run as root (rc 2). No more
`sudo python3 -m core.app`: that ran code from my home as root.

## Check

    systemctl status sectop-net.service sectop.service sectop-whois.socket
    ls -l /run/sectop /run/sectop-net /run/sectop-whois.sock
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

Stops and removes the units, `/usr/local/lib/sectop`, the launcher and the sysusers file.
Kept: `/etc/sectop`, users sectop / sectop-net and group sectop
(`userdel sectop; userdel sectop-net; groupdel sectop` by hand).
