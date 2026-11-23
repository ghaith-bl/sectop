#!/usr/bin/env bash
#
# install.sh - install sectop from this repo's git HEAD as root-owned code + services.
#
#   sudo ./install.sh                       install or update (HEAD, not uncommitted changes)
#   sudo ./install.sh --desktop-user NAME   same, user helper for NAME (two accounts)
#   sudo ./install.sh --check               requirements only, changes nothing
#   sudo ./install.sh --setuid-accept       new setuid / setgid programs seen: on my list
#   sudo ./install.sh --home-accept         start places in the desktop home as now: accepted
#   sudo ./install.sh --remove              stop + remove units, code, launcher, sysusers file
#
# Users: the one running sudo is the admin: member of group sectop (reads the UI state,
# whois), its name in the posture default (wheel, sectop, mullvad: "@admin"). The desktop
# user (GNOME session) gets the user helper sectop-user@NAME.service and no sectop group;
# its home's start places are watched by sectop-home@NAME.service (user sectop-home).
# One account: no --desktop-user, both are the sudo user.
#
# Why: code a service runs must not be writable by my user (docs/architecture.md,
# Privilege split). git archive HEAD -> /usr/local/lib/sectop, root-owned.
# Silverblue: /usr/local -> /var/usrlocal (writable, kept across rpm-ostree updates).
# Details: docs/install.md
set -euo pipefail

DEST=/usr/local/lib/sectop
BIN=/usr/local/bin/sectop
UNIT_DIR=/etc/systemd/system
UNITS=(sectop-net.service sectop.service sectop-whois.socket sectop-whois@.service sectop-user@.service sectop-home@.service)
SYSUSERS=/etc/sysusers.d/sectop.conf
CONF=/etc/sectop
SETUID_LIST=$CONF/setuid-known.txt
TMP=""

log()  { printf '\e[32m[+]\e[0m %s\n' "$*"; }
warn() { printf '\e[33m[!]\e[0m %s\n' "$*" >&2; }
die()  { printf '\e[31m[x]\e[0m %s\n' "$*" >&2; exit 1; }

relabel() { if command -v restorecon >/dev/null; then restorecon -R "$@"; fi; }

remove() {
  systemctl disable --now sectop.service sectop-net.service sectop-whois.socket \
    >/dev/null 2>&1 || true
  local inst
  for inst in $(systemctl list-units --all --plain --no-legend 'sectop-user@*.service' \
                  'sectop-home@*.service' | awk '{print $1}'); do
    systemctl disable --now "$inst" >/dev/null 2>&1 || true
  done
  rm -f "$UNIT_DIR"/multi-user.target.wants/sectop-user@*.service \
        "$UNIT_DIR"/multi-user.target.wants/sectop-home@*.service
  local u
  for u in "${UNITS[@]}"; do rm -f "$UNIT_DIR/$u"; done
  systemctl daemon-reload
  rm -f "$BIN"
  rm -rf "$DEST"
  rm -f "$SYSUSERS"
  log "removed: units, $DEST, $BIN, $SYSUSERS"
  log "kept: $CONF; users sectop, sectop-net, sectop-home and groups sectop, sectop-feed"
  log "  (by hand: userdel sectop; userdel sectop-net; userdel sectop-home; groupdel sectop;"
  log "  groupdel sectop-feed; the desktop user: setfacl -R -x u:sectop-home on its home)"
}

have() { command -v "$1" >/dev/null 2>&1; }

# preflight: a missing must-have stops before anything is written; a missing extra
# only warns (v0.1 reads what silverblue-cis-hardening sets up: README Requirements)
preflight() {
  local miss=0 c v
  [[ -d /run/systemd/system ]] || { warn "need: systemd as init"; miss=1; }
  if [[ -x /usr/bin/python3 ]]; then
    v=$(/usr/bin/python3 -I -c 'import sys; print("%d.%d" % sys.version_info[:2])')
    /usr/bin/python3 -I -c 'import sys; sys.exit(sys.version_info < (3, 11))' \
      || { warn "need: python3 >= 3.11 (tomllib), found $v"; miss=1; }
  else
    warn "need: /usr/bin/python3 >= 3.11"; miss=1
  fi
  for c in git journalctl systemctl systemd-sysusers; do
    have "$c" || { warn "need: $c"; miss=1; }
  done
  (( miss == 0 )) || die "requirements missing (README Requirements): nothing changed"
  log "must-haves: systemd, python3 $v, git, journalctl, systemd-sysusers"

  systemctl is-active --quiet systemd-journald-audit.socket \
    || warn "systemd-journald-audit.socket not active: no audit records for sectop"
  if ! systemctl is-active --quiet auditd.service; then
    warn "auditd not running: security screen mostly empty"
  elif ! auditctl -l 2>/dev/null | grep 'key=root_cmds' >/dev/null; then
    warn "no audit rule key root_cmds (silverblue-cis-hardening audit-rules): no commands"
  fi
  for c in nft ss ip; do have "$c" || warn "no $c: firewall screen incomplete"; done
  if have nft && ! nft list table inet hostfw >/dev/null 2>&1; then
    warn "no nftables table inet hostfw (silverblue-cis-hardening firewall/): firewall boxes empty"
  fi
  have wg || warn "no wg (wireguard-tools): no tunnel details"
  have restorecon || warn "no restorecon: SELinux labels not set (fine without SELinux)"
  log "posture: /etc/sectop/posture.toml checks my baseline; other hosts: expect fails"
}

install_code() {   # $1 = repo, $2 = admin (runs git, posture default)
  local repo=$1 user=$2
  install -d -m 0755 "$(dirname "$DEST")"
  TMP=$(mktemp -d "$(dirname "$DEST")/.sectop.XXXXXX")     # same filesystem: mv = rename
  trap 'rm -rf "$TMP"' EXIT
  # git runs as my user: root refuses a repo owned by someone else (safe.directory).
  # The redirect stays root on purpose: $TMP is root's, my user must not write there.
  # shellcheck disable=SC2024
  sudo -u "$user" git -C "$repo" archive --format=tar HEAD > "$TMP/head.tar" \
    || die "git archive HEAD failed"
  if [[ -n $(sudo -u "$user" git -C "$repo" status --porcelain --untracked-files=no) ]]; then
    warn "uncommitted changes are not installed (HEAD only)"
  fi
  mkdir "$TMP/new"
  tar -x -C "$TMP/new" -f "$TMP/head.tar"
  rm -rf "$TMP/new/tests"                       # not needed to run; fixtures stay in the repo
  render_defaults "$TMP/new" "$user"
  /usr/bin/python3 -I -m compileall -q "$TMP/new/core" "$TMP/new/modules" >/dev/null
  chown -R root:root "$TMP/new"
  find "$TMP/new" -type d -exec chmod 0755 {} +
  find "$TMP/new" -type f -exec chmod 0644 {} +
  chmod 0755 "$TMP/new/bin/"*
  rm -rf "$DEST.old"
  if [[ -e $DEST ]]; then mv "$DEST" "$DEST.old"; fi
  mv "$TMP/new" "$DEST"
  rm -rf "$DEST.old" "$TMP"
  trap - EXIT
  relabel "$DEST"
  install -d -m 0755 "$(dirname "$BIN")"
  ln -sfn "$DEST/bin/sectop" "$BIN"
  relabel "$BIN"
  log "code: $DEST ($(sudo -u "$user" git -C "$repo" log -1 --format='%h %s'))"
}

# deploy/posture.toml: "@admin" in want lists -> the admin's name (wheel, sectop,
# mullvad members). $2 matched the user name regex in main: safe in sed.
render_defaults() {   # $1 = new code dir, $2 = admin
  local f=$1/deploy/posture.toml
  sed -i -E "/^want = /s/\"@admin\"/\"$2\"/g" "$f"
  if grep -qE '^want = .*"@admin"' "$f"; then die "posture default: @admin left in $f"; fi
}

install_users() {  # $1 = admin (only member of group sectop added here)
  install -d -m 0755 "$(dirname "$SYSUSERS")"   # Silverblue: /etc/sysusers.d does not exist
  { cat "$DEST/deploy/sectop.sysusers"
    printf 'm %s sectop\n' "$1"
  } > "$SYSUSERS.tmp"
  chmod 0644 "$SYSUSERS.tmp"
  mv "$SYSUSERS.tmp" "$SYSUSERS"
  relabel "$SYSUSERS"
  systemd-sysusers "$SYSUSERS"
  log "users: $(id sectop), $(id sectop-net), $(id sectop-home)"
}

put_default() {    # $1 = watch | posture: deploy/$1.toml -> $CONF/$1.toml when missing
  local name=$1
  local file=$CONF/$name.toml defaults=$DEST/deploy/$name.toml
  if [[ ! -e $file && ! -L $file ]]; then            # mine stays mine: never over it
    install -m 0644 -o root -g root "$defaults" "$file"
    relabel "$file"
    log "$name: $file (new, from deploy/$name.toml)"
  elif [[ $(sha256sum < "$file") != "$(sha256sum < "$defaults")" ]]; then
    log "$name: $file kept (differs from $defaults)"
  else
    log "$name: $file (same as deploy/$name.toml)"
  fi
}

check_conf() {     # collector and net unit read the config as non-root users
  install -d -m 0755 -o root -g root "$CONF"
  put_default watch
  put_default posture
  local f
  for f in "$CONF"/*.toml; do
    [[ -e $f ]] || continue
    chown root:root "$f"
    chmod 0644 "$f"
  done
  log "config: $CONF 0755, *.toml 0644 root:root (read by sectop users, no secrets)"
}

# setuid-known.txt: the setuid / setgid programs under /usr I have seen (posture
# setuid-known). The first install writes the ones there now; later only --setuid-accept,
# never an update (silverblue-privacy-hardening gives a new one audit rules by itself).
setuid_scan() { find /usr -xdev -type f -perm /6000 | LC_ALL=C sort; }

write_setuid_list() {   # $1 = paths, one per line
  local tmp
  tmp=$(mktemp "$CONF/.setuid-known.XXXXXX")
  { echo "# setuid / setgid programs under /usr I have seen (sectop posture setuid-known)."
    echo "# Written by install.sh; a new one: sudo ./install.sh --setuid-accept"
    printf '%s\n' "$1"
  } > "$tmp"
  chown root:root "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$SETUID_LIST"
  relabel "$SETUID_LIST"
}

seed_setuid_list() {
  local now
  if [[ -e $SETUID_LIST || -L $SETUID_LIST ]]; then
    log "setuid list: $SETUID_LIST kept (new programs: sudo ./install.sh --setuid-accept)"
    return 0
  fi
  now=$(setuid_scan)
  [[ -n $now ]] || { warn "no setuid / setgid program under /usr: no setuid list"; return 0; }
  write_setuid_list "$now"
  log "setuid list: $SETUID_LIST (new: the $(wc -l <<< "$now") programs under /usr now)"
}

# --setuid-accept: show what is new / gone with its package, then the list = /usr now
setuid_accept() {
  local now old new gone p pkg ans
  [[ -d $CONF ]] || die "no $CONF: install first"
  now=$(setuid_scan)
  [[ -n $now ]] || die "no setuid / setgid program found under /usr: list kept"
  old=""
  if [[ -f $SETUID_LIST && ! -L $SETUID_LIST ]]; then
    old=$(grep -v '^[[:space:]]*#' "$SETUID_LIST" | grep . | LC_ALL=C sort || true)
  fi
  new=$(LC_ALL=C comm -13 <(printf '%s\n' "$old") <(printf '%s\n' "$now") | grep . || true)
  gone=$(LC_ALL=C comm -23 <(printf '%s\n' "$old") <(printf '%s\n' "$now") | grep . || true)
  if [[ -z $new && -z $gone ]]; then
    log "setuid list: nothing new ($(wc -l <<< "$now") programs)"
    return 0
  fi
  while IFS= read -r p; do
    [[ -n $p ]] || continue
    pkg=$(rpm -qf "$p" 2>/dev/null || echo "no package")
    printf '  new:  %s  (%s, %s)\n' "$p" "$pkg" "$(stat -c '%U:%G %a' "$p")"
  done <<< "$new"
  while IFS= read -r p; do
    [[ -n $p ]] && printf '  gone: %s\n' "$p"
  done <<< "$gone"
  read -r -p "accept: the list = these $(wc -l <<< "$now") programs? [y/N] " ans < /dev/tty || ans=n
  if [[ $ans == y || $ans == Y ]]; then
    write_setuid_list "$now"
    log "setuid list: $SETUID_LIST written (sectop reads it at the next collect, every 5 min)"
  else
    log "setuid list: not changed"
  fi
}

# --home-accept: what differs from the accepted list (core/homed.py accept), y = the list
# is the home watch's report now. Root reads the report in /run, never the home.
home_accept() {
  [[ -d $CONF ]] || die "no $CONF: install first"
  [[ -f $DEST/bin/sectop-home ]] || die "no $DEST/bin/sectop-home: install first"
  /usr/bin/python3 -I -B "$DEST/bin/sectop-home" --accept
  [[ -f $CONF/home-known.txt ]] && relabel "$CONF/home-known.txt"
  return 0
}

install_units() {  # $1 = desktop user: its user helper + home watch
  local u inst helper=sectop-user@$1.service watch=sectop-home@$1.service
  for u in "${UNITS[@]}"; do
    install -m 0644 -o root -g root "$DEST/deploy/$u" "$UNIT_DIR/$u"
  done
  relabel "$UNIT_DIR"/sectop*
  systemctl daemon-reload
  # one helper: another desktop user's instance (older install) goes
  for inst in $( { systemctl list-units --all --plain --no-legend 'sectop-user@*.service' \
                     'sectop-home@*.service' | awk '{print $1}'
                   find "$UNIT_DIR/multi-user.target.wants" -maxdepth 1 \( \
                     -name 'sectop-user@*.service' -o -name 'sectop-home@*.service' \) \
                     -printf '%f\n' 2>/dev/null; } | sort -u); do
    [[ $inst == "$helper" || $inst == "$watch" ]] && continue
    systemctl disable --now "$inst" >/dev/null 2>&1 || true
    log "$inst stopped + disabled (desktop user is now $1)"
  done
  systemctl enable sectop-net.service sectop.service sectop-whois.socket "$helper" "$watch" >/dev/null
  systemctl restart sectop-net.service sectop.service sectop-whois.socket "$helper" "$watch"
  for u in sectop-net.service sectop.service sectop-whois.socket "$helper" "$watch"; do
    if systemctl is-active --quiet "$u"; then
      log "$u active"
    else
      warn "$u not active: journalctl -b -u $u"
    fi
  done
}

USER_RE='^[a-z_][a-z0-9_-]{0,31}$'

# no 'cmd | grep -q' under pipefail: grep -q quits at the first match, the writer can get
# SIGPIPE and the pipe fails although the line was there
in_group() { [[ " $(id -nG "$1" 2>/dev/null) " == *" $2 "* ]]; }

# the desktop user: a login account, not the admin's privileges
check_desktop() {  # $1 = desktop user, $2 = admin
  local d=$1 uid
  [[ $d =~ $USER_RE && $d != root ]] || die "--desktop-user: bad user name '$d'"
  uid=$(id -u "$d" 2>/dev/null) || die "--desktop-user: no such user '$d'"
  (( uid >= 1000 )) || die "--desktop-user: $d is a system user (uid $uid)"
  [[ $d == "$2" ]] && return 0
  if in_group "$d" wheel; then
    warn "$d is in wheel: sudo from the desktop session (from the admin: gpasswd -d $d wheel)"
  fi
  if in_group "$d" sectop; then
    warn "$d is in group sectop: reads the UI state + whois socket. sysusers never removes"
    warn "  a member: sudo gpasswd -d $d sectop, then $d logs out and in (or reboot)"
  fi
}

main() {
  [[ $EUID -eq 0 ]] || die "run with sudo"
  [[ ${1:-} == --remove ]] && { remove; return; }
  [[ ${1:-} == --check ]] && { preflight; return; }
  [[ ${1:-} == --setuid-accept ]] && { [[ $# -eq 1 ]] || die "usage: sudo $0 --setuid-accept"; setuid_accept; return; }
  [[ ${1:-} == --home-accept ]] && { [[ $# -eq 1 ]] || die "usage: sudo $0 --home-accept"; home_accept; return; }
  local desktop=""
  if [[ ${1:-} == --desktop-user ]]; then
    [[ $# -eq 2 ]] || die "usage: sudo $0 --desktop-user NAME"
    desktop=$2; shift 2
  fi
  [[ $# -eq 0 ]] || die "usage: sudo $0 [--desktop-user NAME | --check | --remove | --setuid-accept | --home-accept]"
  local user=${SUDO_USER:-} repo
  [[ $user =~ $USER_RE && $user != root ]] \
    || die "run with sudo from your login (SUDO_USER missing or root)"
  desktop=${desktop:-$user}
  check_desktop "$desktop" "$user"
  repo=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
  local member=no
  if in_group "$user" sectop; then member=yes; fi
  preflight
  install_code "$repo" "$user"
  install_users "$user"
  check_conf
  seed_setuid_list
  install_units "$desktop"
  if [[ $desktop == "$user" ]]; then
    log "one account: $user reads sectop and runs the user helper"
  else
    log "admin $user: group sectop | desktop $desktop: user helper only, no sectop group"
  fi
  if [[ $member == yes ]]; then
    log "UI: sectop   (as $user, no sudo)"
  else
    log "UI: $user is new in group sectop: log out and in once, then: sectop"
  fi
  log "check: systemd-analyze security sectop.service sectop-net.service sectop-whois@x.service"
  log "       systemd-analyze security sectop-user@$desktop.service sectop-home@$desktop.service"
  if [[ ! -e $CONF/home-known.txt ]]; then
    log "home watch: $desktop's account gives sectop-home read access (docs/install.md, Home"
    log "  watch), then the first list: sudo ./install.sh --home-accept"
  fi
}

main "$@"
