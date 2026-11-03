#!/usr/bin/env bash
#
# install.sh - install sectop from this repo's git HEAD as root-owned code + services.
#
#   sudo ./install.sh            install or update (HEAD, not uncommitted changes)
#   sudo ./install.sh --check    requirements only, changes nothing
#   sudo ./install.sh --remove   stop + remove units, code, launcher, sysusers file
#
# Why: code a service runs must not be writable by my user (docs/architecture.md,
# Privilege split). git archive HEAD -> /usr/local/lib/sectop, root-owned.
# Silverblue: /usr/local -> /var/usrlocal (writable, kept across rpm-ostree updates).
# Details: docs/install.md
set -euo pipefail

DEST=/usr/local/lib/sectop
BIN=/usr/local/bin/sectop
UNIT_DIR=/etc/systemd/system
UNITS=(sectop-net.service sectop.service sectop-whois.socket sectop-whois@.service sectop-user@.service)
SYSUSERS=/etc/sysusers.d/sectop.conf
CONF=/etc/sectop
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
                  | awk '{print $1}'); do
    systemctl disable --now "$inst" >/dev/null 2>&1 || true
  done
  rm -f "$UNIT_DIR"/multi-user.target.wants/sectop-user@*.service
  local u
  for u in "${UNITS[@]}"; do rm -f "$UNIT_DIR/$u"; done
  systemctl daemon-reload
  rm -f "$BIN"
  rm -rf "$DEST"
  rm -f "$SYSUSERS"
  log "removed: units, $DEST, $BIN, $SYSUSERS"
  log "kept: $CONF; users sectop, sectop-net and group sectop"
  log "  (by hand: userdel sectop; userdel sectop-net; groupdel sectop)"
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
  elif ! auditctl -l 2>/dev/null | grep -q 'key=root_cmds'; then
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

install_code() {   # $1 = repo, $2 = login user
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

install_users() {  # $1 = login user
  install -d -m 0755 "$(dirname "$SYSUSERS")"   # Silverblue: /etc/sysusers.d does not exist
  { cat "$DEST/deploy/sectop.sysusers"
    printf 'm %s sectop\n' "$1"
  } > "$SYSUSERS.tmp"
  chmod 0644 "$SYSUSERS.tmp"
  mv "$SYSUSERS.tmp" "$SYSUSERS"
  relabel "$SYSUSERS"
  systemd-sysusers "$SYSUSERS"
  log "users: $(id sectop), $(id sectop-net)"
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

install_units() {  # $1 = login user: its user helper (sectop-user@<user>.service)
  local u helper=sectop-user@$1.service
  for u in "${UNITS[@]}"; do
    install -m 0644 -o root -g root "$DEST/deploy/$u" "$UNIT_DIR/$u"
  done
  relabel "$UNIT_DIR"/sectop*
  systemctl daemon-reload
  systemctl enable sectop-net.service sectop.service sectop-whois.socket "$helper" >/dev/null
  systemctl restart sectop-net.service sectop.service sectop-whois.socket "$helper"
  for u in sectop-net.service sectop.service sectop-whois.socket "$helper"; do
    if systemctl is-active --quiet "$u"; then
      log "$u active"
    else
      warn "$u not active: journalctl -b -u $u"
    fi
  done
}

main() {
  [[ $EUID -eq 0 ]] || die "run with sudo"
  [[ ${1:-} == --remove ]] && { remove; return; }
  [[ ${1:-} == --check ]] && { preflight; return; }
  [[ $# -eq 0 ]] || die "usage: sudo $0 [--check | --remove]"
  local user=${SUDO_USER:-} repo
  [[ $user =~ ^[a-z_][a-z0-9_-]*$ && $user != root ]] \
    || die "run with sudo from your login (SUDO_USER missing or root)"
  repo=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
  local member=no
  if id -nG "$user" | tr ' ' '\n' | grep -qx sectop; then member=yes; fi
  preflight
  install_code "$repo" "$user"
  install_users "$user"
  check_conf
  install_units "$user"
  if [[ $member == yes ]]; then
    log "UI: sectop   (as $user, no sudo)"
  else
    log "UI: $user is new in group sectop: log out and in once, then: sectop"
  fi
  log "check: systemd-analyze security sectop.service sectop-net.service sectop-whois@x.service"
  log "       systemd-analyze security sectop-user@$user.service"
}

main "$@"
