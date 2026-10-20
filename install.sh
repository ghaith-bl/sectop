#!/usr/bin/env bash
#
# install.sh - install sectop from this repo's git HEAD as root-owned code + services.
#
#   sudo ./install.sh            install or update (HEAD, not uncommitted changes)
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
UNITS=(sectop-net.service sectop.service sectop-whois.socket sectop-whois@.service)
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

install_code() {   # $1 = repo, $2 = login user
  local repo=$1 user=$2
  install -d -m 0755 "$(dirname "$DEST")"
  TMP=$(mktemp -d "$(dirname "$DEST")/.sectop.XXXXXX")     # same filesystem: mv = rename
  trap 'rm -rf "$TMP"' EXIT
  # git runs as my user: root refuses a repo owned by someone else (safe.directory)
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
  ln -sfn "$DEST/bin/sectop" "$BIN"
  relabel "$BIN"
  log "code: $DEST ($(sudo -u "$user" git -C "$repo" log -1 --format='%h %s'))"
}

install_users() {  # $1 = login user
  { cat "$DEST/deploy/sectop.sysusers"
    printf 'm %s sectop\n' "$1"
  } > "$SYSUSERS.tmp"
  chmod 0644 "$SYSUSERS.tmp"
  mv "$SYSUSERS.tmp" "$SYSUSERS"
  relabel "$SYSUSERS"
  systemd-sysusers "$SYSUSERS"
  log "users: $(id sectop), $(id sectop-net)"
}

check_conf() {     # collector and net unit read the config as non-root users
  install -d -m 0755 -o root -g root "$CONF"
  local f
  for f in "$CONF"/*.toml; do
    [[ -e $f ]] || continue
    chown root:root "$f"
    chmod 0644 "$f"
  done
  log "config: $CONF 0755, *.toml 0644 root:root (read by sectop users, no secrets)"
}

install_units() {
  local u
  for u in "${UNITS[@]}"; do
    install -m 0644 -o root -g root "$DEST/deploy/$u" "$UNIT_DIR/$u"
  done
  relabel "$UNIT_DIR"/sectop*
  systemctl daemon-reload
  systemctl enable sectop-net.service sectop.service sectop-whois.socket >/dev/null
  systemctl restart sectop-net.service sectop.service sectop-whois.socket
  for u in sectop-net.service sectop.service sectop-whois.socket; do
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
  [[ $# -eq 0 ]] || die "usage: sudo $0 [--remove]"
  local user=${SUDO_USER:-} repo
  [[ $user =~ ^[a-z_][a-z0-9_-]*$ && $user != root ]] \
    || die "run with sudo from your login (SUDO_USER missing or root)"
  repo=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
  local member=no
  if id -nG "$user" | tr ' ' '\n' | grep -qx sectop; then member=yes; fi
  install_code "$repo" "$user"
  install_users "$user"
  check_conf
  install_units
  if [[ $member == yes ]]; then
    log "UI: sectop   (as $user, no sudo)"
  else
    log "UI: $user is new in group sectop: log out and in once, then: sectop"
  fi
  log "check: systemd-analyze security sectop.service sectop-net.service sectop-whois@x.service"
}

main "$@"
