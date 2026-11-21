#!/usr/bin/env bash
# Idempotently prepare a purpose-specific key on RU188 only; private key never leaves RU.
set -Eeuo pipefail
umask 077
test "$(id -u)" -eq 0
base=/etc/mnebyvpn-owner-mtproxy
install -d -m 0700 "$base"
known=/tmp/mnebyvpn-owner-telemt-known-hosts
test -s "$known"
install -m 0600 "$known" "$base/known_hosts"
ssh-keygen -lf "$base/known_hosts" >/dev/null
if [[ ! -e "$base/id_ed25519" ]]; then
  test ! -e "$base/id_ed25519.pub"
  ssh-keygen -q -t ed25519 -N '' -C 'mnebyvpn-owner-telemt-tunnel' -f "$base/id_ed25519"
fi
test -s "$base/id_ed25519" && test -s "$base/id_ed25519.pub"
test "$(stat -c %a "$base/id_ed25519")" = 600
ssh-keygen -y -f "$base/id_ed25519" | cut -d' ' -f1,2 | cmp - <(cut -d' ' -f1,2 "$base/id_ed25519.pub")
echo 'owner_telemt_ssh_key_prepared=true'
