#!/usr/bin/env bash
# Append one constrained public key. Preserve all existing operator access.
set -Eeuo pipefail
umask 077
test "$(id -u)" -eq 0
pub=/tmp/mnebyvpn-owner-telemt-id_ed25519.pub
test -s "$pub"
ssh-keygen -lf "$pub" >/dev/null
read -r algorithm material comment < "$pub"
[[ "$algorithm" == ssh-ed25519 && "$material" =~ ^[A-Za-z0-9+/]+={0,2}$ ]]
sshdir=/root/.ssh
install -d -m 0700 "$sshdir"
keyfile="$sshdir/authorized_keys"
touch "$keyfile"
chmod 0600 "$keyfile"
marker=mnebyvpn-owner-telemt-tunnel
entry="from=\"188.120.254.223,10.66.77.2\",restrict,port-forwarding,permitopen=\"127.0.0.1:9096\" $algorithm $material $marker"
if grep -Fq " $marker" "$keyfile"; then
  grep -Fxq "$entry" "$keyfile" || {
    echo 'owner_telemt_existing_key_mismatch=true' >&2; exit 2;
  }
else
  printf '%s\n' "$entry" >> "$keyfile"
fi
rm -f "$pub"
echo 'owner_telemt_restricted_forwarding_key=installed'
