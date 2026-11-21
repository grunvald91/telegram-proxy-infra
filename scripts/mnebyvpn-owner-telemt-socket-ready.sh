#!/usr/bin/env bash
# Ensure the SSH-only Telemt API capability belongs to the dedicated worker UID.
set -Eeuo pipefail
socket=/run/mnebyvpn-owner-mtproxy/telemt.sock
for i in $(seq 1 50); do
  if [[ -S "$socket" ]]; then
    chown 13096:13096 "$socket"
    chmod 0600 "$socket"
    test "$(stat -c '%u:%g:%a' "$socket")" = '13096:13096:600'
    exit 0
  fi
  sleep .2
done
echo 'owner_mtproxy_socket_unavailable=true' >&2
exit 1
