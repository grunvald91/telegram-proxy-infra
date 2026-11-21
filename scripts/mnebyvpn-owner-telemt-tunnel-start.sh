#!/usr/bin/env bash
# Never changes Telemt, DNS, NAT, active VPN, or existing user keys.
set -Eeuo pipefail
test "$(id -u)" -eq 0
service=mnebyvpn-owner-telemt-tunnel
test -s /etc/mnebyvpn-owner-mtproxy/id_ed25519
test -s /etc/mnebyvpn-owner-mtproxy/known_hosts
install -m 0755 /tmp/mnebyvpn-owner-telemt-socket-ready.sh /usr/local/sbin/mnebyvpn-owner-telemt-socket-ready
install -m 0644 /tmp/mnebyvpn-owner-telemt-tunnel.service "/etc/systemd/system/$service.service"
systemctl daemon-reload
systemctl enable --now "$service"
systemctl is-active --quiet "$service"
sock=/run/mnebyvpn-owner-mtproxy/telemt.sock
test -S "$sock"
test "$(stat -c '%u:%g:%a' "$sock")" = '13096:13096:600'
# No customer payload or API secret enters logs; response is parsed in memory only.
curl --noproxy '*' --unix-socket "$sock" -fsS --max-time 6 \
  'http://localhost/v1/system/info' | python3 -c \
  'import json,sys; data=json.load(sys.stdin); assert data.get("ok") is True and isinstance(data.get("data"),dict)'
echo 'owner_telemt_private_socket_ready=true'
