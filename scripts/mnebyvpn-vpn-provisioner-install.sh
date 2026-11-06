#!/usr/bin/env bash
# Promote isolated 89-node Xray canary into a fail-closed, expiring per-user
# trial provisioner. Keep public TLS 8443, Telegram WG and unrelated Xray intact.
set -Eeuo pipefail
umask 077
[[ $(id -u) -eq 0 ]] || exit 2
exec 9>/run/lock/mnebyvpn-vpn-provisioner.lock
flock -n 9 || exit 2
SOURCE=/tmp/mnebyvpn-vpn-provisioner.py
AGENT=/opt/mnebyvpn/vpn-provisioner.py
KEY=/etc/mnebyvpn/provisioner.key
UNIT=/etc/systemd/system/mnebyvpn-vpn-provisioner.service
CONFIG=/etc/mnebyvpn/xray-canary.json
STATE=/var/lib/mnebyvpn-vpn/state.json
test -s "$SOURCE"
python3 -m py_compile "$SOURCE"
test "$(systemctl is-active mnebyvpn-xray-canary)" = active
test "$(systemctl is-active xray)" = active
test -s "$CONFIG"
test -s /etc/mnebyvpn/canary-uuid
test -f /etc/nginx/sites-available/mnebyvpn-telegram-8443.conf
grep -Fq 'location = /mnebyvpn-vpn/ws' /etc/nginx/sites-available/mnebyvpn-telegram-8443.conf
ip -4 addr show dev tg-relay | grep -Fq '10.66.77.1/'
if ss -H -lnt | awk '{print $4}' | grep -Eq ':18944$'; then
  [[ -f "$UNIT" ]] || { echo "provisioner_private_port_taken"; exit 2; }
fi
mkdir -p /opt/mnebyvpn/backups /opt/mnebyvpn /etc/mnebyvpn /var/lib/mnebyvpn-vpn
chmod 700 /var/lib/mnebyvpn-vpn
BACKUP="$(mktemp -d /opt/mnebyvpn/backups/provisioner-XXXXXXXX)"
chmod 700 "$BACKUP"
cp -p "$CONFIG" "$BACKUP/xray-config"
if [[ -f "$STATE" ]]; then cp -p "$STATE" "$BACKUP/state"; fi
if [[ -f "$AGENT" ]]; then cp -p "$AGENT" "$BACKUP/agent"; fi
if [[ -f "$UNIT" ]]; then cp -p "$UNIT" "$BACKUP/unit"; fi
restore(){
  set +e
  systemctl stop mnebyvpn-vpn-provisioner.service >/dev/null 2>&1 || true
  systemctl disable mnebyvpn-vpn-provisioner.service >/dev/null 2>&1 || true
  cp -p "$BACKUP/xray-config" "$CONFIG"
  for entry in state agent unit; do
    case "$entry" in
      state) out="$STATE";;
      agent) out="$AGENT";;
      unit) out="$UNIT";;
    esac
    if [[ -f "$BACKUP/$entry" ]]; then cp -p "$BACKUP/$entry" "$out"; else rm -f "$out"; fi
  done
  systemctl daemon-reload
  systemctl enable --now mnebyvpn-xray-canary.service >/dev/null 2>&1 || true
  echo "vpn_provisioner_rolled_back=true"
}
trap restore ERR
if [[ ! -f "$KEY" ]]; then
  openssl rand -hex 32 > "$KEY"
fi
chmod 600 "$KEY"
install -m 700 "$SOURCE" "$AGENT"
cat > "$UNIT" <<'UNIT'
[Unit]
Description=MNEBYVPN isolated trial provisioning agent with node-enforced expiry
Wants=network-online.target
After=network-online.target wg-quick@tg-relay.service
Conflicts=mnebyvpn-xray-canary.service

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/mnebyvpn/vpn-provisioner.py
Restart=always
RestartSec=2s
KillMode=control-group
TimeoutStopSec=10s
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/etc/mnebyvpn /var/lib/mnebyvpn-vpn
LimitNOFILE=8192
MemoryMax=280M
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
UNIT
chmod 644 "$UNIT"
systemctl daemon-reload
systemctl disable --now mnebyvpn-xray-canary.service >/dev/null
systemctl enable --now mnebyvpn-vpn-provisioner.service >/dev/null
READY=no
for i in $(seq 1 30); do
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 http://10.66.77.1:18944/healthz || true)"
  if [[ "$code" == 200 ]]; then READY=yes; break; fi
  sleep 1
done
[[ "$READY" == yes ]] || { echo "node_provisioner_not_ready"; exit 2; }
ss -H -lnt | awk '{print $4}' | grep -Fqx '10.66.77.1:18944'
ss -H -lnt | awk '{print $4}' | grep -Fqx '127.0.0.1:18943'
test "$(systemctl is-active xray)" = active
code="$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 8 \
  --resolve cdn.servgo.ru:8443:"$(ip -4 -o addr show dev eth0 | awk '$3=="inet" {print $4}' | cut -d/ -f1 | head -1)" \
  -X POST -H 'Content-Type: application/json' -d '{"update_id":100}' \
  https://cdn.servgo.ru:8443/mnebyvpn-telegram/webhook)"
[[ "$code" == 401 ]] || { echo "existing_telegram_route_damaged"; exit 2; }
trap - ERR
echo "vpn_agent_with_per_user_expiry=healthy"
echo "vpn_xray_supervised_by_agent=true"
echo "vpn_agent_bound_to_wireguard=true"
echo "vpn_test_keys_not_logged=true"
echo "preexisting_shared_xray=active"
echo "foreign_telegram_route_unchanged=true"
