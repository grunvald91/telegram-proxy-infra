#!/usr/bin/env bash
# Isolated, time-limited Xray VLESS/WebSocket/TLS proof of connectivity.
# Separate systemd service; never touch existing xray.service or nginx :443.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" == 0 ]] || exit 2
exec 9>/run/lock/mnebyvpn-xray-canary.lock
flock -n 9 || exit 2
XRAY=/opt/xray/xray
[[ -x "$XRAY" ]] || { echo "xray_binary_missing"; exit 2; }
test -s /etc/letsencrypt/live/cdn.servgo.ru/fullchain.pem
test -s /etc/letsencrypt/live/cdn.servgo.ru/privkey.pem
SITE=/etc/nginx/sites-available/mnebyvpn-telegram-8443.conf
UNIT=/etc/systemd/system/mnebyvpn-xray-canary.service
CONF=/etc/mnebyvpn/xray-canary.json
KEY=/etc/mnebyvpn/canary-uuid
[[ -f "$SITE" ]] || exit 2
grep -Fq 'listen ' "$SITE"
grep -Fq '8443 ssl;' "$SITE"
grep -Fq 'location = /mnebyvpn-telegram/webhook' "$SITE"
test "$(systemctl is-active xray)" = active || {
  echo "preexisting_xray_not_active"; exit 2;
}
if ss -H -lnt | awk '{print $4}' | grep -Eq ':18943$'; then
  [[ -f "$UNIT" ]] && grep -Fq 'mnebyvpn/xray-canary.json' "$UNIT" || {
    echo "canary_port_occupied"; exit 2;
  }
fi
mkdir -p /opt/mnebyvpn/backups /etc/mnebyvpn
BACKUP="$(mktemp -d /opt/mnebyvpn/backups/xray-canary-XXXXXXXX)"
chmod 700 "$BACKUP"
cp -p "$SITE" "$BACKUP/site"
test ! -e "$UNIT" || cp -p "$UNIT" "$BACKUP/unit"
test ! -e "$CONF" || cp -p "$CONF" "$BACKUP/config"
test ! -e "$KEY" || cp -p "$KEY" "$BACKUP/key"
restore(){
  set +e
  systemctl stop mnebyvpn-xray-canary.service >/dev/null 2>&1 || true
  systemctl disable mnebyvpn-xray-canary.service >/dev/null 2>&1 || true
  cp -p "$BACKUP/site" "$SITE"
  for item in unit config key; do
    case "$item" in
      unit) target="$UNIT";;
      config) target="$CONF";;
      key) target="$KEY";;
    esac
    if [[ -f "$BACKUP/$item" ]]; then cp -p "$BACKUP/$item" "$target"; else rm -f "$target"; fi
  done
  systemctl daemon-reload
  nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
  echo "canary_rolled_back=true"
}
trap restore ERR
if ! getent passwd mnebyvpn-xray >/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin mnebyvpn-xray
fi
chown root:mnebyvpn-xray /etc/mnebyvpn
chmod 750 /etc/mnebyvpn
if [[ ! -f "$KEY" ]]; then
  python3 - <<'PY' > "$KEY"
import uuid
print(uuid.uuid4())
PY
fi
chmod 600 "$KEY"
python3 - "$CONF" "$KEY" <<'PY'
import json,sys,pathlib,uuid
path=pathlib.Path(sys.argv[1])
credential=pathlib.Path(sys.argv[2]).read_text().strip()
uuid.UUID(credential)
config={
 "log":{"loglevel":"warning"},
 "inbounds":[{
  "listen":"127.0.0.1","port":18943,"protocol":"vless",
  "settings":{"clients":[{"id":credential,"level":0}],"decryption":"none"},
  "streamSettings":{"network":"ws","security":"none",
    "wsSettings":{"path":"/mnebyvpn-vpn/ws"}},
  "tag":"mnebyvpn-inbound"
 }],
 "outbounds":[
  {"protocol":"freedom","tag":"direct"},
  {"protocol":"blackhole","tag":"blocked"}
 ],
 "routing":{
  "domainStrategy":"IPIfNonMatch",
  "rules":[
   {"type":"field","ip":["0.0.0.0/8","10.0.0.0/8","100.64.0.0/10",
      "127.0.0.0/8","169.254.0.0/16","172.16.0.0/12",
      "192.168.0.0/16","224.0.0.0/4","240.0.0.0/4",
      "::1/128","fc00::/7","fe80::/10"],
    "outboundTag":"blocked"},
   {"type":"field","domain":["domain:localhost"],"outboundTag":"blocked"}
  ]
 }
}
path.write_text(json.dumps(config,indent=2)+'\n')
PY
chown root:mnebyvpn-xray "$CONF"
chmod 640 "$CONF"
"$XRAY" run -test -config "$CONF" >/dev/null 2>&1 || {
  echo "xray_canary_config_invalid"; exit 2;
}
cat > "$UNIT" <<'UNIT'
[Unit]
Description=MNEBYVPN isolated VLESS WebSocket canary on localhost
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mnebyvpn-xray
Group=mnebyvpn-xray
ExecStart=/opt/xray/xray run -config /etc/mnebyvpn/xray-canary.json
Restart=on-failure
RestartSec=3s
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
LimitNOFILE=8192
MemoryMax=180M
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
UNIT
chmod 644 "$UNIT"
python3 - "$SITE" <<'PY'
import sys,pathlib
p=pathlib.Path(sys.argv[1])
s=p.read_text()
new='''    # Isolated canary VPN tunnel: TLS terminates on this same foreign server.
    location = /mnebyvpn-vpn/ws {
        access_log off;
        proxy_pass http://127.0.0.1:18943;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
    }
'''
if 'location = /mnebyvpn-vpn/ws {' not in s:
  marker='    location = /mnebyvpn-telegram/webhook {'
  if s.count(marker)!=1:raise SystemExit('Cannot find isolated Telegram vhost marker')
  s=s.replace(marker,new+marker)
  p.write_text(s)
PY
nginx -t >/dev/null
systemctl daemon-reload
systemctl enable --now mnebyvpn-xray-canary.service >/dev/null
systemctl reload nginx
test "$(systemctl is-active mnebyvpn-xray-canary.service)" = active
ready=no
for attempt in $(seq 1 15); do
  if ss -H -lnt | awk '{print $4}' | grep -Fqx '127.0.0.1:18943'; then
    ready=yes; break
  fi
  sleep 1
done
[[ "$ready" == yes ]] || { echo "xray_canary_listener_not_running"; exit 2; }
# The existing bot endpoint must remain protected.
code="$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 8 \
 --resolve cdn.servgo.ru:8443:"$(ip -4 -o addr show dev eth0 | awk '$3=="inet" {print $4}' | cut -d/ -f1 | head -1)" \
 -X POST -H 'Content-Type: application/json' -d '{"update_id":1}' \
 https://cdn.servgo.ru:8443/mnebyvpn-telegram/webhook)"
[[ "$code" == 401 ]] || { echo "existing_telegram_route_regressed"; exit 2; }
test "$(systemctl is-active xray)" = active
trap - ERR
echo "vpn_isolated_canary_xray=active"
echo "vpn_test_credential_not_printed=true"
echo "existing_xray_service=active"
echo "existing_bot_route_protected=true"
echo "vpn_canary_port_localhost_only=true"
