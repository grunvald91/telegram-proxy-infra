#!/usr/bin/env bash
# Explicit, 30-minute, rollback-by-default on-device experiment.
# This is NOT production promotion: it automatically reverts.
# No change to existing VPN subscription tokens, clients, TLS certs, firewall.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 1 && "$1" =~ ^/tmp/mnebydns-ci-[0-9]+$ ]] || exit 2
work="$1"
runid="$(basename "$work" | cut -d- -f3)"
[[ "$runid" =~ ^[0-9]+$ ]] || exit 2
base="/opt/mnebydns-googlepilot-backups/$runid"
nginx=/etc/nginx/nginx.conf
dns=/opt/mnebydns-dot/Corefile
pilot=/etc/mnebydns-googlepilot
unit=/etc/systemd/system/mnebydns-googlepilot.service
watchdog="mnebydns-four-google-watchdog-$runid"
watchdog_service="/etc/systemd/system/$watchdog.service"
watchdog_timer="/etc/systemd/system/$watchdog.timer"

exec 9>/run/lock/mnebyvpn-public-route.lock
flock -n 9 || { echo "shared_443_route_lock_occupied=true"; exit 2; }
for file in mnebydns-four-google-canary.py mnebydns-four-google-rollback.sh; do
  test -s "$work/$file"
done
python3 "$work/mnebydns-four-google-canary.py" self-test
test ! -e "$base" && test ! -e "$unit" && test ! -e "$pilot"
test ! -e "$watchdog_service" && test ! -e "$watchdog_timer"
test -z "$(ss -H -lnt 'sport = :15449')"
for file in "$nginx" "$dns"; do
  test -f "$file" && test ! -L "$file"
done
for svc in nginx xray.service mnebydns-dot.service mnebydns-gemini.service; do
  systemctl is-active --quiet "$svc"
done
test "$(awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo)" -ge 450
nginx -t >/dev/null 2>&1

mkdir -p /opt/mnebydns-googlepilot-backups
install -d -m 700 -o root -g root "$base"
cp -p "$nginx" "$base/nginx.before"
cp -p "$dns" "$base/dns.before"
install -m 700 "$work/mnebydns-four-google-rollback.sh" "$base/rollback.sh"
python3 "$work/mnebydns-four-google-canary.py" render \
  "$nginx" "$dns" "$base"
test -s "$base/nginx.pilot" && test -s "$base/dns.pilot"
test -s "$base/proxy.pilot"

# A separate service on loopback is required before introducing live SNI map.
cat > "$base/pilot.service" <<'UNIT'
[Unit]
Description=MNEBYDNS four-Google-services time-limited owner-only TLS pilot
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=simple
ExecStart=/usr/sbin/nginx -c /etc/mnebydns-googlepilot/nginx.conf -g "daemon off;"
DynamicUser=yes
RuntimeDirectory=mnebydns-googlepilot
RuntimeDirectoryMode=0700
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_UNIX
MemoryMax=100M
CPUQuota=20%
TasksMax=24
LimitNOFILE=512
Restart=on-failure
RestartSec=3s
TimeoutStopSec=8s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT
chmod 600 "$base/pilot.service"

abort(){
  code="$?"
  trap - EXIT
  flock -u 9 || true
  if test -s "$base/rollback.sh" && test -s "$base/nginx.pilot" && test -s "$base/dns.pilot"; then
    bash "$base/rollback.sh" "$base" || echo "canary_auto_rollback_NOT_CONFIRMED=true"
  else
    echo "canary_no_live_swap_completed_no_config_rollback_needed=true"
  fi
  exit "$code"
}
trap abort EXIT

install -d -m 755 -o root -g root "$pilot"
install -m 644 -o root -g root "$base/proxy.pilot" "$pilot/nginx.conf"
install -m 644 -o root -g root "$base/pilot.service" "$unit"
# nginx -t validates its PID pathname before systemd creates RuntimeDirectory.
# Create an empty temporary runtime directory; systemd adopts/chowns it on start.
install -d -m 700 -o root -g root /run/mnebydns-googlepilot
nginx -t -c "$pilot/nginx.conf" >/dev/null 2>&1 || {
  echo "isolated_nginx_configuration_invalid=yes"; exit 3;
}
systemctl daemon-reload
systemctl start mnebydns-googlepilot.service
for i in $(seq 1 40); do
  ss -H -lnt 'sport = :15449' | grep -q '127.0.0.1:15449' && break
  sleep .2
done
systemctl is-active --quiet mnebydns-googlepilot.service
ss -H -lnt 'sport = :15449' | grep -q '127.0.0.1:15449'
echo "isolated_google_pilot_on_loopback=true"

# Validate original Google certificate through the new SNI backend.
# Avoid interpolating an arbitrary user supplied hostname in bash.
for host in android.googleapis.com firebaseinstallations.googleapis.com gcm-http.googleapis.com \
  www.youtube.com youtubei.googleapis.com i.ytimg.com \
  stitch.withgoogle.com accounts.google.com aistudio.google.com \
  generativelanguage.googleapis.com jnn-pa.googleapis.com \
  www.googleapis.com optimizationguide-pa.googleapis.com \
  www.gstatic.com fonts.gstatic.com ssl.gstatic.com \
  www.google.com labs.google; do
  code="$(curl -4 --noproxy '*' -sS -o /dev/null -w '%{http_code}' \
       --connect-timeout 4 --max-time 11 \
       --connect-to "$host:443:127.0.0.1:15449" \
       "https://$host/" 2>/dev/null || true)"
  [[ "$code" != 000 && -n "$code" ]] ||
    { echo "pre_publish_origin_TLS_failed=$host"; exit 5; }
  echo "pre_publish_original_TLS_valid=$host"
done

# Arm independent timer before changing shared ingress and DNS.
# Persistent OnCalendar timer survives VPS reboot; missed deadlines are
# enforced on boot, unlike transient systemd-run monotonic timers.
# A fixed UTC calendar timestamp is computed once, after backend TLS passes.
deadline="$(date -u -d '+30 minutes' +'%Y-%m-%d %H:%M:%S UTC')"
systemd-analyze calendar "$deadline" >/dev/null
cat > "$base/watchdog.service" <<UNIT
[Unit]
Description=Restore original MNEBYDNS DNS/SNI after scoped Google canary

[Service]
Type=oneshot
ExecStart=/bin/bash $base/rollback.sh $base
UNIT
cat > "$base/watchdog.timer" <<UNIT
[Unit]
Description=Persistent 30 minute MNEBYDNS pilot rollback deadline

[Timer]
OnCalendar=$deadline
Persistent=true
AccuracySec=1s
Unit=$watchdog.service

[Install]
WantedBy=timers.target
UNIT
chmod 600 "$base/watchdog.service" "$base/watchdog.timer"
install -m 644 "$base/watchdog.service" "$watchdog_service"
install -m 644 "$base/watchdog.timer" "$watchdog_timer"
systemctl daemon-reload
systemctl enable --now "$watchdog.timer" >/dev/null
systemctl is-active --quiet "$watchdog.timer"
echo "automatic_rollback_seconds=1800"
echo "automatic_rollback_persists_after_reboot=true"
echo "automatic_rollback_calendar_UTC=$deadline"
echo "automatic_rollback_unit=$watchdog.timer"
test -s "$base/nginx.pilot" && test -s "$base/dns.pilot"
# Syntax-check staged shared Nginx before touching the active config.
nginx -t -c "$base/nginx.pilot" >/dev/null 2>&1 || {
  echo "staged_shared_443_nginx_invalid=yes"; exit 6;
}
# Preserve metadata for original production configs.
chown --reference="$nginx" "$base/nginx.pilot"
chmod --reference="$nginx" "$base/nginx.pilot"
chown --reference="$dns" "$base/dns.pilot"
chmod --reference="$dns" "$base/dns.pilot"
cp -p "$base/nginx.pilot" "$nginx"
nginx -t >/dev/null 2>&1 || { echo "shared_nginx_canary_validation_failed=yes"; exit 7; }
systemctl reload nginx
systemctl is-active --quiet nginx
# Before DNS cutover, confirm foreign 443 reaches original Google TLS.
# Existing exact Google SNI entries are owned by old services: only reuse
# after verifying their public original TLS remains valid before DNS cutover.
mapfile -t preexisting < <(python3 "$work/mnebydns-four-google-canary.py" \
    audit-existing "$base/nginx.before")
echo "preexisting_unchanged_exact_google_routes=${#preexisting[@]}"
for host in "${preexisting[@]}" www.youtube.com stitch.withgoogle.com aistudio.google.com accounts.google.com; do
  code="$(curl -4 --noproxy '*' -sS -o /dev/null -w '%{http_code}' \
       --connect-timeout 4 --max-time 10 \
       --resolve "$host:443:89.125.90.101" \
       "https://$host/" 2>/dev/null || true)"
  [[ "$code" != 000 && -n "$code" ]] ||
    { echo "public_443_pre_DNS_TLS_failed=$host"; exit 8; }
  echo "public_443_original_TLS_valid=$host"
done
cp -p "$base/dns.pilot" "$dns"
echo "DNS_reconfiguration_started=true"
systemctl restart mnebydns-dot.service
dns_ready=no
for attempt in $(seq 1 50); do
  if systemctl is-active --quiet mnebydns-dot.service &&
     ss -H -lnt 'sport = :853' | awk '{print $4}' | grep -Fxq '89.125.90.101:853'; then
    dns_ready=yes
    break
  fi
  sleep 0.2
done
if [[ "$dns_ready" != yes ]]; then
  echo "MNEBYDNS_restart_or_port_not_ready=true"
  exit 9
fi
echo "MNEBYDNS_DoT_ready_after_restart=true"
test "$(systemctl is-active nginx)" = active
test "$(systemctl is-active xray.service)" = active
test "$(systemctl is-active mnebydns-gemini.service)" = active
test "$(systemctl is-active mnebydns-googlepilot.service)" = active
echo "public_443_and_DoT_four_services_canary=ACTIVE"
echo "auto_restore_after_1800_seconds=ARMED"
echo "original_VPN_unchanged=yes"
trap - EXIT
flock -u 9
