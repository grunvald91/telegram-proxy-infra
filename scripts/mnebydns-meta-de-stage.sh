#!/usr/bin/env bash
# Stage an isolated time-limited Meta-only WireGuard SNI sidecar on DE.
# NEVER changes live CoreDNS, shared Nginx, existing five-service sidecar or Xray.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 2 && "$1" =~ ^/tmp/mnebydns-meta-de-[0-9]+$ ]] || exit 2
work="$1"; deadline="$2"
id="$(basename "$work" | sed 's/^mnebydns-meta-de-//')"
[[ "$id" =~ ^[0-9]+$ ]] || exit 2
[[ "$deadline" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]][0-9]{2}:[0-9]{2}:[0-9]{2}[[:space:]]UTC$ ]] || exit 2
now="$(date -u +%s)"
expires="$(date -u -d "$deadline" +%s)"
(( expires - now >= 300 && expires - now <= 2700 )) || exit 2
systemd-analyze calendar "$deadline" >/dev/null
# The restricted Nginx sidecar writes aggregate numeric session events to journald.
# Avoid /dev/stdout: opening journald's inherited stream fails under this service.
test -S /run/systemd/journal/dev-log || { echo "DE_Meta_syslog_socket_not_available=true"; exit 3; }
stable_root=/opt/mnebydns-stable-checkpoints
checkpoint="$(cat "$stable_root/current")"
[[ "$checkpoint" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 2
(cd "$checkpoint" && sha256sum -c stable-manifest.sha256 >/dev/null)
base="/opt/mnebydns-experiment-backups/$id"
live_nginx=/etc/nginx/nginx.conf
live_dns=/opt/mnebydns-dot/Corefile
live_proxy=/etc/mnebydns-googlepilot/nginx.conf
sidecar_dir=/etc/mnebydns-meta-pilot
service="mnebydns-meta-pilot-$id"
watch="mnebydns-meta-de-watchdog-$id"
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 18 9 || exit 3
for kind in nginx dns proxy; do
  case "$kind" in
    nginx) live="$live_nginx";;
    dns) live="$live_dns";;
    proxy) live="$live_proxy";;
  esac
  cmp -s "$checkpoint/$kind.stable" "$live" || {
    printf 'DE_Meta_stage_refuses_stable_%s_drift=true\n' "$kind"; exit 3;
  }
done
for unit in nginx mnebydns-dot.service mnebydns-googlepilot.service mnebydns-gemini.service xray.service; do
  systemctl is-active --quiet "$unit"
done
ip -4 -o addr show dev tg-relay | grep -Fq '10.66.77.1/'
test "$(awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo)" -ge 300
test ! -e "$base" && test ! -e "$sidecar_dir"
for path in "/etc/systemd/system/$service.service" \
  "/etc/systemd/system/$watch.service" "/etc/systemd/system/$watch.timer"; do
  test ! -e "$path"
done
for source in mnebydns-meta-overlay.py mnebydns-four-google-canary.py mnebydns-meta-de-rollback.sh; do
  test -s "$work/$source"
done
test -z "$(ss -H -lnt 'sport = :19443')"
install -d -m 700 /opt/mnebydns-experiment-backups
install -d -m 700 "$base"
python3 "$work/mnebydns-meta-overlay.py" self-test
python3 "$work/mnebydns-meta-overlay.py" render "$live_dns" "$base"
cp -p "$checkpoint/nginx.stable" "$base/nginx.pilot"
cp -p "$checkpoint/proxy.stable" "$base/proxy.pilot"
install -m 700 "$work/mnebydns-meta-de-rollback.sh" "$base/rollback.sh"
test -s "$base/dns.pilot" && test -s "$base/proxy.meta"
for kind in nginx proxy; do cmp -s "$checkpoint/$kind.stable" "$base/$kind.pilot"; done
test -s "$checkpoint/dns.stable"
cat > "$base/$service.service" <<UNIT
[Unit]
Description=Temporary private WireGuard-only Meta HTTPS SNI proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/sbin/nginx -c /etc/mnebydns-meta-pilot/nginx.conf -g "daemon off;"
DynamicUser=yes
RuntimeDirectory=mnebydns-meta-pilot
RuntimeDirectoryMode=0700
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateDevices=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_UNIX
MemoryMax=128M
CPUQuota=35%
TasksMax=24
LimitNOFILE=1024
Restart=on-failure
RestartSec=3s
TimeoutStopSec=8s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT
cat > "$base/$watch.service" <<UNIT
[Unit]
Description=Restore five working MNEBYDNS services after Meta experiment deadline
[Service]
Type=oneshot
ExecStart=/bin/bash $base/rollback.sh $base
UNIT
cat > "$base/$watch.timer" <<UNIT
[Unit]
Description=Persistent timed rollback of Meta-only DNS experimental routing
[Timer]
OnCalendar=$deadline
Persistent=true
AccuracySec=1s
Unit=$watch.service
[Install]
WantedBy=timers.target
UNIT
for unit in "$service.service" "$watch.service" "$watch.timer"; do
  install -m 644 "$base/$unit" "/etc/systemd/system/$unit"
done
systemctl daemon-reload
systemctl enable --now "$watch.timer" >/dev/null
systemctl is-active --quiet "$watch.timer"
cleanup(){
  rc=$?
  trap - EXIT
  flock -u 9 || true
  bash "$base/rollback.sh" "$base" || echo "DE_Meta_STAGE_FAILURE_MANUAL_ROLLBACK_NEEDED=true"
  exit "$rc"
}
trap cleanup EXIT
install -d -m 755 "$sidecar_dir"
install -m 644 "$base/proxy.meta" "$sidecar_dir/nginx.conf"
install -d -m 700 /run/mnebydns-meta-pilot
nginx -t -c "$sidecar_dir/nginx.conf" >/dev/null
systemctl enable --now "$service.service" >/dev/null
ready=no
for _ in $(seq 1 40); do
  if systemctl is-active --quiet "$service.service" &&
     ss -H -lnt 'sport = :19443' | grep -Fq '10.66.77.1:19443'; then ready=yes; break; fi
  sleep .25
done
test "$ready" = yes
for kind in nginx dns proxy; do
  case "$kind" in
    nginx) live="$live_nginx";;
    dns) live="$live_dns";;
    proxy) live="$live_proxy";;
  esac
  cmp -s "$checkpoint/$kind.stable" "$live"
done
systemctl is-active --quiet "$watch.timer"
echo "DE_Meta_private_WG_sidecar_STAGED=true"
echo "DE_Meta_timer_persistent_UTC=$deadline"
echo "DE_public_DNS_original_five_UNCHANGED=true"
echo "DE_VPN_Xray_shared_Nginx_original_five_UNCHANGED=true"
trap - EXIT
flock -u 9
