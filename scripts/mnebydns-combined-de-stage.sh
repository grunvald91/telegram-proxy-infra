#!/usr/bin/env bash
# Stage a reversible three-app MNEBYDNS experiment. Production DNS remains
# unchanged until the separate guarded activation after RU and DE TLS tests.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 2 && "$1" =~ ^/tmp/mnebydns-combined-de-[0-9]+$ ]] || exit 2
work="$1"; deadline="$2"; id="$(basename "$work" | sed 's/^mnebydns-combined-de-//')"
[[ "$id" =~ ^[0-9]+$ ]] || exit 2
[[ "$deadline" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]][0-9]{2}:[0-9]{2}:[0-9]{2}[[:space:]]UTC$ ]] || exit 2
now="$(date -u +%s)"; expiry="$(date -u -d "$deadline" +%s)"
(( expiry - now >= 300 && expiry - now <= 2700 )) || exit 2
systemd-analyze calendar "$deadline" >/dev/null
root=/opt/mnebydns-stable-checkpoints
checkpoint="$(cat "$root/current")"
[[ "$checkpoint" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 2
(cd "$checkpoint" && sha256sum -c stable-manifest.sha256 >/dev/null)
base="/opt/mnebydns-combined-backups/$id"
sidecar=/etc/mnebydns-meta-pilot
service="mnebydns-combined-meta-$id"
watch="mnebydns-combined-de-watchdog-$id"
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 18 9 || exit 3
for kind in nginx dns proxy; do
  case "$kind" in
    nginx) live=/etc/nginx/nginx.conf ;;
    dns) live=/opt/mnebydns-dot/Corefile ;;
    proxy) live=/etc/mnebydns-googlepilot/nginx.conf ;;
  esac
  cmp -s "$checkpoint/$kind.stable" "$live" || {
    echo "combined_stage_refuses_stable_drift_$kind=true"; exit 3;
  }
done
for unit in nginx mnebydns-dot.service mnebydns-googlepilot.service mnebydns-gemini.service xray.service; do
  systemctl is-active --quiet "$unit"
done
ip -4 -o addr show dev tg-relay | grep -Fq '10.66.77.1/'
test "$(awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo)" -ge 300
test -z "$(ss -H -lnt 'sport = :19443')"
test ! -e "$base" && test ! -e "$sidecar"
for item in "/etc/systemd/system/$service.service" \
            "/etc/systemd/system/$watch.service" "/etc/systemd/system/$watch.timer"; do
  test ! -e "$item"
done
for source in mnebydns-combined-render.py mnebydns-chatgpt-de-overlay.py \
              mnebydns-meta-overlay.py mnebydns-stable-five-render.py \
              mnebydns-four-google-canary.py mnebydns-combined-de-rollback.sh; do
  test -s "$work/$source"
done
python3 "$work/mnebydns-combined-render.py" self-test
install -d -m 700 /opt/mnebydns-combined-backups
install -d -m 700 "$base"
printf '%s\n' "$checkpoint" > "$base/checkpoint.ref"
chmod 600 "$base/checkpoint.ref"
python3 "$work/mnebydns-combined-render.py" render \
  "$checkpoint/nginx.stable" "$checkpoint/dns.stable" "$checkpoint/proxy.stable" "$base"
for kind in nginx dns proxy; do
  test -s "$base/$kind.pilot"
  ! cmp -s "$checkpoint/$kind.stable" "$base/$kind.pilot"
done
test -s "$base/proxy.meta"
(cd "$base" && sha256sum nginx.pilot dns.pilot proxy.pilot proxy.meta checkpoint.ref > combined-manifest.sha256)
install -m 700 "$work/mnebydns-combined-de-rollback.sh" "$base/rollback.sh"
cat > "$base/$watch.service" <<UNIT
[Unit]
Description=Restore stable five services after combined DNS test
[Service]
Type=oneshot
ExecStart=/bin/bash $base/rollback.sh $base
UNIT
cat > "$base/$watch.timer" <<UNIT
[Unit]
Description=Persistent rollback timer for combined ChatGPT Meta DNS canary
[Timer]
OnCalendar=$deadline
Persistent=true
AccuracySec=1s
Unit=$watch.service
[Install]
WantedBy=timers.target
UNIT
cat > "$base/$service.service" <<UNIT
[Unit]
Description=Private WireGuard-only Meta TLS/SNI proxy
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
MemoryMax=90M
CPUQuota=20%
TasksMax=24
LimitNOFILE=384
Restart=on-failure
RestartSec=3s
TimeoutStopSec=8s
StandardOutput=journal
StandardError=journal
UNIT
install -m 644 "$base/$watch.service" "/etc/systemd/system/$watch.service"
install -m 644 "$base/$watch.timer" "/etc/systemd/system/$watch.timer"
install -m 644 "$base/$service.service" "/etc/systemd/system/$service.service"
systemctl daemon-reload
systemctl enable --now "$watch.timer" >/dev/null
systemctl is-active --quiet "$watch.timer"
test -n "$(systemctl list-timers --all --no-legend "$watch.timer")"
abort() {
  rc=$?; trap - EXIT
  flock -u 9 || true
  bash "$base/rollback.sh" "$base" || echo "combined_DE_stage_rollback_attention_required=true"
  exit "$rc"
}
trap abort EXIT
install -d -m 755 "$sidecar"
install -m 644 "$base/proxy.meta" "$sidecar/nginx.conf"
install -d -m 700 /run/mnebydns-meta-pilot
nginx -t -c "$sidecar/nginx.conf" >/dev/null 2>&1
nginx -t -c "$base/nginx.pilot" >/dev/null 2>&1
nginx -t -c "$base/proxy.pilot" >/dev/null 2>&1
systemctl start "$service.service"
ready=no
for _ in $(seq 1 40); do
  if systemctl is-active --quiet "$service.service" &&
     ss -H -lnt 'sport = :19443' | grep -Fq '10.66.77.1:19443'; then
    ready=yes; break
  fi
  sleep .25
done
test "$ready" = yes
for kind in nginx dns proxy; do
  case "$kind" in
    nginx) live=/etc/nginx/nginx.conf ;;
    dns) live=/opt/mnebydns-dot/Corefile ;;
    proxy) live=/etc/mnebydns-googlepilot/nginx.conf ;;
  esac
  cmp -s "$checkpoint/$kind.stable" "$live"
done
echo "combined_DE_private_Meta_tls_READY=true"
echo "combined_DE_ChatGPT_files_staged_no_public_cutover=true"
echo "combined_DE_rollback_UTC=$deadline"
echo "combined_DE_stable_five_unchanged=true"
trap - EXIT
flock -u 9
