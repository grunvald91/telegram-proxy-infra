#!/usr/bin/env bash
# Stage an isolated German Meta sidecar and persistent 24-minute recovery timer.
# This phase does NOT change public DNS, shared Nginx, Xray or existing VPN.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 1 && "$1" =~ ^/tmp/mnebydns-meta-safe-[0-9]+$ ]] || exit 2
work="$1"
runid="$(basename "$work" | awk -F- '{print $NF}')"
[[ "$runid" =~ ^[0-9]+$ ]] || exit 2
root=/opt/mnebydns-stable-checkpoints
checkpoint="$(cat "$root/current")"
[[ "$checkpoint" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 2
base="/opt/mnebydns-experiment-backups/$runid"
name="mnebydns-meta-pilot-$runid"
timer="mnebydns-meta-revert-$runid"
meta=/etc/mnebydns-meta-private/nginx.conf
dns=/opt/mnebydns-dot/Corefile
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 20 9 || exit 3
(cd "$checkpoint" && sha256sum -c stable-manifest.sha256 >/dev/null)
for pair in nginx:/etc/nginx/nginx.conf dns:/opt/mnebydns-dot/Corefile proxy:/etc/mnebydns-googlepilot/nginx.conf; do
  kind="$(printf '%s' "$pair" | cut -d: -f1)"
  file="$(printf '%s' "$pair" | cut -d: -f2)"
  cmp -s "$checkpoint/$kind.stable" "$file" || {
    echo "unowned_stable_config_refuse_deploy=$kind"; exit 4;
  }
done
for unit in nginx mnebydns-dot.service mnebydns-googlepilot.service xray.service; do
  systemctl is-active --quiet "$unit"
done
test -s "$work/mnebydns-meta-overlay.py"
test -s "$work/mnebydns-four-google-canary.py"
test -s "$work/mnebydns-meta-canary-rollback.sh"
python3 "$work/mnebydns-meta-overlay.py" self-test
ip -4 -o addr show dev tg-relay | grep -Fq '10.66.77.1/'
test -z "$(ss -H -lnt 'sport = :19443')"
test ! -e "$base" && test ! -e /etc/mnebydns-meta-private
test ! -e "/etc/systemd/system/$name.service"
test ! -e "/etc/systemd/system/$timer.service"
test ! -e "/etc/systemd/system/$timer.timer"
test "$(awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo)" -ge 300
install -d -m 700 /opt/mnebydns-experiment-backups
install -d -m 700 "$base"
cp -p "$dns" "$base/dns.before"
python3 "$work/mnebydns-meta-overlay.py" render "$dns" "$base"
install -m 700 "$work/mnebydns-meta-canary-rollback.sh" "$base/rollback.sh"
test -s "$base/dns.pilot" && test -s "$base/proxy.meta"
fail() {
  code=$?
  trap - EXIT
  flock -u 9 || true
  bash "$base/rollback.sh" "$base" || echo "meta_stage_rollback_NOT_CONFIRMED=true"
  exit "$code"
}
trap fail EXIT
cat > "$base/pilot.service" <<UNIT
[Unit]
Description=Isolated MNEBYDNS Meta-only private WireGuard TLS passthrough
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/sbin/nginx -c /etc/mnebydns-meta-private/nginx.conf -g "daemon off;"
DynamicUser=yes
RuntimeDirectory=mnebydns-meta-pilot
RuntimeDirectoryMode=0700
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
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
[Install]
WantedBy=multi-user.target
UNIT
deadline="$(date -u -d '+24 minutes' +'%Y-%m-%d %H:%M:%S UTC')"
systemd-analyze calendar "$deadline" >/dev/null
cat > "$base/watchdog.service" <<UNIT
[Unit]
Description=Rollback only MNEBYDNS Meta temporary canary to five stable services
[Service]
Type=oneshot
ExecStart=/bin/bash $base/rollback.sh $base
UNIT
cat > "$base/watchdog.timer" <<UNIT
[Unit]
Description=Persistent 24-minute auto-rollback of unverified Meta DNS routes
[Timer]
OnCalendar=$deadline
Persistent=true
AccuracySec=1s
Unit=$timer.service
[Install]
WantedBy=timers.target
UNIT
install -d -m 755 /etc/mnebydns-meta-private
install -m 644 "$base/proxy.meta" "$meta"
install -d -m 700 /run/mnebydns-meta-pilot
nginx -t -c "$meta" >/dev/null
install -m 644 "$base/pilot.service" "/etc/systemd/system/$name.service"
install -m 644 "$base/watchdog.service" "/etc/systemd/system/$timer.service"
install -m 644 "$base/watchdog.timer" "/etc/systemd/system/$timer.timer"
systemctl daemon-reload
systemctl enable --now "$timer.timer" >/dev/null
systemctl is-active --quiet "$timer.timer"
systemctl start "$name.service"
ready=no
for _ in $(seq 1 40); do
  if systemctl is-active --quiet "$name.service" &&
     ss -H -lnt 'sport = :19443' | grep -Fq '10.66.77.1:19443'; then
    ready=yes; break
  fi
  sleep .2
done
test "$ready" = yes || { echo meta_sidecar_live_not_ready=true; exit 5; }
cmp -s "$checkpoint/dns.stable" "$dns"
cmp -s "$checkpoint/nginx.stable" /etc/nginx/nginx.conf
cmp -s "$checkpoint/proxy.stable" /etc/mnebydns-googlepilot/nginx.conf
echo "meta_private_sidecar_ready=true"
echo "meta_watchdog_rollback_utc=$deadline"
echo "meta_public_DNS_remains_stable=true"
echo "meta_sidecar_only_WireGuard_10_66_77_1_port19443=true"
trap - EXIT
flock -u 9
