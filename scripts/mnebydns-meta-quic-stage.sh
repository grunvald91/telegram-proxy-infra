#!/usr/bin/env bash
# Stage owner-only allowlisted QUIC UDP relay. Arm independent persistent rollback
# before starting listener. No shared DNS/TCP, firewall or VPN service changes.
set -Eeuo pipefail
(( EUID==0 )) || exit 2
[[ $# == 3 && ( "$1" == ru || "$1" == de ) && "$2" =~ ^[0-9]{9,13}$ ]] || exit 2
role="$1"; id="$2"; deadline="$3"
[[ "$deadline" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]][0-9]{2}:[0-9]{2}:[0-9]{2}[[:space:]]UTC$ ]] || exit 2
now="$(date -u +%s)"; expiry="$(date -u -d "$deadline" +%s)"
(( expiry-now>=180 && expiry-now<=3600 )) || exit 2
work="/tmp/mnebydns-meta-quic-$id"
base="/opt/mnebydns-meta-quic-$id"
unit="mnebydns-meta-quic-$role-$id"
watch="$unit-rollback"
test -s "$work/mnebydns-meta-quic.py"
test -s "$work/mnebydns-meta-quic-rollback.sh"
test ! -e "$base"
for n in "$unit.service" "$watch.service" "$watch.timer"; do
  test ! -e "/etc/systemd/system/$n"
done
systemd-analyze calendar "$deadline" >/dev/null
python3 -c 'import cryptography'
ss -H -lun "sport = :$([[ $role == ru ]] && echo 443 || echo 19444)" | grep . && {
  echo "meta_quic_${role}_udp_port_not_free=true"; exit 3;
} || true
ip -4 -o addr show dev tg-relay | grep -Fq "$([[ $role == ru ]] && echo '10.66.77.2/' || echo '10.66.77.1/')"
if [[ "$role" == ru ]]; then
  ip -4 route get 10.66.77.1 | grep -Fq tg-relay
  systemctl is-active --quiet nginx
  test ! -e /etc/mnebydns-meta-pilot || { echo 'RU_unexpected_DE_meta_marker=true'; exit 3; }
else
  ip -4 route get 10.66.77.2 | grep -Fq tg-relay
  systemctl is-active --quiet mnebydns-dot.service
  systemctl is-active --quiet mnebydns-googlepilot.service
  stable="$(cat /opt/mnebydns-stable-checkpoints/current)"
  [[ "$stable" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]]
  cmp -s "$stable/dns.stable" /opt/mnebydns-dot/Corefile
  cmp -s "$stable/nginx.stable" /etc/nginx/nginx.conf
  cmp -s "$stable/proxy.stable" /etc/mnebydns-googlepilot/nginx.conf
fi
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 30 9 || exit 3
install -d -m 755 "$base"
install -m 644 "$work/mnebydns-meta-quic.py" "$base/relay.py"
install -m 700 "$work/mnebydns-meta-quic-rollback.sh" "$base/rollback.sh"
if [[ "$role" == ru ]]; then
  listen_args="--role ru --bind 0.0.0.0 --port 443 --peer 10.66.77.1"
  cap=$'AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE'
else
  listen_args="--role de --bind 10.66.77.1 --port 19444 --peer 10.66.77.2"
  cap=""
fi
cat > "$base/$unit.service" <<UNIT
[Unit]
Description=Temporary MNEBYDNS Meta-only QUIC $role UDP relay
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 $base/relay.py $listen_args
DynamicUser=yes
NoNewPrivileges=yes
$cap
ProtectSystem=strict
ProtectHome=yes
PrivateDevices=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_UNIX
MemoryMax=96M
CPUQuota=30%
TasksMax=32
LimitNOFILE=1024
Restart=on-failure
RestartSec=2s
StandardOutput=journal
StandardError=journal
UNIT
cat > "$base/$watch.service" <<UNIT
[Unit]
Description=Restore previous MNEBYDNS UDP state after QUIC owner pilot
[Service]
Type=oneshot
ExecStart=/bin/bash $base/rollback.sh $role $id
UNIT
cat > "$base/$watch.timer" <<UNIT
[Unit]
Description=Persistent timer to stop temporary Meta QUIC $role service
[Timer]
OnCalendar=$deadline
Persistent=true
AccuracySec=1s
Unit=$watch.service
[Install]
WantedBy=timers.target
UNIT
for f in "$unit.service" "$watch.service" "$watch.timer"; do
  install -m 644 "$base/$f" "/etc/systemd/system/$f"
done
systemctl daemon-reload
systemctl enable --now "$watch.timer" >/dev/null
systemctl is-active --quiet "$watch.timer"
# rollback function must never execute while the stage script owns lock.
abort(){
  rc=$?
  trap - EXIT
  flock -u 9
  bash "$base/rollback.sh" "$role" "$id" || echo "meta_quic_${role}_rollback_requires_attention=true"
  exit "$rc"
}
trap abort EXIT
systemctl start "$unit.service"
ready=false
for _ in $(seq 1 30); do
  if systemctl is-active --quiet "$unit.service" &&
     ss -H -lun "sport = :$([[ $role == ru ]] && echo 443 || echo 19444)" | grep -q .; then
    ready=true;break
  fi
  sleep .2
done
test "$ready" = true
systemctl is-active --quiet "$watch.timer"
echo "meta_quic_${role}_UDP_listener_ACTIVE=true"
echo "meta_quic_${role}_rollback_UTC=$deadline"
echo "meta_quic_${role}_TCP_DNS_VPN_originals_unchanged=true"
trap - EXIT
flock -u 9