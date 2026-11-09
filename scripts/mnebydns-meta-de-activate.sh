#!/usr/bin/env bash
# Activate only the Meta A+RR overlay on DE after both private/TLS and RU SNI gates.
# This file does not modify nginx, the original five-route proxy or VPN.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 1 && "$1" =~ ^/opt/mnebydns-experiment-backups/[0-9]+$ ]] || exit 2
base="$1"
id="$(basename "$base")"
stable_root=/opt/mnebydns-stable-checkpoints
checkpoint="$(cat "$stable_root/current")"
[[ "$checkpoint" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 2
(cd "$checkpoint" && sha256sum -c stable-manifest.sha256 >/dev/null)
live_dns=/opt/mnebydns-dot/Corefile
service="mnebydns-meta-pilot-$id"
watch="mnebydns-meta-de-watchdog-$id"
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 18 9 || exit 3
cmp -s "$checkpoint/nginx.stable" /etc/nginx/nginx.conf
cmp -s "$checkpoint/proxy.stable" /etc/mnebydns-googlepilot/nginx.conf
cmp -s "$checkpoint/dns.stable" "$live_dns" || { echo "DE_Meta_activation_refuses_unknown_DNS=true"; exit 3; }
test -s "$base/dns.pilot"
test -s "$base/proxy.meta"
cmp -s "$base/proxy.meta" /etc/mnebydns-meta-pilot/nginx.conf
systemctl is-active --quiet "$service.service"
systemctl is-active --quiet "$watch.timer"
ss -H -lnt 'sport = :19443' | grep -Fq '10.66.77.1:19443'
for unit in nginx mnebydns-gemini.service mnebydns-googlepilot.service xray.service; do
  systemctl is-active --quiet "$unit"
done
check_calendar="$(systemctl list-timers --all --no-legend "$watch.timer" || true)"
test -n "$check_calendar"
echo "DE_Meta_rollback_timer_armed=true"
abort(){
  code=$?
  trap - EXIT
  flock -u 9 || true
  bash "$base/rollback.sh" "$base" || echo "DE_Meta_ACTIVATION_FAILURE_MANUAL_ROLLBACK_NEEDED=true"
  exit "$code"
}
trap abort EXIT
install -m 644 "$base/dns.pilot" "$live_dns.new-meta-$id"
mv -f "$live_dns.new-meta-$id" "$live_dns"
systemctl reset-failed mnebydns-dot.service || true
systemctl restart mnebydns-dot.service
ready=no
for _ in $(seq 1 40); do
  if systemctl is-active --quiet mnebydns-dot.service &&
     ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'; then ready=yes; break; fi
  sleep .25
done
test "$ready" = yes
cmp -s "$base/dns.pilot" "$live_dns"
cmp -s "$checkpoint/nginx.stable" /etc/nginx/nginx.conf
cmp -s "$checkpoint/proxy.stable" /etc/mnebydns-googlepilot/nginx.conf
systemctl is-active --quiet "$watch.timer"
echo "DE_Meta_exact_DNS_overlay_ACTIVE_TEMPORARY=true"
echo "DE_five_other_service_configs_byte_identical=true"
echo "DE_original_VPN_and_shared_443_untouched=true"
trap - EXIT
flock -u 9
