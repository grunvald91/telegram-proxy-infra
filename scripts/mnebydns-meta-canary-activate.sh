#!/usr/bin/env bash
# Enable ONLY the temporary Meta CoreDNS overlay after both private hops passed.
# The existing five-service SNI proxy and all VPN/Telegram configs remain unchanged.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 1 && "$1" =~ ^/opt/mnebydns-experiment-backups/[0-9]+$ ]] || exit 2
base="$1"
runid="$(basename "$base")"
root=/opt/mnebydns-stable-checkpoints
checkpoint="$(cat "$root/current")"
[[ "$checkpoint" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 2
dns=/opt/mnebydns-dot/Corefile
service="mnebydns-meta-pilot-$runid"
watchdog="mnebydns-meta-revert-$runid"
for file in dns.before dns.pilot proxy.meta pilot.service watchdog.service watchdog.timer; do
  test -s "$base/$file"
done
(cd "$checkpoint" && sha256sum -c stable-manifest.sha256 >/dev/null)
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 20 9 || exit 3
abort() {
  code=$?
  trap - EXIT
  flock -u 9 || true
  bash "$base/rollback.sh" "$base" || echo meta_dns_activation_rollback_NOT_CONFIRMED=true
  exit "$code"
}
trap abort EXIT
cmp -s "$checkpoint/dns.stable" "$dns" || { echo meta_dns_not_at_stable_baseline=true; exit 4; }
cmp -s "$checkpoint/dns.stable" "$base/dns.before"
cmp -s "$checkpoint/nginx.stable" /etc/nginx/nginx.conf
cmp -s "$checkpoint/proxy.stable" /etc/mnebydns-googlepilot/nginx.conf
cmp -s "$base/proxy.meta" /etc/mnebydns-meta-private/nginx.conf
systemctl is-active --quiet "$service.service"
systemctl is-active --quiet "$watchdog.timer"
ss -H -lnt 'sport = :19443' | grep -Fq '10.66.77.1:19443'
install -m 644 "$base/dns.pilot" "$dns.meta-$runid"
mv -f "$dns.meta-$runid" "$dns"
systemctl reset-failed mnebydns-dot.service || true
systemctl restart mnebydns-dot.service
ready=no
for i in $(seq 1 40); do
  if systemctl is-active --quiet mnebydns-dot.service &&
     ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'; then ready=yes; break; fi
  sleep .2
done
test "$ready" = yes || { echo meta_DoT_not_ready_after_restart=true; exit 5; }
cmp -s "$base/dns.pilot" "$dns"
systemctl is-active --quiet nginx
systemctl is-active --quiet xray.service
systemctl is-active --quiet mnebydns-googlepilot.service
echo meta_temporary_public_DoT_routes_ACTIVE=true
echo five_service_SNI_and_VPN_untouched=true
echo meta_automatic_rollback_timer_ACTIVE=true
trap - EXIT
flock -u 9
