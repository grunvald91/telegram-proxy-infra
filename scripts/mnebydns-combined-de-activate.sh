#!/usr/bin/env bash
# DE cutover ONLY after private Meta and public RU TLS gates; 30m auto-revert.
# ChatGPT enters existing German Claude/Google 15449 SNI ingress.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 1 && "$1" =~ ^/opt/mnebydns-combined-backups/[0-9]+$ ]] || exit 2
base="$1"; id="$(basename "$base")"
checkpoint="$(cat /opt/mnebydns-stable-checkpoints/current)"
[[ "$checkpoint" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 2
test -s "$base/checkpoint.ref"
test "$(cat "$base/checkpoint.ref")" = "$checkpoint" || { echo "combined_DE_checkpoint_changed_during_canary=true"; exit 3; }
(cd "$checkpoint" && sha256sum -c stable-manifest.sha256 >/dev/null)
(cd "$base" && sha256sum -c combined-manifest.sha256 >/dev/null)
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
    echo "combined_DE_activation_refuses_stable_drift_$kind=true"; exit 3;
  }
done
test -s "$base/rollback.sh"
cmp -s "$base/proxy.meta" /etc/mnebydns-meta-pilot/nginx.conf
for unit in nginx mnebydns-dot.service mnebydns-googlepilot.service \
            mnebydns-gemini.service xray.service "$service.service" "$watch.timer"; do
  systemctl is-active --quiet "$unit"
done
ss -H -lnt 'sport = :19443' | grep -Fq '10.66.77.1:19443'
systemctl list-timers --all --no-legend "$watch.timer" | grep -Fq "$watch"
abort() {
  rc=$?
  trap - EXIT
  flock -u 9 || true
  bash "$base/rollback.sh" "$base" || echo "combined_DE_rollback_NOT_CONFIRMED=true"
  exit "$rc"
}
trap abort EXIT
# Foreign backend is loaded first. It preserves all stable names and existing
# backend socket, only adds ChatGPT names to its strict allowlist.
install -m 644 "$base/proxy.pilot" "/etc/mnebydns-googlepilot/nginx.conf.new-$id"
mv -f "/etc/mnebydns-googlepilot/nginx.conf.new-$id" /etc/mnebydns-googlepilot/nginx.conf
systemctl restart mnebydns-googlepilot.service
ready=no
for _ in $(seq 1 40); do
  if systemctl is-active --quiet mnebydns-googlepilot.service &&
    ss -H -lnt 'sport = :15449' | grep -Fq '127.0.0.1:15449'; then
    ready=yes; break
  fi
  sleep .25
done
test "$ready" = yes
cmp -s "$base/proxy.pilot" /etc/mnebydns-googlepilot/nginx.conf
# Public German 443 map is routed to the SAME backend as Claude/Google.
install -m 644 "$base/nginx.pilot" "/etc/nginx/nginx.conf.new-$id"
mv -f "/etc/nginx/nginx.conf.new-$id" /etc/nginx/nginx.conf
nginx -t >/dev/null
systemctl reload nginx
systemctl is-active --quiet nginx
cmp -s "$base/nginx.pilot" /etc/nginx/nginx.conf
# Switch DNS last. No window where synthetic answers point at a missing route.
install -m 644 "$base/dns.pilot" "/opt/mnebydns-dot/Corefile.new-$id"
mv -f "/opt/mnebydns-dot/Corefile.new-$id" /opt/mnebydns-dot/Corefile
systemctl restart mnebydns-dot.service
ready=no
for _ in $(seq 1 40); do
  if systemctl is-active --quiet mnebydns-dot.service &&
    ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'; then
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
  cmp -s "$base/$kind.pilot" "$live"
done
for unit in nginx mnebydns-dot.service mnebydns-googlepilot.service \
            mnebydns-gemini.service xray.service "$service.service" "$watch.timer"; do
  systemctl is-active --quiet "$unit"
done
echo "combined_DE_ChatGPT_to_existing_Claude_Google_route_ACTIVE=true"
echo "combined_DE_Meta_to_RU_private_WG_route_ACTIVE=true"
echo "combined_DE_stable_five_routes_preserved_in_pilot=true"
echo "combined_DE_independent_rollback_timer_ACTIVE=true"
trap - EXIT
flock -u 9
