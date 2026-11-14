#!/usr/bin/env bash
# Independent DNS-only rollback; never changes Nginx/Proxy/VPN or client data.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 1 && "$1" =~ ^/opt/mnebydns-fastpath/[1-9][0-9]{8,12}$ ]] || exit 2
base="$1"; id="$(basename "$base")"
dns=/opt/mnebydns-dot/Corefile
nginx=/etc/nginx/nginx.conf
proxy=/etc/mnebydns-googlepilot/nginx.conf
pointer=/opt/mnebydns-stable-checkpoints/current
unit="mnebydns-fastpath-rollback-$id"
test -s "$base/dns.before"
test -s "$base/dns.pilot"
test -s "$base/checkpoint.before"
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 55 9 || { echo 'FASTPATH_ROLLBACK_LOCK_FAILED=true'; exit 3; }
old="$(cat "$base/checkpoint.before")"
current="$(cat "$pointer")"
[[ "$old" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 3
(cd "$old" && sha256sum -c stable-manifest.sha256 >/dev/null)
cmp -s "$old/dns.stable" "$base/dns.before"
cmp -s "$old/nginx.stable" "$nginx"
cmp -s "$old/proxy.stable" "$proxy"
if [[ "$old" != "$current" ]]; then
  # A committed newer checkpoint must not be reverted by the watchdog.
  if [[ -f "$base/confirmed" ]] &&
     [[ "$current" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] &&
     cmp -s "$base/dns.pilot" "$dns" &&
     cmp -s "$current/dns.stable" "$dns"; then
    echo "FASTPATH_ALREADY_CONFIRMED_NO_ROLLBACK=true"
    exit 0
  fi
  echo 'FASTPATH_ROLLBACK_REFUSES_NEWER_CHECKPOINT=true' >&2
  exit 4
fi
if cmp -s "$base/dns.pilot" "$dns"; then
  cp -p "$base/dns.before" "$dns.fastpath-restore-$id"
  mv -f "$dns.fastpath-restore-$id" "$dns"
  if ! bash "$base/reload.sh" "$dns"; then
    cmp -s "$base/dns.before" "$dns"
    systemctl restart mnebydns-dot.service
  fi
elif ! cmp -s "$base/dns.before" "$dns"; then
  echo 'FASTPATH_ROLLBACK_UNRECOGNIZED_LIVE_CONFIG=true' >&2
  exit 4
fi
for attempt in $(seq 1 50); do
  if systemctl is-active --quiet mnebydns-dot.service &&
     ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'; then break; fi
  sleep .2
done
cmp -s "$base/dns.before" "$dns"
cmp -s "$old/nginx.stable" "$nginx"
cmp -s "$old/proxy.stable" "$proxy"
test "$(cat "$pointer")" = "$old"
systemctl is-active --quiet nginx
systemctl is-active --quiet mnebydns-dot.service
ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'
systemctl stop "$unit.timer" >/dev/null 2>&1 || true
echo 'FASTPATH_ROLLBACK_VERIFIED=true'
