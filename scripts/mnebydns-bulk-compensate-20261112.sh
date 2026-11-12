#!/usr/bin/env bash
# Compensating transaction if DB CAS fails AFTER stable bulk checkpoint commit.
# Only reverts the exact committed bulk pilot, never unrelated route changes.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 1 && "$1" =~ ^/opt/mnebydns-owner-domain/[1-9][0-9]{8,12}$ ]] || exit 2
base="$1"
live_dns=/opt/mnebydns-dot/Corefile
live_nginx=/etc/nginx/nginx.conf
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 45 9 || exit 3
# Atomic checkpoint promotion may precede the confirmed sentinel.
# The complete live/stable pilot equality below is the trusted proof.
test -s "$base/checkpoint.before"
before="$(cat "$base/checkpoint.before")"
current="$(cat /opt/mnebydns-stable-checkpoints/current)"
[[ "$current" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 3
[[ "$before" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 3
[[ "$before" != "$current" ]] || exit 3
(cd "$current" && sha256sum -c stable-manifest.sha256 >/dev/null)
(cd "$before" && sha256sum -c stable-manifest.sha256 >/dev/null)
cmp -s "$current/dns.stable" "$base/dns.pilot"
cmp -s "$current/nginx.stable" "$base/nginx.pilot"
cmp -s "$base/dns.pilot" "$live_dns"
cmp -s "$base/nginx.pilot" "$live_nginx"
cmp -s "$before/dns.stable" "$base/dns.before"
cmp -s "$before/nginx.stable" "$base/nginx.before"
cmp -s "$before/proxy.stable" /etc/mnebydns-googlepilot/nginx.conf
nginx -t -c "$base/nginx.before" >/dev/null 2>&1
new="/opt/mnebydns-stable-checkpoints/$(date -u +%s)"
test ! -e "$new"
mkdir -m 700 "$new"
cp -a "$before/." "$new/"
(cd "$new" && sha256sum -c stable-manifest.sha256 >/dev/null)
cp -p "$base/nginx.before" "$live_nginx.bulk-compensate"
mv -f "$live_nginx.bulk-compensate" "$live_nginx"
nginx -t >/dev/null 2>&1
systemctl reload nginx
cp -p "$base/dns.before" "$live_dns.bulk-compensate"
mv -f "$live_dns.bulk-compensate" "$live_dns"
bash "$base/reload.sh" "$live_dns"
for attempt in $(seq 1 50); do
  if systemctl is-active --quiet mnebydns-dot.service &&
     ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'; then
    break
  fi
  sleep .2
done
systemctl is-active --quiet nginx
systemctl is-active --quiet mnebydns-dot.service
cmp -s "$base/nginx.before" "$live_nginx"
cmp -s "$base/dns.before" "$live_dns"
cmp -s "$new/nginx.stable" "$live_nginx"
cmp -s "$new/dns.stable" "$live_dns"
temp="$(mktemp /opt/mnebydns-stable-checkpoints/current.next.XXXXXXXX)"
printf '%s\n' "$new" > "$temp"
chmod --reference=/opt/mnebydns-stable-checkpoints/current "$temp"
mv -f "$temp" /opt/mnebydns-stable-checkpoints/current
test "$(cat /opt/mnebydns-stable-checkpoints/current)" = "$new"
echo 'MNEBYDNS_BULK_COMPENSATING_REVERT_VERIFIED=true'
