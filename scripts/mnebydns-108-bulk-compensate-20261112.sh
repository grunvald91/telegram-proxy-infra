#!/usr/bin/env bash
# Compensating revert only for a confirmed mass pilot whose DB commit failed.
# Never overwrite concurrent edits or a newer stable checkpoint.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 1 && "$1" =~ ^/opt/mnebydns-owner-domain/[1-9][0-9]{8,12}$ ]] || exit 2
base="$1"
id="$(basename "$base")"
name="mnebydns-owner-rollback-$id"
dns=/opt/mnebydns-dot/Corefile
nginx=/etc/nginx/nginx.conf
proxy=/etc/mnebydns-googlepilot/nginx.conf
pointer=/opt/mnebydns-stable-checkpoints/current
test -f "$base/confirmed"
test ! -e "$base/bulk-compensated"
old="$(cat "$base/checkpoint.before")"
new="$(cat "$pointer")"
[[ "$old" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]]
[[ "$new" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]]
test "$old" != "$new"
(cd "$old" && sha256sum -c stable-manifest.sha256 >/dev/null)
(cd "$new" && sha256sum -c stable-manifest.sha256 >/dev/null)
cmp -s "$old/dns.stable" "$base/dns.before"
cmp -s "$old/nginx.stable" "$base/nginx.before"
cmp -s "$old/proxy.stable" "$proxy"
cmp -s "$new/dns.stable" "$base/dns.pilot"
cmp -s "$new/nginx.stable" "$base/nginx.pilot"
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 45 9 || exit 3
test "$(cat "$pointer")" = "$new"
cmp -s "$base/dns.pilot" "$dns"
cmp -s "$base/nginx.pilot" "$nginx"
cmp -s "$old/proxy.stable" "$proxy"
cp -p "$base/nginx.before" "$nginx.mass-compensate-$id"
mv -f "$nginx.mass-compensate-$id" "$nginx"
nginx -t >/dev/null 2>&1
systemctl reload nginx
cp -p "$base/dns.before" "$dns.mass-compensate-$id"
mv -f "$dns.mass-compensate-$id" "$dns"
bash "$base/reload.sh" "$dns"
for attempt in $(seq 1 60); do
  if systemctl is-active --quiet mnebydns-dot.service &&
     ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'; then break; fi
  sleep .2
done
cmp -s "$base/dns.before" "$dns"
cmp -s "$base/nginx.before" "$nginx"
nginx -t >/dev/null 2>&1
systemctl is-active --quiet nginx
systemctl is-active --quiet mnebydns-dot.service
ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'
tmp="$(mktemp /opt/mnebydns-stable-checkpoints/current.mass-revert.XXXXXXXX)"
printf '%s\n' "$old" > "$tmp"
chmod --reference="$pointer" "$tmp"
mv -f "$tmp" "$pointer"
test "$(cat "$pointer")" = "$old"
touch "$base/bulk-compensated"
systemctl disable --now "$name.timer" >/dev/null 2>&1 || true
rm -f -- "/etc/systemd/system/$name.timer"
systemctl daemon-reload
echo 'MASS_BULK_COMPENSATING_RESTORE_VERIFIED=true'
