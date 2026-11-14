#!/usr/bin/env bash
# Promote a strictly verified DNS-only candidate to a new stable checkpoint.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 1 && "$1" =~ ^/opt/mnebydns-fastpath/[1-9][0-9]{8,12}$ ]] || exit 2
base="$1"; id="$(basename "$base")"
dns=/opt/mnebydns-dot/Corefile
nginx=/etc/nginx/nginx.conf
proxy=/etc/mnebydns-googlepilot/nginx.conf
pointer=/opt/mnebydns-stable-checkpoints/current
unit="mnebydns-fastpath-rollback-$id"
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 50 9 || exit 3
old="$(cat "$base/checkpoint.before")"
current="$(cat "$pointer")"
[[ "$old" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 3
[[ "$current" == "$old" ]] || exit 4
test ! -e "$base/confirmed"
(cd "$old" && sha256sum -c stable-manifest.sha256 >/dev/null)
cmp -s "$old/dns.stable" "$base/dns.before"
cmp -s "$old/nginx.stable" "$nginx"
cmp -s "$old/proxy.stable" "$proxy"
cmp -s "$base/dns.pilot" "$dns"
systemctl is-active --quiet "$unit.timer"
systemctl is-active --quiet nginx
systemctl is-active --quiet mnebydns-dot.service
nginx -t >/dev/null 2>&1
target="/opt/mnebydns-stable-checkpoints/$(date -u +%s)"
test ! -e "$target"
mkdir -m 700 "$target"
cp -a "$old/." "$target/"
cp -p "$base/dns.pilot" "$target/dns.stable"
(cd "$target" && sha256sum nginx.stable dns.stable proxy.stable > stable-manifest.sha256)
(cd "$target" && sha256sum -c stable-manifest.sha256 >/dev/null)
cmp -s "$target/dns.stable" "$dns"
cmp -s "$target/nginx.stable" "$nginx"
cmp -s "$target/proxy.stable" "$proxy"
tmp="$(mktemp /opt/mnebydns-stable-checkpoints/current.fastpath.XXXXXXXX)"
printf '%s\n' "$target" > "$tmp"
chmod --reference="$pointer" "$tmp"
mv -f "$tmp" "$pointer"
test "$(cat "$pointer")" = "$target"
touch "$base/confirmed"
systemctl stop "$unit.timer" >/dev/null 2>&1 || true
echo "FASTPATH_CONFIRMED_STABLE=true"
echo "FASTPATH_COMMIT_CHECKPOINT=$target"
