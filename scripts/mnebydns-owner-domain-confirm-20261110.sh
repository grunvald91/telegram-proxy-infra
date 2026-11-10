#!/usr/bin/env bash
# Permanently accept only an already verified, current owner-domain canary.
# The expiry timer stays armed until its expiration; rollback sees confirmed
# checkpoint and becomes a no-op. No unguarded window during commit.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 1 && "$1" =~ ^/opt/mnebydns-owner-domain/[0-9]{9,13}$ ]] || exit 2
base="$1"
test -s "$base/domain"
test -s "$base/dns.before"
test -s "$base/nginx.before"
test -s "$base/dns.pilot"
test -s "$base/nginx.pilot"
id="$(basename "$base")"
name="mnebydns-owner-rollback-$id"
live_dns=/opt/mnebydns-dot/Corefile
live_nginx=/etc/nginx/nginx.conf

exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 35 9 || exit 3
# Crash-recovery: the checkpoint pointer may have been promoted just
# before the process crashed, but before 'confirmed' was written. The
# independent timer must not undo a committed checkpoint, and retry must
# be able to finish the database transition after proving the live state.
current="$(cat /opt/mnebydns-stable-checkpoints/current)"
[[ "$current" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 4
(cd "$current" && sha256sum -c stable-manifest.sha256 >/dev/null)
if cmp -s "$current/dns.stable" "$base/dns.pilot" &&
   cmp -s "$current/nginx.stable" "$base/nginx.pilot"; then
  cmp -s "$base/dns.pilot" "$live_dns"
  cmp -s "$base/nginx.pilot" "$live_nginx"
  nginx -t >/dev/null 2>&1
  systemctl is-active --quiet nginx
  systemctl is-active --quiet mnebydns-dot.service
  touch "$base/confirmed"
  echo 'owner_domain_already_confirmed=true'
  exit 0
fi
# A stray sentinel alone is never permission to claim a successful route.
test ! -f "$base/confirmed" || { echo 'owner_domain_confirmed_state_drift=true'; exit 4; }
systemctl is-active --quiet "$name.timer"
test -s "$base/$name.timer"
# Confirmation must precede automatic rollback by at least 4 minutes.
deadline="$(sed -n 's/^OnCalendar=//p' "$base/$name.timer")"
expiry="$(date -u -d "$deadline" +%s)"
now="$(date -u +%s)"
(( expiry-now>240 )) || { echo 'owner_domain_confirmation_too_late=true'; exit 4; }
cmp -s "$base/dns.pilot" "$live_dns"
cmp -s "$base/nginx.pilot" "$live_nginx"
nginx -t >/dev/null 2>&1
systemctl is-active --quiet nginx
systemctl is-active --quiet mnebydns-dot.service

old="$(cat /opt/mnebydns-stable-checkpoints/current)"
[[ "$old" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 4
(cd "$old" && sha256sum -c stable-manifest.sha256 >/dev/null)
cmp -s "$old/dns.stable" "$base/dns.before"
cmp -s "$old/nginx.stable" "$base/nginx.before"
cmp -s "$old/proxy.stable" /etc/mnebydns-googlepilot/nginx.conf
new="/opt/mnebydns-stable-checkpoints/$(date -u +%s)"
test ! -e "$new"
mkdir -m 700 "$new"
cp -a "$old/." "$new/"
cp -p "$base/dns.pilot" "$new/dns.stable"
cp -p "$base/nginx.pilot" "$new/nginx.stable"
(cd "$new" && sha256sum nginx.stable dns.stable proxy.stable > stable-manifest.sha256)
(cd "$new" && sha256sum -c stable-manifest.sha256 >/dev/null)
cmp -s "$new/dns.stable" "$live_dns"
cmp -s "$new/nginx.stable" "$live_nginx"
printf '%s\n' "$old" > "$base/checkpoint.before"
tmp="$(mktemp /opt/mnebydns-stable-checkpoints/current.next.XXXXXXXX)"
printf '%s\n' "$new" > "$tmp"
chmod --reference=/opt/mnebydns-stable-checkpoints/current "$tmp"
mv -f "$tmp" /opt/mnebydns-stable-checkpoints/current
test "$(cat /opt/mnebydns-stable-checkpoints/current)" = "$new"
# Sentinel is written only after atomic checkpoint promotion. Until then the
# independent timer will restore original config if nothing commits.
touch "$base/confirmed"
echo "owner_domain_committed_checkpoint=$new"
echo 'owner_domain_confirmed_stable=true'
