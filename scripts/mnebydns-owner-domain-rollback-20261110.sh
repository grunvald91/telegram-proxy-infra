#!/usr/bin/env bash
# Independent owner-domain canary rollback. Refuses to overwrite unrelated edits.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 1 && "$1" =~ ^/opt/mnebydns-owner-domain/[0-9]{9,13}$ ]] || exit 2
base="$1"
test -s "$base/dns.before"
test -s "$base/nginx.before"
test -s "$base/dns.pilot"
test -s "$base/nginx.pilot"
id="$(basename "$base")"
name="mnebydns-owner-rollback-$id"
live_dns=/opt/mnebydns-dot/Corefile
live_nginx=/etc/nginx/nginx.conf
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 55 9 || { echo 'owner_domain_rollback_lock_unavailable=true'; exit 3; }
# After a successful owner-confirmed promotion, the timer remains armed
# until expiry but MUST NOT revert a later stable checkpoint.
confirmed=false
if test -f "$base/confirmed"; then
  confirmed=true
else
  checkpoint="$(cat /opt/mnebydns-stable-checkpoints/current 2>/dev/null || true)"
  # A committed add OR removal may lose its 'confirmed' sentinel in the
  # tiny crash window after checkpoint promotion. Equality of the complete
  # checkpoint and live pilot is stronger proof than presence/absence of
  # a hostname marker, which is absent after a successful removal.
  if [[ "$checkpoint" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] &&
     (cd "$checkpoint" && sha256sum -c stable-manifest.sha256 >/dev/null) &&
     cmp -s "$checkpoint/dns.stable" "$base/dns.pilot" &&
     cmp -s "$checkpoint/nginx.stable" "$base/nginx.pilot" &&
     cmp -s "$base/dns.pilot" "$live_dns" &&
     cmp -s "$base/nginx.pilot" "$live_nginx"; then
    confirmed=true
  fi
fi
if [[ "$confirmed" == true ]]; then
  systemctl disable --now "$name.timer" >/dev/null 2>&1 || true
  rm -f -- "/etc/systemd/system/$name.timer"
  systemctl daemon-reload
  echo 'owner_domain_canary_confirmed_no_rollback=true'
  exit 0
fi
for kind in dns nginx; do
  case "$kind" in
    dns) current="$live_dns";;
    nginx) current="$live_nginx";;
  esac
  if ! cmp -s "$base/$kind.before" "$current" &&
     ! cmp -s "$base/$kind.pilot" "$current"; then
    echo "owner_domain_rollback_unrecognized_${kind}_state=true"
    exit 4
  fi
done
if cmp -s "$base/nginx.pilot" "$live_nginx"; then
  cp -p "$base/nginx.before" "$live_nginx.owner-rollback-$id"
  mv -f "$live_nginx.owner-rollback-$id" "$live_nginx"
  nginx -t >/dev/null 2>&1
  systemctl reload nginx
fi
if cmp -s "$base/dns.pilot" "$live_dns"; then
  cp -p "$base/dns.before" "$live_dns.owner-rollback-$id"
  mv -f "$live_dns.owner-rollback-$id" "$live_dns"
  systemctl restart mnebydns-dot.service
fi
# The rollback is successful only when DoT has re-opened public port 853.
for attempt in $(seq 1 60); do
  if systemctl is-active --quiet mnebydns-dot.service &&
     ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'; then
    break
  fi
  sleep .2
done
ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'
cmp -s "$base/dns.before" "$live_dns"
cmp -s "$base/nginx.before" "$live_nginx"
systemctl is-active --quiet nginx
systemctl is-active --quiet mnebydns-dot.service
systemctl disable --now "$name.timer" >/dev/null 2>&1 || true
rm -f -- "/etc/systemd/system/$name.timer"
systemctl daemon-reload
echo 'owner_domain_canary_rollback_verified=true'
