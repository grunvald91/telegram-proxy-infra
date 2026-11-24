#!/usr/bin/env bash
# Restore only the exact before/pilot pair created by the bulk transaction.
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

exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 50 9
[[ "$(cat "$base/mode")" == bulk-add ]]
checkpoint="$(cat "$pointer")"
[[ "$checkpoint" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]]
(cd "$checkpoint" && sha256sum --strict -c stable-manifest.sha256 >/dev/null)

disarm() {
  systemctl disable --now "$name.timer" >/dev/null 2>&1 || true
  rm -f -- "/etc/systemd/system/$name.timer"
  systemctl daemon-reload
}

if test -f "$base/confirmed" || (
  cmp -s "$checkpoint/dns.stable" "$base/dns.pilot" &&
  cmp -s "$checkpoint/nginx.stable" "$base/nginx.pilot"
); then
  disarm
  echo 'owner_domain_canary_confirmed_no_rollback=true'
  exit 0
fi

cmp -s "$checkpoint/dns.stable" "$base/dns.before"
cmp -s "$checkpoint/nginx.stable" "$base/nginx.before"
cmp -s "$checkpoint/proxy.stable" "$proxy"
for pair in "dns:$dns" "nginx:$nginx"; do
  IFS=: read -r kind live <<< "$pair"
  if ! cmp -s "$base/$kind.before" "$live" && ! cmp -s "$base/$kind.pilot" "$live"; then
    echo "MASS_BULK_ROLLBACK_UNKNOWN_CONFIG=$kind" >&2
    exit 4
  fi
done

if cmp -s "$base/dns.pilot" "$dns"; then
  cp -p "$base/dns.before" "$dns.mass-rollback-$id"
  mv -f "$dns.mass-rollback-$id" "$dns"
  if systemctl is-active --quiet mnebydns-dot.service; then
    bash "$base/reload.sh" "$dns"
  else
    systemctl restart mnebydns-dot.service
  fi
elif ! systemctl is-active --quiet mnebydns-dot.service; then
  systemctl restart mnebydns-dot.service
fi
if cmp -s "$base/nginx.pilot" "$nginx"; then
  cp -p "$base/nginx.before" "$nginx.mass-rollback-$id"
  mv -f "$nginx.mass-rollback-$id" "$nginx"
  nginx -t -q
  systemctl reload nginx
fi
for attempt in $(seq 1 45); do
  if systemctl is-active --quiet mnebydns-dot.service &&
     ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'; then
    break
  fi
  sleep .2
done
systemctl is-active --quiet mnebydns-dot.service
systemctl is-active --quiet nginx
ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'
cmp -s "$base/dns.before" "$dns"
cmp -s "$base/nginx.before" "$nginx"
disarm
echo 'owner_domain_canary_rollback_verified=true'
