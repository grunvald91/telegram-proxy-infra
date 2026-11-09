#!/usr/bin/env bash
# Exact-file rollback of a temporary public DE Meta SNI map.
# Never changes DNS, VPN, WG, firewall, other Nginx files, or non-owned routes.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 1 && "$1" =~ ^/opt/mnebydns-meta-de-public-backups/[0-9]{9,13}$ ]] || exit 2
base="$1"; id="$(basename "$base")"
live=/etc/nginx/nginx.conf
name="mnebydns-meta-de-public-watchdog-$id"
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 20 9 || { echo 'de_public_meta_rollback_lock_unavailable=true'; exit 3; }
test -s "$base/before" && test -s "$base/pilot"
if cmp -s "$base/before" "$live"; then
  echo 'de_public_meta_nginx_already_original=true'
elif cmp -s "$base/pilot" "$live"; then
  cp -p "$base/before" "$live"
  nginx -t >/dev/null 2>&1 || { echo 'de_public_meta_rollback_nginx_test_failed=true'; exit 4; }
  systemctl reload nginx
  echo 'de_public_meta_exact_route_removed=true'
else
  echo 'de_public_meta_refuses_unowned_nginx_changes=true'
  exit 5
fi
cmp -s "$base/before" "$live"
systemctl is-active --quiet nginx
for kind in service timer; do
  f="/etc/systemd/system/$name.$kind"
  if [[ -e "$f" ]]; then
    cmp -s "$base/$name.$kind" "$f" || {
      echo "de_public_meta_rollback_guard_drift_$kind=true"
      exit 6
    }
  fi
done
systemctl disable --now "$name.timer" >/dev/null 2>&1 || true
rm -f -- "/etc/systemd/system/$name.service" "/etc/systemd/system/$name.timer"
systemctl daemon-reload
echo 'de_public_meta_rollback_complete=true'
echo 'de_public_meta_DNS_VPN_other_configs_untouched=true'
