#!/usr/bin/env bash
# Owner-only exact-file rollback for temporary Meta RU:443 -> private WireGuard.
# It never writes unrelated Nginx configuration and never changes WireGuard.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 1 && "$1" =~ ^/opt/mnebydns-meta-ru-backups/[0-9]+$ ]] || exit 2
base="$1"
live=/etc/nginx/streams.d/01-mtproxy-443.conf
for f in before pilot; do test -s "$base/$f"; done
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 15 9 || { echo "ru_rollback_route_lock_failed=true"; exit 2; }
if cmp -s "$base/before" "$live"; then
  echo "ru_meta_rollback_already_baseline=true"
elif cmp -s "$base/pilot" "$live"; then
  cp -p "$base/before" "$live"
  nginx -t >/dev/null 2>&1
  systemctl reload nginx
  echo "ru_meta_nginx_route_reverted=true"
else
  echo "ru_meta_rollback_refuses_unowned_config=true"
  exit 3
fi
systemctl is-active --quiet nginx
runid="${base##*/}"
name="mnebydns-meta-ru-watchdog-$runid"
for kind in service timer; do
  unit=/etc/systemd/system/"$name.$kind"
  if test -e "$unit"; then
    cmp -s "$base/$name.$kind" "$unit" || {
      echo "ru_meta_rollback_refuses_changed_watchdog=$kind"; exit 3;
    }
  fi
done
systemctl disable --now "$name.timer" >/dev/null 2>&1 || true
for kind in service timer; do
  rm -f -- /etc/systemd/system/"$name.$kind"
done
systemctl daemon-reload
echo "ru_meta_pilot_rollback_completed=true"
