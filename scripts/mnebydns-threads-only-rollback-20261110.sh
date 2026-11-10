#!/usr/bin/env bash
# Independently runnable exact-file rollback for DE Threads-only pilot.
set -Eeuo pipefail
(( EUID==0 )) || exit 2
[[ $# == 1 && "$1" =~ ^/opt/mnebydns-threads-canary/[0-9]{9,13}$ ]] || exit 2
base="$1"; id="$(basename "$base")"
name="mnebydns-threads-rollback-$id"
live_dns=/opt/mnebydns-dot/Corefile
live_nginx=/etc/nginx/nginx.conf
for file in dns.before nginx.before dns.pilot nginx.pilot; do
  test -s "$base/$file"
done
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 25 9 || { echo 'threads_rollback_lock_failed=true'; exit 3; }
# Refuse to overwrite any unowned concurrent changes.
for pair in "dns:$live_dns" "nginx:$live_nginx"; do
  IFS=: read -r kind live <<< "$pair"
  if ! cmp -s "$base/$kind.before" "$live" &&
     ! cmp -s "$base/$kind.pilot" "$live"; then
    echo "threads_unowned_change_rollback_refused=true"
    exit 4
  fi
done
if ! cmp -s "$base/dns.before" "$live_dns"; then
  cp -p "$base/dns.before" "$live_dns.restore-$id"
  mv -f "$live_dns.restore-$id" "$live_dns"
  systemctl reset-failed mnebydns-dot.service || true
  systemctl restart mnebydns-dot.service
  echo 'threads_dns_route_rolled_back=true'
fi
if ! cmp -s "$base/nginx.before" "$live_nginx"; then
  cp -p "$base/nginx.before" "$live_nginx.restore-$id"
  mv -f "$live_nginx.restore-$id" "$live_nginx"
  nginx -t >/dev/null 2>&1
  systemctl reload nginx
  echo 'threads_public_sni_route_rolled_back=true'
fi
cmp -s "$base/dns.before" "$live_dns"
cmp -s "$base/nginx.before" "$live_nginx"
systemctl is-active --quiet nginx
systemctl is-active --quiet mnebydns-dot.service
for kind in service timer; do
  if [[ -e "/etc/systemd/system/$name.$kind" ]]; then
    cmp -s "$base/$name.$kind" "/etc/systemd/system/$name.$kind" ||
      { echo 'threads_rollback_unit_changed=true'; exit 5; }
  fi
done
systemctl disable --now "$name.timer" >/dev/null 2>&1 || true
rm -f -- "/etc/systemd/system/$name.service" "/etc/systemd/system/$name.timer"
systemctl daemon-reload
echo 'threads_original_dns_and_nginx_restored=true'
echo 'threads_rollback_finished=true'
