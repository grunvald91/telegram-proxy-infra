#!/usr/bin/env bash
# One-time narrowly scoped repair of DoT config readability. No DNS content edits.
set -Eeuo pipefail
trap 'exit_code=$?; echo "MNEBYDNS_DOT_RECOVERY_FAILED line=$LINENO code=$exit_code" >&2; exit "$exit_code"' ERR
echo 'MNEBYDNS_DOT_RECOVERY_PRECHECK_STARTED=true'
(( EUID == 0 )) || exit 2
[[ $# == 0 ]] || exit 2
dns=/opt/mnebydns-dot/Corefile
nginx=/etc/nginx/nginx.conf
proxy=/etc/mnebydns-googlepilot/nginx.conf
pointer=/opt/mnebydns-stable-checkpoints/current
service=mnebydns-dot.service
test -f "$dns" && test ! -L "$dns"
test -f "$pointer" && test ! -L "$pointer"
checkpoint="$(cat "$pointer")"
[[ "$checkpoint" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 3
(cd "$checkpoint" && sha256sum -c stable-manifest.sha256 >/dev/null)
for pair in "dns:$dns" "nginx:$nginx" "proxy:$proxy"; do
  IFS=: read -r kind live <<< "$pair"
  cmp -s "$checkpoint/$kind.stable" "$live" || {
    echo "DOT_REPAIR_BASELINE_DRIFT_$kind=true"; exit 3;
  }
done
test "$(systemctl show --value -p User "$service")" = mnebydns-dot
test "$(systemctl show --value -p Group "$service")" = mnebydns-dot
test "$(systemctl show --value -p DynamicUser "$service")" = yes
test "$(stat -c '%u' "$dns")" = 0
before="$(sha256sum "$dns" | cut -d' ' -f1)"
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 45 9 || { echo 'DOT_REPAIR_PUBLIC_ROUTE_LOCK_BUSY=true'; exit 3; }
test "$(cat "$pointer")" = "$checkpoint"
cmp -s "$checkpoint/dns.stable" "$dns"
cmp -s "$checkpoint/nginx.stable" "$nginx"
cmp -s "$checkpoint/proxy.stable" "$proxy"
# Keep DynamicUser=yes, granting file read only via a restricted static group.
reader=mnebydns-config-read
if ! getent group "$reader" >/dev/null; then
  groupadd --system -- "$reader"
  echo 'MNEBYDNS_DOT_STATIC_READER_GROUP_CREATED=true'
fi
getent group "$reader" >/dev/null
dropin_dir=/etc/systemd/system/mnebydns-dot.service.d
dropin="$dropin_dir/90-config-reader.conf"
install -d -m 755 "$dropin_dir"
if test -e "$dropin"; then
  test -f "$dropin" && test ! -L "$dropin"
  test "$(cat "$dropin")" = "[Service]
SupplementaryGroups=mnebydns-config-read"
else
  printf '[Service]\nSupplementaryGroups=mnebydns-config-read\n' > "$dropin"
  chmod 0644 "$dropin"
fi
chgrp "$reader" "$dns"
chmod 0640 "$dns"
test "$(stat -c '%a:%U:%G' "$dns")" = '640:root:mnebydns-config-read'
systemctl daemon-reload
test "$(systemctl show --value -p DynamicUser "$service")" = yes
systemctl cat "$service" | grep -Fxq "SupplementaryGroups=$reader"
test "$before" = "$(sha256sum "$dns" | cut -d' ' -f1)"
cmp -s "$checkpoint/dns.stable" "$dns"
systemctl reset-failed "$service"
systemctl restart "$service"
for i in $(seq 1 25); do
  if systemctl is-active --quiet "$service" &&
     ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'; then
    break
  fi
  sleep .4
done
systemctl is-active --quiet "$service"
ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'
systemctl is-active --quiet nginx
systemctl is-active --quiet mnebydns-googlepilot.service
cmp -s "$checkpoint/nginx.stable" "$nginx"
cmp -s "$checkpoint/proxy.stable" "$proxy"
test "$(cat "$pointer")" = "$checkpoint"
echo "MNEBYDNS_DOT_CONFIG_CONTENT_UNCHANGED=true"
echo "MNEBYDNS_DOT_COREFILE_PERMISSIONS_FIXED=true"
echo "MNEBYDNS_DOT_SERVICE_ACTIVE=true"
echo "MNEBYDNS_DOT_853_LISTENING=true"
