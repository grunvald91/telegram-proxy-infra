#!/usr/bin/env bash
# Stage a bounded Threads-only SmartDNS canary on DE. No other domains changed.
set -Eeuo pipefail
(( EUID==0 )) || exit 2
[[ $# == 2 && "$1" =~ ^/tmp/mnebydns-threads-canary-[0-9]{9,13}$ ]] || exit 2
work="$1"; deadline="$2"
id="$(basename "$work" | cut -d- -f5)"
[[ "$id" =~ ^[0-9]{9,13}$ ]] || exit 2
[[ "$deadline" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]][0-9]{2}:[0-9]{2}:[0-9]{2}[[:space:]]UTC$ ]] || exit 2
now="$(date -u +%s)"
expiry="$(date -u -d "$deadline" +%s)"
(( expiry-now>=300 && expiry-now<=1800 )) || exit 2
systemd-analyze calendar "$deadline" >/dev/null
base="/opt/mnebydns-threads-canary/$id"
name="mnebydns-threads-rollback-$id"
live_dns=/opt/mnebydns-dot/Corefile
live_nginx=/etc/nginx/nginx.conf
checkpoint="$(cat /opt/mnebydns-stable-checkpoints/current)"
[[ "$checkpoint" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 3
(cd "$checkpoint" && sha256sum -c stable-manifest.sha256 >/dev/null)
for pair in "dns:$live_dns" "nginx:$live_nginx" "proxy:/etc/mnebydns-googlepilot/nginx.conf"; do
  IFS=: read -r kind live <<< "$pair"
  cmp -s "$checkpoint/$kind.stable" "$live" || {
    echo 'threads_preflight_stable_baseline_mismatch=true';exit 3;
  }
done
for svc in nginx mnebydns-dot.service mnebydns-googlepilot.service xray.service; do
  systemctl is-active --quiet "$svc"
done
test ! -e "$base"
for kind in timer service; do
  test ! -e "/etc/systemd/system/$name.$kind"
done
test -s "$work/mnebydns-threads-only-render-20261110.py"
test -s "$work/mnebydns-threads-only-rollback-20261110.sh"
python3 "$work/mnebydns-threads-only-render-20261110.py" self-test
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 25 9 || exit 3
install -d -m 700 /opt/mnebydns-threads-canary "$base"
cp -p "$live_dns" "$base/dns.before"
cp -p "$live_nginx" "$base/nginx.before"
python3 "$work/mnebydns-threads-only-render-20261110.py" render \
  --base-dns "$base/dns.before" --base-nginx "$base/nginx.before" --out "$base"
for kind in nginx dns; do
  live="$live_dns"
  if [[ "$kind" == nginx ]]; then live="$live_nginx"; fi
  chmod --reference="$live" "$base/$kind.pilot"
  chown --reference="$live" "$base/$kind.pilot"
done
nginx -t -c "$base/nginx.pilot" >/dev/null 2>&1
install -m 700 "$work/mnebydns-threads-only-rollback-20261110.sh" "$base/rollback.sh"
cat > "$base/$name.service" <<UNIT
[Unit]
Description=Independently restore original Threads-only SmartDNS pilot configuration
[Service]
Type=oneshot
ExecStart=/bin/bash $base/rollback.sh $base
UNIT
cat > "$base/$name.timer" <<UNIT
[Unit]
Description=Independent persistent expiry for temporary Threads-only SmartDNS
[Timer]
OnCalendar=$deadline
Persistent=true
AccuracySec=1s
Unit=$name.service
[Install]
WantedBy=timers.target
UNIT
for kind in service timer; do
  install -m 644 "$base/$name.$kind" "/etc/systemd/system/$name.$kind"
done
systemctl daemon-reload
systemctl enable --now "$name.timer" >/dev/null
systemctl is-active --quiet "$name.timer"
abort(){
  rc=$?
  trap - EXIT
  flock -u 9 || true
  bash "$base/rollback.sh" "$base" || echo 'threads_stage_rollback_requires_attention=true'
  exit "$rc"
}
trap abort EXIT
# Always route public SNI before the new DNS result advertises the ingress.
cp -p "$base/nginx.pilot" "$live_nginx.new-$id"
mv -f "$live_nginx.new-$id" "$live_nginx"
nginx -t >/dev/null 2>&1
systemctl reload nginx
systemctl is-active --quiet nginx
cmp -s "$base/nginx.pilot" "$live_nginx"
cp -p "$base/dns.pilot" "$live_dns.new-$id"
mv -f "$live_dns.new-$id" "$live_dns"
systemctl restart mnebydns-dot.service
ready=false
for _ in $(seq 1 50); do
  if systemctl is-active --quiet mnebydns-dot.service &&
     ss -H -ltn 'sport = :853' | grep -Fq '89.125.90.101:853'; then
    ready=true;break
  fi
  sleep .2
done
test "$ready" = true
cmp -s "$base/dns.pilot" "$live_dns"
systemctl is-active --quiet "$name.timer"
echo 'threads_canary_de_nginx_active=true'
echo 'threads_canary_de_dot_active=true'
echo 'threads_canary_stable_proxy_and_vpn_unmodified=true'
echo "threads_canary_auto_rollback_UTC=$deadline"
trap - EXIT
flock -u 9
