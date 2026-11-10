#!/usr/bin/env bash
# Guarded removal of an exact ACTIVE domain only; kept reversible until checkpoint.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 4 ]] || exit 2
work="$1";id="$2";domain="$3";deadline="$4"
[[ "$work" =~ ^/tmp/mnebydns-owner-domain-[0-9]{9,13}$ ]] || exit 2
[[ "$id" =~ ^[0-9]{9,13}$ && "$work" == "/tmp/mnebydns-owner-domain-$id" ]] || exit 2
[[ "$domain" =~ ^[a-z0-9.-]{4,253}$ ]] || exit 2
[[ "$deadline" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]][0-9]{2}:[0-9]{2}:[0-9]{2}[[:space:]]UTC$ ]] || exit 2
now="$(date -u +%s)";expiry="$(date -u -d "$deadline" +%s)"
(( expiry-now>=300 && expiry-now<=1200 )) || exit 2
systemd-analyze calendar "$deadline" >/dev/null

base="/opt/mnebydns-owner-domain/$id"
name="mnebydns-owner-rollback-$id"
dns=/opt/mnebydns-dot/Corefile
nginx=/etc/nginx/nginx.conf
checkpoint="$(cat /opt/mnebydns-stable-checkpoints/current)"
[[ "$checkpoint" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 3
(cd "$checkpoint" && sha256sum -c stable-manifest.sha256 >/dev/null)
for pair in "dns:$dns" "nginx:$nginx" "proxy:/etc/mnebydns-googlepilot/nginx.conf"; do
  IFS=: read -r kind live <<< "$pair"
  cmp -s "$checkpoint/$kind.stable" "$live" || {
    echo 'owner_domain_remove_stable_checkpoint_mismatch=true'
    exit 3
  }
done
for service in nginx mnebydns-dot.service mnebydns-googlepilot.service xray.service; do
  systemctl is-active --quiet "$service"
done
test -s "$work/mnebydns-owner-domain-render-20261110.py"
test -s "$work/mnebydns-owner-domain-rollback-20261110.sh"
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 30 9 || exit 3
test ! -e "$base"
for suffix in service timer; do test ! -e "/etc/systemd/system/$name.$suffix"; done
install -d -m 700 /opt/mnebydns-owner-domain "$base"
cp -p "$dns" "$base/dns.before"
cp -p "$nginx" "$base/nginx.before"
printf '%s\n' "$domain" > "$base/domain"
printf '%s\n' remove > "$base/mode"
python3 "$work/mnebydns-owner-domain-render-20261110.py" render-remove \
 --domain "$domain" --core "$base/dns.before" --nginx "$base/nginx.before" --out "$base"
for kind in dns nginx; do
  if [[ "$kind" == dns ]]; then file="$dns"; else file="$nginx"; fi
  chmod --reference="$file" "$base/$kind.pilot"
  chown --reference="$file" "$base/$kind.pilot"
done
nginx -t -c "$base/nginx.pilot" >/dev/null 2>&1
install -m 700 "$work/mnebydns-owner-domain-rollback-20261110.sh" "$base/rollback.sh"
install -m 700 "$work/mnebydns-owner-domain-confirm-20261110.sh" "$base/confirm.sh"
cat > "$base/$name.service" <<UNIT
[Unit]
Description=Restore original owner-domain before rejected route removal
[Service]
Type=oneshot
ExecStart=/bin/bash $base/rollback.sh $base
UNIT
cat > "$base/$name.timer" <<UNIT
[Unit]
Description=Guarded owner domain removal deadline $id
[Timer]
OnCalendar=$deadline
Persistent=true
AccuracySec=1s
Unit=$name.service
[Install]
WantedBy=timers.target
UNIT
for suffix in service timer; do
  install -m 644 "$base/$name.$suffix" "/etc/systemd/system/$name.$suffix"
done
systemctl daemon-reload
systemctl enable --now "$name.timer" >/dev/null
systemctl is-active --quiet "$name.timer"
abort(){
  code=$?
  trap - EXIT
  flock -u 9 || true
  bash "$base/rollback.sh" "$base" || echo 'owner_domain_remove_abort_rollback_unverified=true'
  exit "$code"
}
trap abort EXIT
cp -p "$base/nginx.pilot" "$nginx.owner-remove-$id"
mv -f "$nginx.owner-remove-$id" "$nginx"
nginx -t >/dev/null 2>&1
systemctl reload nginx
cmp -s "$base/nginx.pilot" "$nginx"
cp -p "$base/dns.pilot" "$dns.owner-remove-$id"
mv -f "$dns.owner-remove-$id" "$dns"
systemctl restart mnebydns-dot.service
# systemctl active may precede bind(:853); don't test DNS/TLS during that gap.
for attempt in $(seq 1 60); do
  if systemctl is-active --quiet mnebydns-dot.service &&
     ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'; then
    break
  fi
  sleep .2
done
systemctl is-active --quiet mnebydns-dot.service
ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'
cmp -s "$base/dns.pilot" "$dns"
systemctl is-active --quiet "$name.timer"
echo 'owner_domain_removal_canary_active=true'
echo "owner_domain_removal_guard_deadline_UTC=$deadline"
trap - EXIT
flock -u 9
