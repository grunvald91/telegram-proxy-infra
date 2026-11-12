#!/usr/bin/env bash
# Single reversible switch of all validated exact-host SmartDNS routes.
# Reuses the existing independent owner-domain 60-minute rollback service.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 3 ]] || exit 2
work="$1"; id="$2"; deadline="$3"
[[ "$id" =~ ^[1-9][0-9]{8,12}$ ]] || exit 2
[[ "$work" == "/tmp/mnebydns-mass-$id" ]] || exit 2
[[ "$deadline" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]][0-9]{2}:[0-9]{2}:[0-9]{2}[[:space:]]UTC$ ]] || exit 2
expiry="$(date -u -d "$deadline" +%s)"
now="$(date -u +%s)"
(( expiry-now >= 900 && expiry-now <= 3660 )) || exit 2
systemd-analyze calendar "$deadline" >/dev/null
base="/opt/mnebydns-owner-domain/$id"
name="mnebydns-owner-rollback-$id"
dns=/opt/mnebydns-dot/Corefile
nginx=/etc/nginx/nginx.conf
proxy=/etc/mnebydns-googlepilot/nginx.conf
stable_pointer=/opt/mnebydns-stable-checkpoints/current
for file in dns.before nginx.before dns.pilot nginx.pilot checksums.sha256 plan.json; do
  [[ -f "$work/$file" && ! -L "$work/$file" ]] || exit 3
done
for file in rollback.sh confirm.sh reload.sh; do
  [[ -s "$work/$file" && ! -L "$work/$file" ]] || exit 3
done
(cd "$work" && sha256sum -c checksums.sha256 >/dev/null)
checkpoint="$(cat "$stable_pointer")"
[[ "$checkpoint" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 3
(cd "$checkpoint" && sha256sum -c stable-manifest.sha256 >/dev/null)
cmp -s "$checkpoint/dns.stable" "$dns"
cmp -s "$checkpoint/nginx.stable" "$nginx"
cmp -s "$checkpoint/proxy.stable" "$proxy"
cmp -s "$work/dns.before" "$dns"
cmp -s "$work/nginx.before" "$nginx"
test -s "$work/dns.pilot" && test -s "$work/nginx.pilot"
! cmp -s "$work/dns.before" "$work/dns.pilot"
! cmp -s "$work/nginx.before" "$work/nginx.pilot"
for service in nginx mnebydns-dot.service mnebydns-googlepilot.service xray.service; do
  systemctl is-active --quiet "$service" || exit 3
done
nginx -t -c "$work/nginx.pilot" >/dev/null 2>&1

exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 45 9 || exit 3
# All state checks must be repeated under the shared public-routing lock.
cmp -s "$checkpoint/dns.stable" "$dns"
cmp -s "$checkpoint/nginx.stable" "$nginx"
cmp -s "$checkpoint/proxy.stable" "$proxy"
test "$(cat "$stable_pointer")" = "$checkpoint"
test ! -e "$base"
for suffix in service timer; do test ! -e "/etc/systemd/system/$name.$suffix"; done
install -d -m 700 /opt/mnebydns-owner-domain "$base"
for item in dns.before nginx.before dns.pilot nginx.pilot; do
  cp -p "$work/$item" "$base/$item"
done
printf 'bulk-108-research\n' > "$base/domain"
printf 'bulk-add\n' > "$base/mode"
for kind in dns nginx; do
  if [[ "$kind" == dns ]]; then live="$dns"; else live="$nginx"; fi
  chmod --reference="$live" "$base/$kind.pilot"
  chown --reference="$live" "$base/$kind.pilot"
done
install -m 700 "$work/rollback.sh" "$base/rollback.sh"
install -m 700 "$work/confirm.sh" "$base/confirm.sh"
install -m 700 "$work/reload.sh" "$base/reload.sh"
cat > "$base/$name.service" <<UNIT
[Unit]
Description=Restore unconfirmed MNEBYDNS mass rollout $id
[Service]
Type=oneshot
ExecStart=/bin/bash $base/rollback.sh $base
UNIT
cat > "$base/$name.timer" <<UNIT
[Unit]
Description=MNEBYDNS bulk independent 60 minute rollback $id
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
abort() {
  code=$?
  trap - EXIT
  flock -u 9 || true
  if ! bash "$base/rollback.sh" "$base"; then
    echo 'MASS_BULK_ROLLBACK_UNVERIFIED=true' >&2
  fi
  exit "$code"
}
trap abort EXIT
cp -p "$base/nginx.pilot" "$nginx.mass-stage-$id"
mv -f "$nginx.mass-stage-$id" "$nginx"
nginx -t >/dev/null 2>&1
systemctl reload nginx
systemctl is-active --quiet nginx
cmp -s "$base/nginx.pilot" "$nginx"
cp -p "$base/dns.pilot" "$dns.mass-stage-$id"
mv -f "$dns.mass-stage-$id" "$dns"
bash "$base/reload.sh" "$dns"
for attempt in $(seq 1 60); do
  if systemctl is-active --quiet mnebydns-dot.service &&
     ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'; then break; fi
  sleep .2
done
systemctl is-active --quiet mnebydns-dot.service
systemctl is-active --quiet nginx
systemctl is-active --quiet "$name.timer"
ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'
cmp -s "$base/dns.pilot" "$dns"
cmp -s "$base/nginx.pilot" "$nginx"
echo "MASS_BULK_STAGE_ACTIVE=true"
echo "MASS_BULK_EXPIRY_UTC=$deadline"
trap - EXIT
flock -u 9
