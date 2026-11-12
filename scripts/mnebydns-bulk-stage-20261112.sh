#!/usr/bin/env bash
# 1-shot mass exact-host canary, with the existing independent owner rollback timer.
# No DB mutations; the runner confirms only after full live public-edge verification.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 2 ]] || exit 2
work="$1"; id="$2"
[[ "$id" =~ ^[1-9][0-9]{8,12}$ ]] || exit 2
[[ "$work" == "/tmp/mnebydns-owner-domain-$id" ]] || exit 2
[[ ! -L "$work" && -d "$work" ]] || exit 2
dns=/opt/mnebydns-dot/Corefile
nginx=/etc/nginx/nginx.conf
proxy=/etc/mnebydns-googlepilot/nginx.conf
base="/opt/mnebydns-owner-domain/$id"
name="mnebydns-owner-rollback-$id"
for file in manifest.tsv expected.json dns.pilot nginx.pilot \
    mnebydns-owner-domain-render-20261110.py \
    mnebydns-bulk-remote-verify-20261112.py \
    mnebydns-owner-domain-rollback-20261110.sh \
    mnebydns-owner-domain-confirm-20261110.sh \
    mnebydns-dot-config-change-20261111.sh; do
  [[ -f "$work/$file" && ! -L "$work/$file" ]] || exit 3
done
checkpoint="$(cat /opt/mnebydns-stable-checkpoints/current)"
[[ "$checkpoint" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 3
(cd "$checkpoint" && sha256sum -c stable-manifest.sha256 >/dev/null)
for pair in "dns:$dns" "nginx:$nginx" "proxy:$proxy"; do
  IFS=: read -r kind file <<< "$pair"
  cmp -s "$checkpoint/$kind.stable" "$file" || exit 3
done
for svc in nginx mnebydns-dot.service mnebydns-googlepilot.service xray.service; do
  systemctl is-active --quiet "$svc" || exit 3
done
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 45 9 || exit 3
checkpoint="$(cat /opt/mnebydns-stable-checkpoints/current)"
[[ "$checkpoint" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 3
(cd "$checkpoint" && sha256sum -c stable-manifest.sha256 >/dev/null)
cmp -s "$checkpoint/dns.stable" "$dns"
cmp -s "$checkpoint/nginx.stable" "$nginx"
cmp -s "$checkpoint/proxy.stable" "$proxy"
test ! -e "$base"
for kind in timer service; do test ! -e "/etc/systemd/system/$name.$kind"; done
install -d -m 700 /opt/mnebydns-owner-domain "$base"
cp -p "$dns" "$base/dns.before"
cp -p "$nginx" "$base/nginx.before"
cut -f1 "$work/manifest.tsv" | head -n1 > "$base/domain"
printf "%s\n" bulk > "$base/mode"
cp -p "$work/dns.pilot" "$base/dns.pilot"
cp -p "$work/nginx.pilot" "$base/nginx.pilot"
chmod --reference="$dns" "$base/dns.pilot"
chmod --reference="$nginx" "$base/nginx.pilot"
chown --reference="$dns" "$base/dns.pilot"
chown --reference="$nginx" "$base/nginx.pilot"
python3 "$work/mnebydns-bulk-remote-verify-20261112.py" "$work" "$base"
nginx -t -c "$base/nginx.pilot" >/dev/null 2>&1
install -m 700 "$work/mnebydns-owner-domain-rollback-20261110.sh" "$base/rollback.sh"
install -m 700 "$work/mnebydns-dot-config-change-20261111.sh" "$base/reload.sh"
install -m 700 "$work/mnebydns-owner-domain-confirm-20261110.sh" "$base/confirm.sh"
deadline="$(date -u -d '+60 minutes' '+%Y-%m-%d %H:%M:%S UTC')"
systemd-analyze calendar "$deadline" >/dev/null
cat > "$base/$name.service" <<UNIT
[Unit]
Description=Automatic bulk DNS pilot rollback $id
[Service]
Type=oneshot
ExecStart=/bin/bash $base/rollback.sh $base
UNIT
cat > "$base/$name.timer" <<UNIT
[Unit]
Description=Independent bulk DNS watchdog $id
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
  status=$?
  trap - EXIT
  flock -u 9 || true
  bash "$base/rollback.sh" "$base" || echo 'MNEBYDNS_BULK_ABORT_ROLLBACK_UNVERIFIED=true'
  exit "$status"
}
trap abort EXIT
cp -p "$base/nginx.pilot" "$nginx.owner-stage-$id"
mv -f "$nginx.owner-stage-$id" "$nginx"
nginx -t >/dev/null 2>&1
systemctl reload nginx
systemctl is-active --quiet nginx
cmp -s "$base/nginx.pilot" "$nginx"
cp -p "$base/dns.pilot" "$dns.owner-stage-$id"
mv -f "$dns.owner-stage-$id" "$dns"
bash "$base/reload.sh" "$dns"
for attempt in $(seq 1 50); do
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
echo "MNEBYDNS_BULK_CANARY_LIVE=$id"
echo "MNEBYDNS_BULK_CANARY_EXPIRES=$deadline"
trap - EXIT
flock -u 9
