#!/usr/bin/env bash
# Temporary DE public TCP443 Meta SNI map; exact-file rollback + independent timer.
set -Eeuo pipefail
(( EUID==0 )) || exit 2
[[ $# == 2 && "$1" =~ ^/tmp/mnebydns-meta-de-public-[0-9]{9,13}$ ]] || exit 2
work="$1"; deadline="$2"; id="$(basename "$work" | sed 's/^mnebydns-meta-de-public-//')"
[[ "$deadline" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]][0-9]{2}:[0-9]{2}:[0-9]{2}[[:space:]]UTC$ ]] || exit 2
now="$(date -u +%s)"; expiry="$(date -u -d "$deadline" +%s)"
(( expiry-now >= 180 && expiry-now <= 1800 )) || exit 2
systemd-analyze calendar "$deadline" >/dev/null
live=/etc/nginx/nginx.conf
base="/opt/mnebydns-meta-de-public-backups/$id"
name="mnebydns-meta-de-public-watchdog-$id"
test -s "$work/mnebydns-meta-de-public-rollback.sh"
checkpoint="$(cat /opt/mnebydns-stable-checkpoints/current)"
[[ "$checkpoint" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 3
(cd "$checkpoint" && sha256sum -c stable-manifest.sha256 >/dev/null)
for pair in "nginx.stable:$live" "dns.stable:/opt/mnebydns-dot/Corefile" "proxy.stable:/etc/mnebydns-googlepilot/nginx.conf"; do
  file="$(cut -d: -f1 <<< "$pair")"
  dest="$(cut -d: -f2- <<< "$pair")"
  cmp -s "$checkpoint/$file" "$dest" || { echo 'de_public_meta_baseline_drift=true'; exit 3; }
done
for service in nginx mnebydns-dot.service mnebydns-googlepilot.service xray.service; do
  systemctl is-active --quiet "$service"
done
systemctl is-active --quiet "mnebydns-meta-pilot-$id.service"
ss -H -ltn 'sport = :19443' | grep -Fq '10.66.77.1:19443'
test ! -e "$base"
for kind in service timer; do test ! -e "/etc/systemd/system/$name.$kind"; done
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 20 9 || exit 3
install -d -m 700 /opt/mnebydns-meta-de-public-backups "$base"
cp -p "$live" "$base/before"
install -m 700 "$work/mnebydns-meta-de-public-rollback.sh" "$base/rollback.sh"
python3 - "$base/before" "$base/pilot" <<'PY'
import pathlib,re,sys
original=pathlib.Path(sys.argv[1]).read_text()
anchor='map $ssl_preread_server_name $direct_mtproxy_backend {'
if original.count(anchor)!=1:raise SystemExit('unexpected SNI map layout')
if any(tag in original.lower() for tag in ('i.instagram.com','threads.com','graph.instagram.com')):
    raise SystemExit('existing Meta map already present')
zones=('instagram.com','cdninstagram.com','instagr.am','ig.me',
 'igsonar.com','threads.com','threads.net','facebook.com',
 'facebook.net','fbcdn.net','fbsbx.com','fb.com',
 'meta.com','meta.ai','instagramstatic.com','igcdn.com','fbcdn.com')
pattern=r'~*^(?:[a-z0-9-]+\.)*(?:'+'|'.join(re.escape(z) for z in zones)+r')$'
insert=('\n        instagramstatic-a.akamaihd.net 10.66.77.1:19443;\n'
        '        '+pattern+' 10.66.77.1:19443;\n')
pos=original.index(anchor)+len(anchor)
patched=original[:pos]+insert+original[pos:]
if patched.replace(insert,'',1)!=original or patched.count('10.66.77.1:19443')!=2:
    raise SystemExit('non-additive map patch')
if patched.count('default ')!=original.count('default '):
    raise SystemExit('default backend drift')
pathlib.Path(sys.argv[2]).write_text(patched)
print('de_public_meta_only_sni_additive_patch=true',flush=True)
PY
chown --reference="$live" "$base/pilot"
chmod --reference="$live" "$base/pilot"
nginx -t -c "$base/pilot" >/dev/null 2>&1
cat > "$base/$name.service" <<UNIT
[Unit]
Description=Restore original DE public 443 config after Meta canary
[Service]
Type=oneshot
ExecStart=/bin/bash $base/rollback.sh $base
UNIT
cat > "$base/$name.timer" <<UNIT
[Unit]
Description=Independent timer to revert temporary DE Meta 443 SNI
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
  bash "$base/rollback.sh" "$base" || echo 'de_public_meta_rollback_requires_attention=true'
  exit "$rc"
}
trap abort EXIT
cp -p "$base/pilot" "$live"
nginx -t >/dev/null 2>&1
systemctl reload nginx
systemctl is-active --quiet nginx
cmp -s "$base/pilot" "$live"
systemctl is-active --quiet "$name.timer"
echo 'de_public_meta_temporary_443_sni_route_active=true'
echo "de_public_meta_rollback_deadline_utc=$deadline"
echo 'de_public_other_SNI_route_text_byte_identical=true'
trap - EXIT
flock -u 9
