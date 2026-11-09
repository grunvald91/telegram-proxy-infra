#!/usr/bin/env bash
# Temporary RU:443 Meta + ChatGPT SNI passthrough into pre-existing private WireGuard.
# No new public listener, no modification of unrelated service backends.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ ( $# == 1 || $# == 2 ) && "$1" =~ ^/tmp/mnebydns-meta-ru-[0-9]+$ ]] || exit 2
work="$1"
runid="${work##*-}"
[[ "$runid" =~ ^[0-9]+$ ]] || exit 2
base="/opt/mnebydns-meta-ru-backups/$runid"
live=/etc/nginx/streams.d/01-mtproxy-443.conf
name="mnebydns-meta-ru-watchdog-$runid"
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -n 9 || { echo "ru_route_lock_unavailable=true"; exit 2; }
test -s "$work/mnebydns-meta-ru-rollback.sh"
test -f "$live" && test ! -L "$live"
test ! -e "$base"
systemctl is-active --quiet nginx
nginx -t >/dev/null 2>&1
ip -4 route get 10.66.77.1 | grep -Fq 'tg-relay'
mkdir -p /opt/mnebydns-meta-ru-backups
install -d -m 700 "$base"
cp -p "$live" "$base/before"
install -m 700 "$work/mnebydns-meta-ru-rollback.sh" "$base/rollback.sh"
python3 - "$base/before" "$base/pilot" <<'PY'
import pathlib,re,sys
src=pathlib.Path(sys.argv[1]).read_text()
if src.count('map $ssl_preread_server_name $stream_443_backend {')!=1:
    raise ValueError('RU existing SNI map differs from verified layout')
pat=re.compile(r'(map\s+\$ssl_preread_server_name\s+\$stream_443_backend\s*\{)([^{}]*)(\})',re.S)
matches=list(pat.finditer(src))
if len(matches)!=1:raise ValueError('Unexpected RU stream SNI map count')
body=matches[0].group(2)
if 'default 10.66.77.1:443;' not in body:
    raise ValueError('Telegram default stream backend changed')
if '19443' in src or 'instagram.com' in body:
    raise ValueError('Meta pilot or conflicting route already exists')
zones=(
 'instagram.com','cdninstagram.com','instagr.am','ig.me',
 'igsonar.com','threads.com','threads.net','facebook.com',
 'facebook.net','fbcdn.net','fbsbx.com','fb.com',
 'meta.com','meta.ai','instagramstatic.com','igcdn.com','fbcdn.com',
)
chatgpt_zones=(
 'chatgpt.com','openai.com','oaistatic.com','oaiusercontent.com','oaistatsig.com',
)
# Third-party integrations are exact names, never unbounded proxy zones.
chatgpt_exact=(
 'cdn.openaimerge.com','cdn.workos.com','challenges.cloudflare.com',
 'forwarder.workos.com','frontend-apps-multi-region.workos.com',
 'images.workoscdn.com','setup.workos.com','workos.imgix.net',
 'js.intercomcdn.com','js.stripe.com','o207216.ingest.sentry.io',
 'o33249.ingest.sentry.io','rum.browser-intake-datadoghq.com',
 'ct.sendgrid.net','humb.apple.com',
)
for host in chatgpt_zones+chatgpt_exact:
    if host in body:
        raise ValueError('ChatGPT SNI already owned by an existing RU route')
pattern='~*^(?:[a-z0-9-]+\.)*(?:'+'|'.join(re.escape(z) for z in zones)+')$'
chatgpt_pattern='~*^(?:[a-z0-9-]+\.)*(?:'+'|'.join(re.escape(z) for z in chatgpt_zones)+')$'
insert=(
    '\n    instagramstatic-a.akamaihd.net 10.66.77.1:19443;\n'
    + ''.join('    '+host+' 10.66.77.1:19443;\n' for host in chatgpt_exact)
    + '    '+pattern+' 10.66.77.1:19443;\n'
    + '    '+chatgpt_pattern+' 10.66.77.1:19443;\n'
)
m=matches[0]
out=src[:m.end(1)]+insert+src[m.end(1):]
assert out.replace(insert,'',1)==src
pathlib.Path(sys.argv[2]).write_text(out)
print('ru_exact_sni_map_meta_plus_chatgpt=true',flush=True)
print('ru_sni_existing_default_and_other_routes_preserved=true',flush=True)
PY
chown --reference="$live" "$base/pilot"
chmod --reference="$live" "$base/pilot"
watch_service="/etc/systemd/system/$name.service"
watch_timer="/etc/systemd/system/$name.timer"
test ! -e "$watch_service" && test ! -e "$watch_timer"
if [[ $# == 2 ]]; then
  deadline="$2"
  [[ "$deadline" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]][0-9]{2}:[0-9]{2}:[0-9]{2}[[:space:]]UTC$ ]] || exit 2
  now="$(date -u +%s)"
  expiry="$(date -u -d "$deadline" +%s)"
  (( expiry - now >= 120 && expiry - now <= 3600 )) || {
    echo "ru_shared_deadline_out_of_bounds=true"; exit 2;
  }
else
  deadline="$(date -u -d '+35 minutes' +'%Y-%m-%d %H:%M:%S UTC')"
fi
systemd-analyze calendar "$deadline" >/dev/null
cat > "$base/$name.service" <<UNIT
[Unit]
Description=Revert owner-only RU Meta DNS WireGuard SNI experiment
[Service]
Type=oneshot
ExecStart=/bin/bash $base/rollback.sh $base
UNIT
cat > "$base/$name.timer" <<UNIT
[Unit]
Description=Persistent timer to restore original RU stream SNI
[Timer]
OnCalendar=$deadline
Persistent=true
AccuracySec=1s
Unit=$name.service
[Install]
WantedBy=timers.target
UNIT
install -m 644 "$base/$name.service" "$watch_service"
install -m 644 "$base/$name.timer" "$watch_timer"
systemctl daemon-reload
systemctl enable --now "$name.timer" >/dev/null
systemctl is-active --quiet "$name.timer"
abort(){
  code=$?
  trap - EXIT
  flock -u 9 || true
  bash "$base/rollback.sh" "$base" || echo "ru_automatic_rollback_not_confirmed=true"
  exit "$code"
}
trap abort EXIT
cp -p "$base/pilot" "$live"
nginx -t >/dev/null 2>&1
systemctl reload nginx
systemctl is-active --quiet nginx
cmp -s "$base/pilot" "$live"
echo "ru_meta_sni_to_private_wg_19443_active=true"
echo "ru_meta_rollback_UTC=$deadline"
echo "ru_meta_rollback_persistent_after_restart=true"
echo "ru_existing_443_listener_unchanged=true"
trap - EXIT
flock -u 9
