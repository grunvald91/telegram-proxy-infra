#!/usr/bin/env bash
# Preserve the successful DE ChatGPT route as stable, discard nonworking Meta.
# Run only against the active audited combined canary and only AFTER RU SNI rollback.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 2 && "$1" =~ ^/opt/mnebydns-combined-backups/[0-9]+$ && "$2" =~ ^/tmp/mnebydns-combined-de-[0-9]+$ ]] || exit 2
base="$1"; work="$2"; id="${base##*/}"
[[ "$work" == "/tmp/mnebydns-combined-de-$id" ]] || exit 2
root=/opt/mnebydns-stable-checkpoints
checkpoint="$(cat "$root/current")"
[[ "$checkpoint" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 2
[[ "$(cat "$base/checkpoint.ref")" == "$checkpoint" ]] || exit 3
(cd "$checkpoint" && sha256sum -c stable-manifest.sha256 >/dev/null)
(cd "$base" && sha256sum -c combined-manifest.sha256 >/dev/null)
watch="mnebydns-combined-de-watchdog-$id"
sidecar_unit="mnebydns-combined-meta-$id"
systemctl is-active --quiet "$watch.timer"
systemctl is-active --quiet "$sidecar_unit.service"
deadline="$(sed -n 's/^OnCalendar=//p' "$base/$watch.timer")"
remaining=$(( $(date -u -d "$deadline" +%s) - $(date -u +%s) ))
(( remaining >= 180 )) || { echo 'chatgpt_promotion_refuses_near_expired_canary=true'; exit 3; }
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 18 9 || exit 3
# All live files must still be EXACTLY the combined canary we own.
cmp -s "$base/nginx.pilot" /etc/nginx/nginx.conf
cmp -s "$base/dns.pilot" /opt/mnebydns-dot/Corefile
cmp -s "$base/proxy.pilot" /etc/mnebydns-googlepilot/nginx.conf
cmp -s "$base/proxy.meta" /etc/mnebydns-meta-pilot/nginx.conf
for kind in service timer; do
  cmp -s "$base/$watch.$kind" "/etc/systemd/system/$watch.$kind"
done
cmp -s "$base/$sidecar_unit.service" "/etc/systemd/system/$sidecar_unit.service"
for name in nginx mnebydns-dot.service mnebydns-googlepilot.service mnebydns-gemini.service xray.service; do
  systemctl is-active --quiet "$name"
done
out="/opt/mnebydns-chatgpt-promotions/$id"
new_checkpoint="$root/$id"
test ! -e "$out" && test ! -e "$new_checkpoint"
install -d -m 700 /opt/mnebydns-chatgpt-promotions
install -d -m 700 "$out"
python3 "$work/mnebydns-chatgpt-de-overlay.py" render "$checkpoint/nginx.stable" "$checkpoint/dns.stable" "$checkpoint/proxy.stable" "$out"
# Both public Nginx configs already contain ONLY the ChatGPT overlay.
cmp -s "$out/nginx.pilot" "$base/nginx.pilot"
cmp -s "$out/proxy.pilot" "$base/proxy.pilot"
test -s "$out/dns.pilot"
! cmp -s "$out/dns.pilot" "$base/dns.pilot"
! grep -Fq '188.120.254.223' "$out/dns.pilot"
for bad in instagram.com threads.com threads.net edge-mqtt.facebook.com; do
  ! grep -Fq "$bad" "$out/dns.pilot"
done
nginx -t >/dev/null
nginx -t -c /etc/mnebydns-googlepilot/nginx.conf >/dev/null
mkdir -m 700 "$new_checkpoint"
install -m 600 "$out/nginx.pilot" "$new_checkpoint/nginx.stable"
install -m 600 "$out/dns.pilot" "$new_checkpoint/dns.stable"
install -m 600 "$out/proxy.pilot" "$new_checkpoint/proxy.stable"
(cd "$new_checkpoint" && sha256sum nginx.stable dns.stable proxy.stable > stable-manifest.sha256)
(cd "$new_checkpoint" && sha256sum -c stable-manifest.sha256 >/dev/null)
# A separate independent safety timer survives workflow interruption and
# restores the original five-service checkpoint on a partial promotion.
safety="mnebydns-chatgpt-promotion-safety-$id"
cat > "$out/fallback.sh" <<'FALLBACK'
#!/usr/bin/env bash
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 3 ]] || exit 2
old="$1"; new="$2"; id="$3"
[[ "$old" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ && "$new" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ && "$id" =~ ^[0-9]+$ ]] || exit 2
root=/opt/mnebydns-stable-checkpoints
# A permanently promoted new checkpoint is never reverted by this safety job.
if [[ "$(cat "$root/current")" == "$new" ]]; then
  echo "chatgpt_promotion_committed_no_fallback=true"; exit 0
fi
[[ "$(cat "$root/current")" == "$old" ]] || exit 3
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 18 9 || exit 3
for kind in nginx dns proxy; do
  case "$kind" in
    nginx) live=/etc/nginx/nginx.conf ;;
    dns) live=/opt/mnebydns-dot/Corefile ;;
    proxy) live=/etc/mnebydns-googlepilot/nginx.conf ;;
  esac
  if cmp -s "$old/$kind.stable" "$live"; then continue; fi
  if [[ "$kind" == dns ]] && cmp -s "$new/dns.stable" "$live"; then
     install -m 644 "$old/dns.stable" "$live.restore-$id"
     mv -f "$live.restore-$id" "$live"
     systemctl restart mnebydns-dot.service
     continue
  fi
  echo "chatgpt_fallback_refuses_unowned_$kind=true"; exit 4
done
systemctl is-active --quiet mnebydns-dot.service
echo "chatgpt_fallback_five_baseline_restored=true"
FALLBACK
chmod 700 "$out/fallback.sh"
cat > "$out/$safety.service" <<UNIT
[Unit]
Description=Fail-safe for incomplete ChatGPT permanent promotion
[Service]
Type=oneshot
ExecStart=/bin/bash $out/fallback.sh $checkpoint $new_checkpoint $id
UNIT
safety_deadline="$(date -u -d '+5 minutes' +'%Y-%m-%d %H:%M:%S UTC')"
cat > "$out/$safety.timer" <<UNIT
[Unit]
Description=Restore stable five after incomplete ChatGPT promotion
[Timer]
OnCalendar=$safety_deadline
Persistent=true
AccuracySec=1s
Unit=$safety.service
[Install]
WantedBy=timers.target
UNIT
install -m 644 "$out/$safety.service" "/etc/systemd/system/$safety.service"
install -m 644 "$out/$safety.timer" "/etc/systemd/system/$safety.timer"
systemctl daemon-reload
systemctl enable --now "$safety.timer" >/dev/null
systemctl is-active --quiet "$safety.timer"
started_change=no
abort() {
  rc=$?
  trap - EXIT
  if [[ "$started_change" == yes ]]; then
    echo 'chatgpt_promotion_aborted_request_five_restore=true'
    flock -u 9 || true
    bash "$out/fallback.sh" "$checkpoint" "$new_checkpoint" "$id" || echo 'chatgpt_promotion_manual_attention=true'
  fi
  exit "$rc"
}
trap abort EXIT
# Change only DoT. The public nginx and existing German TLS proxy are
# already the exact ChatGPT-only versions and are not restarted.
install -m 644 "$new_checkpoint/dns.stable" "/opt/mnebydns-dot/Corefile.new-$id"
mv -f "/opt/mnebydns-dot/Corefile.new-$id" /opt/mnebydns-dot/Corefile
started_change=yes
systemctl restart mnebydns-dot.service
ready=no
for _ in $(seq 1 45); do
  if systemctl is-active --quiet mnebydns-dot.service &&
    ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'; then
    ready=yes; break
  fi
  sleep .25
done
[[ "$ready" == yes ]]
cmp -s "$new_checkpoint/dns.stable" /opt/mnebydns-dot/Corefile
# Check TLS-validated DoT on the server itself (not the blocked GH runner).
python3 - "$work/dot-probe.py" <<'PY'
import concurrent.futures,importlib.util,pathlib,socket,sys
spec=importlib.util.spec_from_file_location("dot",pathlib.Path(sys.argv[1]))
assert spec and spec.loader
dot=importlib.util.module_from_spec(spec);spec.loader.exec_module(dot)
de="89.125.90.101";ru="188.120.254.223"
cases=[("chatgpt.com",de),("android.chat.openai.com",de),
       ("ws.chatgpt.com",de),("api.openai.com",de),
       ("files.oaiusercontent.com",de),("cdn.oaistatic.com",de),
       ("gemini.google.com",de),("claude.ai",de),
       ("x.com",de),("grok.com",de),("www.tiktok.com",de)]
def probe(item):
  name,expected=item
  try:
    code,_,rr=dot.query(name,1,de,853,"dns.mnebyvpn.site",None)
    ips=[socket.inet_ntoa(data) for kind,ttl,data in rr if kind==1]
    return name,code==0 and ips==[expected],ips
  except Exception as e: return name,False,[type(e).__name__]
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool: rows=list(pool.map(probe,cases))
for name,ok,ips in rows:print("promoted_DoT_"+name+"="+str(ok).lower()+" ips="+",".join(ips),flush=True)
if not all(ok for _,ok,_ in rows):raise SystemExit("11 core DoT routes failed")
for name in ("instagram.com","threads.com","graph.threads.net","api.telegram.org","t.me"):
  try:
    code,_,rr=dot.query(name,1,de,853,"dns.mnebyvpn.site",None)
    ips=[socket.inet_ntoa(data) for kind,ttl,data in rr if kind==1]
    if de in ips or ru in ips:raise SystemExit("unexpected synthetic route for "+name)
    print("promoted_no_Meta_Telegram_rewrite_"+name+"=true",flush=True)
  except (OSError,TimeoutError) as exc:
    print("upstream_external_DNS_error_"+name+"="+type(exc).__name__,flush=True)
print("chatgpt_plus_five_DNS_11_of_11_pass=true",flush=True)
PY
for kind in nginx dns proxy; do
  case "$kind" in
    nginx) live=/etc/nginx/nginx.conf ;;
    dns) live=/opt/mnebydns-dot/Corefile ;;
    proxy) live=/etc/mnebydns-googlepilot/nginx.conf ;;
  esac
  cmp -s "$new_checkpoint/$kind.stable" "$live"
done
for name in nginx mnebydns-dot.service mnebydns-googlepilot.service mnebydns-gemini.service xray.service; do
  systemctl is-active --quiet "$name"
done
# Commit stable checkpoint. The safety job knows to do nothing if this pointer
# was successfully committed.
printf '%s\n' "$new_checkpoint" > "$root/current.new-$id"
mv -f "$root/current.new-$id" "$root/current"
[[ "$(cat "$root/current")" == "$new_checkpoint" ]]
(cd "$new_checkpoint" && sha256sum -c stable-manifest.sha256 >/dev/null)
# Retire only pilot-specific Meta services and both old/short-term timers.
systemctl disable --now "$watch.timer" >/dev/null
systemctl stop "$sidecar_unit.service"
systemctl is-active --quiet "$sidecar_unit.service" && exit 5
systemctl disable "$sidecar_unit.service" >/dev/null 2>&1 || true
systemctl disable --now "$safety.timer" >/dev/null
for f in "/etc/systemd/system/$watch.service" "/etc/systemd/system/$watch.timer" \
         "/etc/systemd/system/$sidecar_unit.service" \
         "/etc/systemd/system/$safety.service" "/etc/systemd/system/$safety.timer"; do
  rm -f -- "$f"
done
cmp -s "$base/proxy.meta" /etc/mnebydns-meta-pilot/nginx.conf
rm -f -- /etc/mnebydns-meta-pilot/nginx.conf
rmdir /etc/mnebydns-meta-pilot
systemctl daemon-reload
echo "chatgpt_PERMANENT_STABLE_CHECKPOINT=$new_checkpoint"
echo "chatgpt_Claude_Google_existing_DE_443_route_PRESERVED=true"
echo "instagram_threads_Meta_sidecar_and_watchdogs_REMOVED=true"
echo "existing_five_services_and_DoT_preserved=true"
trap - EXIT
flock -u 9
