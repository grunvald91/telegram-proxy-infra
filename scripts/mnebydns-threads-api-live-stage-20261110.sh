#!/usr/bin/env bash
# Add only the Threads-shared i.instagram.com API while the existing 35m owner
# pilot is armed; preserve its original rollback and exact-file guards.
set -Eeuo pipefail
(( EUID==0 )) || exit 2
[[ $# == 2 && "$1" =~ ^[0-9]{9,13}$ ]] || exit 2
run_id="$1"; patch_script="$2"
[[ "$patch_script" =~ ^/tmp/mnebydns-threads-api-[0-9]{9,13}/mnebydns-threads-api-add-20261110.py$ ]] || exit 2
test -s "$patch_script"
base="/opt/mnebydns-threads-canary/$run_id"
live_dns="/opt/mnebydns-dot/Corefile"
live_nginx="/etc/nginx/nginx.conf"
name="mnebydns-threads-rollback-$run_id"
test -s "$base/dns.pilot" && test -s "$base/nginx.pilot"
test -s "$base/dns.before" && test -s "$base/nginx.before"
test -s "$base/rollback.sh"
systemctl is-active --quiet "$name.timer"
systemctl is-active --quiet nginx
systemctl is-active --quiet mnebydns-dot.service
systemctl is-active --quiet "mnebydns-meta-quic-de-$run_id-rollback.timer"
# Precondition: enough time for validation and cleanup before autonomous expiry.
deadline="$(date -u -d "$(systemctl show "$name.timer" -p NextElapseUSecRealtime --value)" +%s)"
now="$(date -u +%s)"
(( deadline-now>=480 && deadline-now<=2500 )) || {
  echo 'threads_shared_api_too_close_to_guarded_expiry=true'; exit 3;
}
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 20 9 || exit 3
cmp -s "$base/dns.pilot" "$live_dns"
cmp -s "$base/nginx.pilot" "$live_nginx"
test ! -e "$base/shared-api-stage-dns.original"
test ! -e "$base/shared-api-stage-nginx.original"
cp -p "$base/dns.pilot" "$base/shared-api-stage-dns.original"
cp -p "$base/nginx.pilot" "$base/shared-api-stage-nginx.original"
scratch="$(mktemp -d "$base/.shared-api.XXXXXXXX")"
python3 "$patch_script" self-test
python3 "$patch_script" render --dns "$base/dns.pilot" --nginx "$base/nginx.pilot" --out "$scratch"
chmod --reference="$live_dns" "$scratch/dns.api"
chown --reference="$live_dns" "$scratch/dns.api"
chmod --reference="$live_nginx" "$scratch/nginx.api"
chown --reference="$live_nginx" "$scratch/nginx.api"
nginx -t -c "$scratch/nginx.api" >/dev/null 2>&1
echo 'threads_shared_api_candidate_nginx_valid=true'

restore_on_error() {
  rc=$?
  trap - EXIT
  if (( rc!=0 )); then
    echo 'threads_shared_api_stage_failed_restoring_existing_pilot=true'
    for kind in dns nginx; do
      if [[ "$kind" == dns ]]; then live="$live_dns"; else live="$live_nginx"; fi
      cp -p "$base/shared-api-stage-$kind.original" "$live.restore-$run_id" &&
        mv -f "$live.restore-$run_id" "$live" || true
      cp -p "$base/shared-api-stage-$kind.original" "$base/$kind.pilot.restore-$run_id" &&
        mv -f "$base/$kind.pilot.restore-$run_id" "$base/$kind.pilot" || true
    done
    nginx -t >/dev/null 2>&1 && systemctl reload nginx || echo 'threads_shared_api_Nginx_restore_needs_attention=true'
    systemctl restart mnebydns-dot.service || echo 'threads_shared_api_DoT_restore_needs_attention=true'
    cmp -s "$base/dns.pilot" "$live_dns" || echo 'threads_shared_api_DNS_restore_not_confirmed=true'
    cmp -s "$base/nginx.pilot" "$live_nginx" || echo 'threads_shared_api_NGINX_restore_not_confirmed=true'
  fi
  rm -rf -- "$scratch"
  flock -u 9 || true
  exit "$rc"
}
trap restore_on_error EXIT
cp -p "$scratch/nginx.api" "$live_nginx.shared-$run_id"
mv -f "$live_nginx.shared-$run_id" "$live_nginx"
nginx -t >/dev/null 2>&1
systemctl reload nginx
systemctl is-active --quiet nginx
cp -p "$scratch/dns.api" "$live_dns.shared-$run_id"
mv -f "$live_dns.shared-$run_id" "$live_dns"
systemctl restart mnebydns-dot.service
systemctl is-active --quiet mnebydns-dot.service
# Persist new expected SHA-equivalent pilot files so the *original*
# autonomous rollback sees exact ownership and can restore .before.
cp -p "$scratch/nginx.api" "$base/nginx.pilot.shared-$run_id"
mv -f "$base/nginx.pilot.shared-$run_id" "$base/nginx.pilot"
cp -p "$scratch/dns.api" "$base/dns.pilot.shared-$run_id"
mv -f "$base/dns.pilot.shared-$run_id" "$base/dns.pilot"
cmp -s "$base/nginx.pilot" "$live_nginx"
cmp -s "$base/dns.pilot" "$live_dns"
systemctl is-active --quiet "$name.timer"
echo 'threads_shared_api_original_existing_rollback_remains_armed=true'
echo "threads_shared_api_original_deadline_UTC=$(date -u -d "@$deadline" +'%Y-%m-%d %H:%M:%S UTC')"
echo 'threads_shared_api_i_instagram_com_only_staged=true'
echo 'threads_shared_api_stable_other_routes_unmodified=true'
trap - EXIT
rm -rf -- "$scratch"
flock -u 9
