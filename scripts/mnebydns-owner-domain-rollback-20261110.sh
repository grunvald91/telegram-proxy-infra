#!/usr/bin/env bash
# Independent owner-domain canary rollback. Refuses to overwrite unrelated edits.
set -Eeuo pipefail
owner_atomic_swap() {
  python3 - "$1" "$2" "$3" <<'PYCODE'
import os,sys
from pathlib import Path
sys.path.insert(0,"/opt/mnebydns-maintenance")
from mnebydns_nov8_restore_safety import capture, atomic_replace, digest
live,expected,candidate=map(Path,sys.argv[1:])
if live not in (Path("/opt/mnebydns-dot/Corefile"),Path("/etc/nginx/nginx.conf")):
    raise SystemExit("unsafe owner route target")
for p in (expected,candidate):
    if p.is_symlink() or not p.is_file():raise SystemExit("invalid owner checkpoint")
state=capture(live)
if state.sha256!=digest(expected.read_bytes()):
    raise SystemExit("concurrent owner-domain config change")
atomic_replace(live,state,candidate.read_bytes())
PYCODE
}
(( EUID == 0 )) || exit 2
[[ $# == 1 && "$1" =~ ^/opt/mnebydns-owner-domain/[0-9]{9,13}$ ]] || exit 2
base="$1"
test -s "$base/dns.before"
test -s "$base/nginx.before"
test -s "$base/dns.pilot"
test -s "$base/nginx.pilot"
id="$(basename "$base")"
name="mnebydns-owner-rollback-$id"
live_dns=/opt/mnebydns-dot/Corefile
live_nginx=/etc/nginx/nginx.conf
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 55 9 || { echo 'owner_domain_rollback_lock_unavailable=true'; exit 3; }
# After a successful owner-confirmed promotion, the timer remains armed
# until expiry but MUST NOT revert a later stable checkpoint.
confirmed=false
if test -f "$base/confirmed"; then
  confirmed=true
else
  checkpoint="$(cat /opt/mnebydns-stable-checkpoints/current 2>/dev/null || true)"
  # A committed add OR removal may lose its 'confirmed' sentinel in the
  # tiny crash window after checkpoint promotion. Equality of the complete
  # checkpoint and live pilot is stronger proof than presence/absence of
  # a hostname marker, which is absent after a successful removal.
  if [[ "$checkpoint" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] &&
     (cd "$checkpoint" && sha256sum -c stable-manifest.sha256 >/dev/null) &&
     cmp -s "$checkpoint/dns.stable" "$base/dns.pilot" &&
     cmp -s "$checkpoint/nginx.stable" "$base/nginx.pilot" &&
     cmp -s "$base/dns.pilot" "$live_dns" &&
     cmp -s "$base/nginx.pilot" "$live_nginx"; then
    confirmed=true
  fi
fi
if [[ "$confirmed" == true ]]; then
  systemctl disable --now "$name.timer" >/dev/null 2>&1 || true
  rm -f -- "/etc/systemd/system/$name.timer"
  systemctl daemon-reload
  echo 'owner_domain_canary_confirmed_no_rollback=true'
  exit 0
fi
for kind in dns nginx; do
  case "$kind" in
    dns) current="$live_dns";;
    nginx) current="$live_nginx";;
  esac
  if ! cmp -s "$base/$kind.before" "$current" &&
     ! cmp -s "$base/$kind.pilot" "$current"; then
    echo "owner_domain_rollback_unrecognized_${kind}_state=true"
    exit 4
  fi
done
if cmp -s "$base/nginx.pilot" "$live_nginx"; then
  owner_atomic_swap "$live_nginx" "$base/nginx.pilot" "$base/nginx.before"
  nginx -t >/dev/null 2>&1
  systemctl reload nginx
fi
if cmp -s "$base/dns.pilot" "$live_dns"; then
  owner_atomic_swap "$live_dns" "$base/dns.pilot" "$base/dns.before"
  test -x "$base/reload.sh"
  bash "$base/reload.sh" "$live_dns"
fi
# The rollback is successful only when DoT has re-opened public port 853.
for attempt in $(seq 1 60); do
  if systemctl is-active --quiet mnebydns-dot.service &&
     ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'; then
    break
  fi
  sleep .2
done
ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'
cmp -s "$base/dns.before" "$live_dns"
cmp -s "$base/nginx.before" "$live_nginx"
systemctl is-active --quiet nginx
systemctl is-active --quiet mnebydns-dot.service
systemctl disable --now "$name.timer" >/dev/null 2>&1 || true
rm -f -- "/etc/systemd/system/$name.timer"
systemctl daemon-reload
echo 'owner_domain_canary_rollback_verified=true'
