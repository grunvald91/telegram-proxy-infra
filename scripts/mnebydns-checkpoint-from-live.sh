#!/usr/bin/env bash
# Record the current DE89 DNS and proxy configs as the NVIDIA rollout's rollback point.
set -Eeuo pipefail
umask 077
(( EUID == 0 ))
[[ $# == 1 && "$1" =~ ^[1-9][0-9]{8,12}$ ]]
base=/opt/mnebydns-stable-checkpoints
pointer="$base/current"
target="$base/$1"
dns=/opt/mnebydns-dot/Corefile
nginx=/etc/nginx/nginx.conf
proxy=/etc/mnebydns-googlepilot/nginx.conf

exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 35 9
trap 'echo "nvidia_live_checkpoint_failed_at_line=$LINENO" >&2' ERR
for service in nginx mnebydns-dot.service; do
  if ! systemctl is-active --quiet "$service"; then
    echo "nvidia_live_checkpoint_required_service_inactive=$service" >&2
    exit 3
  fi
done
for service in mnebydns-googlepilot.service xray.service; do
  state="$(systemctl is-active "$service" || true)"
  echo "nvidia_live_checkpoint_other_service=$service:$state"
done
# Confirmed owner timers are deliberately kept armed as no-ops. Any
# other timed rollback could replace a live config during the batch.
timers="$(systemctl list-units --type=timer --state=active --plain --no-legend)"
while read -r unit _; do
  case "$unit" in
    mnebydns-owner-rollback-*.timer)
      id="${unit#mnebydns-owner-rollback-}"
      id="${id%.timer}"
      if [[ "$id" =~ ^[1-9][0-9]{8,12}$ && -f "/opt/mnebydns-owner-domain/$id/confirmed" ]]; then
        continue
      fi
      echo "nvidia_live_checkpoint_busy=$unit" >&2
      exit 4 ;;
    mnebydns-*rollback*.timer|mnebydns-*revert*.timer|mnebydns-*watchdog*.timer)
      timer_substate="$(systemctl show "$unit" -p SubState --value)"
      rollback_service="$(systemctl show "$unit" -p Unit --value)"
      [[ "$rollback_service" =~ ^mnebydns-[a-z0-9.-]+[.]service$ ]]
      service_state="$(systemctl show "$rollback_service" -p ActiveState --value)"
      echo "nvidia_live_checkpoint_timer=$unit:$timer_substate:$service_state" >&2
      # A completed one-shot calendar timer is still ActiveState=active
      # (elapsed), with no future event. Treat only that terminal state as inert.
      if [[ "$timer_substate" == elapsed && ( "$service_state" == inactive || "$service_state" == failed ) ]]; then
        continue
      fi
      echo "nvidia_live_checkpoint_busy=$unit" >&2
      exit 4 ;;
  esac
done <<< "$timers"

nginx -t -q
test -f "$pointer" && test ! -L "$pointer"
old="$(cat "$pointer")"
[[ "$old" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]]
tmp="$(mktemp -d "$base/.nvidia-baseline.XXXXXXXX")"
cleanup() { rm -rf -- "$tmp"; }
trap cleanup EXIT
for pair in "dns:$dns" "nginx:$nginx" "proxy:$proxy"; do
  IFS=: read -r name source <<< "$pair"
  test -s "$source" && test ! -L "$source"
  cp --preserve=mode,ownership,timestamps -- "$source" "$tmp/$name.stable"
done
(cd "$tmp" && sha256sum dns.stable nginx.stable proxy.stable > stable-manifest.sha256)
cmp -s "$tmp/dns.stable" "$dns"
cmp -s "$tmp/nginx.stable" "$nginx"
cmp -s "$tmp/proxy.stable" "$proxy"
test "$(cat "$pointer")" = "$old"
test ! -e "$target"
printf '%s\n' "$old" > "$tmp/previous-pointer"
mkdir -m 700 "$target"
for name in dns.stable nginx.stable proxy.stable stable-manifest.sha256 previous-pointer; do
  mv -- "$tmp/$name" "$target/$name"
done
(cd "$target" && sha256sum --strict -c stable-manifest.sha256 >/dev/null)
printf '%s\n' "$target" > "$tmp/current"
chmod --reference="$pointer" "$tmp/current"
chown --reference="$pointer" "$tmp/current"
mv -T -- "$tmp/current" "$pointer"
echo 'nvidia_rollback_snapshot_from_current_live_files=true'
