#!/usr/bin/env bash
# Shared CoreDNS config-change readiness check. Never blindly restart a
# resolver that already has the tested CoreDNS reload plugin configured.
set -Eeuo pipefail
[[ $# == 1 && "$1" == /opt/mnebydns-dot/Corefile ]] || exit 2
dns="$1"
service=mnebydns-dot.service
systemctl is-active --quiet "$service"
old_pid="$(systemctl show --value -p MainPID "$service")"
[[ "$old_pid" =~ ^[1-9][0-9]+$ ]] || exit 3

if grep -Fxq '    reload 5s 1s' "$dns"; then
  # The reload plugin picks up atomic Corefile replacements automatically.
  # Let it observe the change and require that the serving PID remains stable.
  /opt/mnebydns-dot/coredns -plugins 2>&1 | grep -Eq '(^|[[:space:].])reload([[:space:]]|$)'
  sleep 7
  current_pid="$(systemctl show --value -p MainPID "$service")"
  [[ "$current_pid" == "$old_pid" ]] || {
    echo 'mnebydns_reload_pid_changed=true'
    exit 3
  }
  echo 'mnebydns_reload_without_restart=true'
else
  # Compatibility with the legacy stable Corefile before the migration.
  systemctl restart "$service"
  echo 'mnebydns_legacy_restart=true'
fi

for attempt in $(seq 1 20); do
  if systemctl is-active --quiet "$service" &&
     ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'; then
    echo 'mnebydns_dot_listener_ready=true'
    exit 0
  fi
  sleep .2
done
echo 'mnebydns_dot_listener_missing=true'
exit 4
