#!/usr/bin/env bash
# Install a standalone read-only DoT probe on an EXISTING server.
# Never changes CoreDNS/Nginx/WireGuard, customer routes or listeners.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 1 && "$1" =~ ^/tmp/mnebydns-dot-minute-[0-9]{9,13}$ ]] || exit 2
stage="$1"
py=/usr/local/libexec/mnebydns-dot-minute-probe.py
unit=/etc/systemd/system/mnebydns-dot-minute-probe.service
timer=/etc/systemd/system/mnebydns-dot-minute-probe.timer
test -s "$stage/probe.py"
test -s "$stage/probe.service"
test -s "$stage/probe.timer"
python3 "$stage/probe.py" --self-test >/dev/null
grep -Fq 'OnCalendar=minutely' "$stage/probe.timer"
grep -Fq 'DynamicUser=yes' "$stage/probe.service"
for entry in \
  "$stage/probe.py:$py" "$stage/probe.service:$unit" "$stage/probe.timer:$timer"; do
  src="$(printf '%s' "$entry" | cut -d: -f1)"
  dst="$(printf '%s' "$entry" | cut -d: -f2)"
  if [[ -e "$dst" ]] && ! cmp -s "$src" "$dst"; then
    echo 'MNEBYDNS_MONITOR_UNRECOGNIZED_BASELINE=true' >&2
    exit 9
  fi
done
install -D -m 0755 "$stage/probe.py" "$py"
install -m 0644 "$stage/probe.service" "$unit"
install -m 0644 "$stage/probe.timer" "$timer"
systemctl daemon-reload
systemctl enable --now mnebydns-dot-minute-probe.timer >/dev/null
systemctl is-active --quiet mnebydns-dot-minute-probe.timer
echo 'MNEBYDNS_EXISTING_NODE_MINUTE_MONITOR_INSTALLED=true'
