#!/usr/bin/env bash
set -Eeuo pipefail
[[ "$(id -u)" == 0 ]] || exit 2
src="${1:?staged watchdog required}"
test -s "$src"
bash -n "$src"
[[ "$(systemctl is-active mnebydns-dot)" == active ]] || exit 2
[[ "$(systemctl is-active mnebydns-personal-sni-stream.service)" == active ]] || exit 2
[[ "$(systemctl is-active mnebydns-personal-sni-redirect.service)" == active ]] || exit 2
iptables -w -t nat -C PREROUTING -i eth0 -d 89.125.90.101 -p tcp --dport 853 -j REDIRECT --to-ports 8854
target=/usr/local/sbin/mnebydns-personal-sni-watch
service=/etc/systemd/system/mnebydns-personal-sni-watch.service
timer=/etc/systemd/system/mnebydns-personal-sni-watch.timer
if test -e "$target" || test -e "$service" || test -e "$timer"; then
  echo 'PERSONAL_SNI_WATCH_INSTALL=REFUSE_OVERWRITE'
  exit 2
fi
install -m 750 "$src" "$target"
cat > "$service" <<'UNIT'
[Unit]
Description=MNEBYDNS check SNI ingress, fail back to original CoreDNS after 3 failures
After=mnebydns-personal-sni-stream.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/mnebydns-personal-sni-watch
TimeoutStartSec=35
NoNewPrivileges=true
PrivateTmp=true
UNIT
cat > "$timer" <<'UNIT'
[Unit]
Description=MNEBYDNS guarded personal DoT SNI health every minute
[Timer]
OnBootSec=2min
OnUnitInactiveSec=1min
AccuracySec=10s
Unit=mnebydns-personal-sni-watch.service
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now mnebydns-personal-sni-watch.timer >/dev/null
systemctl start mnebydns-personal-sni-watch.service
systemctl is-active --quiet mnebydns-personal-sni-watch.timer
systemctl is-active --quiet mnebydns-dot
iptables -w -t nat -C PREROUTING -i eth0 -d 89.125.90.101 -p tcp --dport 853 -j REDIRECT --to-ports 8854
echo 'PERSONAL_SNI_WATCH=INSTALLED_HEALTHY_PUBLIC_CORE_PRESERVED'
