#!/usr/bin/env bash
# Dedicated operator VPN subscription only; never mutate other customers.
set -Eeuo pipefail
umask 077
test "$(id -u)" = 0
SRC="$1"
test -s "$SRC"
python3 -m py_compile "$SRC"
test -d /opt/mnebyvpn/bot
test -s /opt/mnebyvpn/bot/provisioner.key
test "$(docker inspect --format '{{.State.Running}}' mnebyvpn-vpn-worker)" = true
DEST=/usr/local/sbin/mnebyvpn-owner-keepalive.py
install -o root -g root -m 0700 "$SRC" "$DEST"
cat > /etc/systemd/system/mnebyvpn-owner-keepalive.service <<'UNIT'
[Unit]
Description=MNEBYVPN signed owner VPN grant keepalive
Wants=network-online.target
After=network-online.target docker.service
[Service]
Type=oneshot
User=root
Group=root
UMask=0077
ExecStart=/usr/bin/python3 /usr/local/sbin/mnebyvpn-owner-keepalive.py renew
TimeoutStartSec=160
Nice=10
UNIT
cat > /etc/systemd/system/mnebyvpn-owner-keepalive.timer <<'UNIT'
[Unit]
Description=Maintain one MNEBYVPN operator test subscription ahead of node expiry
[Timer]
OnCalendar=daily
OnBootSec=15min
OnUnitInactiveSec=12h
RandomizedDelaySec=5min
Persistent=true
AccuracySec=1min
Unit=mnebyvpn-owner-keepalive.service
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
python3 "$DEST" activate
systemctl enable --now mnebyvpn-owner-keepalive.timer
systemctl is-enabled --quiet mnebyvpn-owner-keepalive.timer
systemctl is-active --quiet mnebyvpn-owner-keepalive.timer
systemctl list-timers --all --no-pager mnebyvpn-owner-keepalive.timer
echo 'operator_timer=enabled'
echo 'operator_grant_activation=verified'
