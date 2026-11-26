#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
action="$1"
stage="$2"
[[ "$stage" =~ ^/run/fi-public-https-[0-9]+-[0-9]+$ && $EUID == 0 ]]
[[ -d "$stage" && ! -L "$stage" && "$(stat -c %u:%a "$stage")" == 0:700 ]]
state=/var/lib/mnebyvpn-nodekit/fi-test-01/dns-auth
unit=mnebyvpn-fi-public-https
socket="$unit.socket"
service="$unit.service"
marker="$state/public-https.enable"
relay="$state/PublicHttpsRelay.py"
timer="fi-https-rollback-$(basename "$stage" | sed 's/^fi-public-https-//')"
ip=217.11.167.91
listeners() { ss -H -lnt "sport = :$1" | awk '{print $4}'; }
guard() {
  for u in mnebyvpn-fi-dns-country.service mnebyvpn-fi-public-dot.socket mnebyvpn-fi-sni-routed-v3.service mnebyvpn-fi-sni-egress-guard.service; do
    systemctl is-active --quiet "$u"
  done
  [[ "$(listeners 14443)" == 127.0.0.1:14443 && "$(listeners 853)" == "$ip:853" ]]
  [[ ! -e "$state/customer-dataplane.enable" && ! -L "$state/customer-dataplane.enable" ]]
  PYTHONPATH=/opt/mnebyvpn-fi-dns-node python3 -B - <<'PY'
from fi_sni_egress_guard import verify,uid,FINGERPRINT
from fi_dns_ssh_stage import read,host
host("217.11.167.91")
n=uid()
parts=read(FINGERPRINT,100).decode().strip().split(":")
assert len(parts)==2 and parts[0]==str(n)
verify(n,parts[1])
PY
}
rollback() {
  [[ -f "$stage/started" ]] || return 0
  [[ "$(cat "$stage/started")" == fi-public-https-v1 ]]
  systemctl disable --now "$socket" >/dev/null 2>&1 || true
  systemctl stop "$service" >/dev/null 2>&1 || true
  for f in "$marker" "$relay" "/etc/systemd/system/$socket" "/etc/systemd/system/$service"; do
    [[ ! -L "$f" ]] || return 1
    rm -f -- "$f"
  done
  systemctl daemon-reload
  [[ -z "$(listeners 443)" ]]
  guard
  rm -f -- "$stage/started"
  echo FI_PUBLIC_HTTPS_ROLLBACK_VERIFIED=true
}
case "$action" in
  stage)
    guard
    [[ -z "$(listeners 443)" ]]
    [[ -z "$(ss -H -lnu 'sport = :443')" ]]
    for f in "$marker" "$relay" "/etc/systemd/system/$socket" "/etc/systemd/system/$service"; do
      [[ ! -e "$f" && ! -L "$f" ]]
    done
    for u in "$socket" "$service"; do
      for base in /etc/systemd/system /run/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
        [[ ! -e "$base/$u.d" && ! -L "$base/$u.d" && ! -e "$base/$u" && ! -L "$base/$u" ]]
      done
    done
    printf 'fi-public-https-v1\n' > "$stage/started"
    trap 'rollback' ERR
    systemd-run --quiet --unit="$timer" --on-active=4min /bin/bash "$stage/stage.sh" rollback "$stage"
    install -m 0600 "$stage/fi_public_https_relay.py" "$relay"
    install -m 0644 "$stage/$socket" "/etc/systemd/system/$socket"
    install -m 0644 "$stage/$service" "/etc/systemd/system/$service"
    systemd-analyze verify "/etc/systemd/system/$socket" "/etc/systemd/system/$service"
    systemctl daemon-reload
    printf 'fi-public-https-v1\n' > "$marker"
    systemctl start "$socket"
    [[ "$(listeners 443)" == "$ip:443" ]]
    guard
    echo FI_PUBLIC_HTTPS_STAGED=true
    ;;
  commit)
    guard
    [[ -f "$stage/started" && "$(cat "$stage/started")" == fi-public-https-v1 ]]
    [[ "$(listeners 443)" == "$ip:443" ]]
    systemctl is-active --quiet "$socket"
    systemctl is-active --quiet "$service"
    pid=$(systemctl show "$service" -p MainPID --value)
    [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]]
    awk '/^Uid:/ { if ($2==0||$3==0||$4==0||$5==0) exit 1; u=1 } /^CapEff:/ {if ($2 !~ /^0+$/) exit 1; c=1} END {if (!u||!c) exit 1}' "/proc/$pid/status"
    systemctl enable "$socket"
    systemctl is-enabled --quiet "$socket"
    systemctl stop "$timer.timer"
    rm -f -- "$stage/started"
    echo FI_PUBLIC_HTTPS_COMMITTED=true
    ;;
  rollback) rollback; systemctl stop "$timer.timer" || true ;;
  *) exit 2 ;;
esac
