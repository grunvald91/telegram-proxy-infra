#!/usr/bin/env bash
# Guarded, targeted VPN/SmartDNS DoT self-route for the dedicated mnebyvpn-xray UID.
# No change to shared CoreDNS, VPN key material, Nginx, WireGuard or UDP/443.
set -Eeuo pipefail
umask 077
MODE="\${1:-status}"
ROOT=/var/lib/mnebydns-vpn-dot-selfroute-20261115
MARK="$ROOT/installed"
OWNER=mnebyvpn-xray
IP=89.125.90.101
ROUTER_PORT=8854
TIMER=mnebydns-vpn-dot-selfroute-autorevert-20261115.timer
SCRIPT=/opt/mnebydns-vpn-dot-selfroute-20261115/manage.sh
log() { printf 'VPN_DOT_SELFROUTE_%s=%s\n' "$1" "$2"; }
rule() {
  local uid
  uid="$(id -u "$OWNER")"
  test "$uid" != 0
  RULE=(-p tcp -d "$IP"/32 --dport 853 -m owner --uid-owner "$uid" -j REDIRECT --to-ports "$ROUTER_PORT")
}
present() { iptables -w -t nat -C OUTPUT "\${RULE[@]}" >/dev/null 2>&1; }
probe() {
  local host="$1"
  runuser -u "$OWNER" -- python3 - "$IP" "$host" <<'PY'
import socket, ssl, sys
ip, sni=sys.argv[1:]
with socket.create_connection((ip,853),timeout=7) as raw:
    raw.settimeout(7)
    with ssl.create_default_context().wrap_socket(raw,server_hostname=sni) as tls:
        assert tls.version()
print("VPN_DOT_SELFROUTE_CERT_VALID=true",flush=True)
PY
}
preflight() {
  rule
  test -x /usr/sbin/iptables
  test -r /etc/mnebydns/personal-sni/nginx.conf
  for svc in mnebydns-personal-sni-stream.service mnebydns-personal-sni-redirect.service mnebydns-dot.service mnebyvpn-vpn-provisioner.service; do
    systemctl is-active --quiet "$svc"
  done
  grep -Fq 'listen 0.0.0.0:8854;' /etc/mnebydns/personal-sni/nginx.conf
  grep -Fq 'default 89.125.90.101:853;' /etc/mnebydns/personal-sni/nginx.conf
  grep -Fq '10.66.77.2:8856;' /etc/mnebydns/personal-sni/nginx.conf
  ss -H -lntp | grep -E ':8854[[:space:]]' | grep -q nginx
  iptables -w -t nat -C PREROUTING -i eth0 -d "$IP" -p tcp --dport 853 -j REDIRECT --to-ports 8854
}
rollback() {
  rule
  if ! test -f "$MARK"; then log ROLLBACK SKIPPED_UNOWNED;return;fi
  if present; then iptables -w -t nat -D OUTPUT "\${RULE[@]}"; fi
  rm -f "$MARK"
  log ROLLBACK RESTORED
}
apply() {
  preflight
  mkdir -p -m 0700 "$ROOT"
  if test -f "$MARK" || present; then log ERROR DUPLICATE_RULE;exit 3;fi
  if probe aaaaaaaaaaaa.dns.mnebyvpn.site >/dev/null 2>&1; then
    log ERROR ALREADY_VALID_NO_CHANGE;exit 3
  fi
  systemd-run --quiet --unit=mnebydns-vpn-dot-selfroute-autorevert-20261115 --on-active=4m --collect /bin/bash "$SCRIPT" rollback
  log AUTO_ROLLBACK ARMED_4M
  : > "$MARK"
  trap 'rollback' ERR
  iptables -w -t nat -I OUTPUT 1 "\${RULE[@]}"
  present
  probe aaaaaaaaaaaa.dns.mnebyvpn.site
  probe dns.mnebyvpn.site
  log VERIFY BOTH_TLS_CERTS_VALID_FROM_VPN_PROCESS_UID
  for svc in mnebydns-personal-sni-stream.service mnebydns-personal-sni-redirect.service mnebydns-dot.service mnebyvpn-vpn-provisioner.service; do
    systemctl is-active --quiet "$svc"
  done
  systemctl stop "$TIMER"
  trap - ERR
  log INSTALLED CONFIRMED
}
status() {
  rule
  if present; then log RULE PRESENT;else log RULE ABSENT;fi
  if test -f "$MARK"; then log MARK PRESENT;else log MARK ABSENT;fi
}
case "$MODE" in
  apply) apply ;;
  rollback) rollback ;;
  status) status ;;
  *) echo 'usage: manage.sh apply|rollback|status' >&2;exit 2 ;;
esac
