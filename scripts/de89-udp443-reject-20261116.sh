#!/usr/bin/env bash
# Exact-purpose firewall rule for public DE89 QUIC UDP/443; no TCP, DoT, WG or Xray changes.
set -Eeuo pipefail
IP=89.125.90.101
DEV=eth0
RULE=(-i "$DEV" -d "$IP/32" -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable)
case "${1:-status}" in
  preflight)
    ip -4 -o addr show dev "$DEV" | grep -Fq "$IP/"
    systemctl is-active --quiet nginx.service
    systemctl is-active --quiet mnebydns-dot.service
    systemctl is-active --quiet mnebyvpn-vpn-provisioner.service
    ss -H -lun 'sport = :443' | grep -Fq "$IP:443"
    ! iptables -w -C INPUT "${RULE[@]}" >/dev/null 2>&1
    echo DE89_UDP443_REJECT_PREFLIGHT=PASS
    ;;
  apply)
    iptables -w -C INPUT "${RULE[@]}" >/dev/null 2>&1 || iptables -w -I INPUT 1 "${RULE[@]}"
    iptables -w -C INPUT "${RULE[@]}"
    echo DE89_UDP443_REJECT=ACTIVE
    ;;
  status)
    if iptables -w -C INPUT "${RULE[@]}" >/dev/null 2>&1; then
      echo DE89_UDP443_REJECT=ACTIVE
    else
      echo DE89_UDP443_REJECT=ABSENT
      exit 1
    fi
    ;;
  rollback)
    if iptables -w -C INPUT "${RULE[@]}" >/dev/null 2>&1; then
      iptables -w -D INPUT "${RULE[@]}"
    fi
    echo DE89_UDP443_REJECT=REMOVED
    ;;
  *) exit 2 ;;
esac
