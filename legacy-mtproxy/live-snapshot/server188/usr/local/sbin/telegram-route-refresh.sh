#!/usr/bin/env bash
set -euo pipefail

SET_NAME="telegram_api"
TMP_SET="${SET_NAME}_tmp"
REDSOCKS_PORT="12346"
TINYPROXY_UID="$(id -u tinyproxy)"
TELEMT_UID="$(id -u telemt)"

ipset create "$SET_NAME" hash:ip family inet -exist
ipset create "$TMP_SET" hash:ip family inet -exist
ipset flush "$TMP_SET"

mapfile -t IPS < <(getent ahostsv4 api.telegram.org | awk '{print $1}' | sort -u)
if [ "${#IPS[@]}" -eq 0 ]; then
  IPS=(149.154.167.220)
fi

for ip in "${IPS[@]}"; do
  ipset add "$TMP_SET" "$ip" -exist
done

ipset swap "$SET_NAME" "$TMP_SET"
ipset flush "$TMP_SET"

iptables -t mangle -C OUTPUT -p tcp -m owner --uid-owner "$TINYPROXY_UID" --dport 443 -j MARK --set-mark 0x77 2>/dev/null ||           iptables -t mangle -A OUTPUT -p tcp -m owner --uid-owner "$TINYPROXY_UID" --dport 443 -j MARK --set-mark 0x77

iptables -t nat -C OUTPUT -p tcp -m set --match-set "$SET_NAME" dst --dport 443 -m owner ! --uid-owner "$TINYPROXY_UID" -m owner ! --uid-owner "$TELEMT_UID" -j REDIRECT --to-ports "$REDSOCKS_PORT" 2>/dev/null ||           iptables -t nat -I OUTPUT 1 -p tcp -m set --match-set "$SET_NAME" dst --dport 443 -m owner ! --uid-owner "$TINYPROXY_UID" -m owner ! --uid-owner "$TELEMT_UID" -j REDIRECT --to-ports "$REDSOCKS_PORT"
