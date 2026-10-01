#!/usr/bin/env bash
set -u

echo "== listeners =="
ss -lntp 2>/dev/null | grep -Ei '(:80|:443|:2398|:8888|:8080|:8081)|mtproxy|tproxy|caddy|nginx' || true

echo
echo "== relevant services =="
for svc in mtproxy tproxy-server caddy nginx docker; do
  if systemctl list-unit-files "$svc.service" >/dev/null 2>&1; then
    printf '%-20s ' "$svc"
    systemctl is-active "$svc" 2>/dev/null || true
  fi
done

echo
echo "This script only checks local service/listener state."
