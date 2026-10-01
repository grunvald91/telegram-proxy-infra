#!/usr/bin/env bash
set -euo pipefail
# Block external access to the MTProxy container's 3128 port via DOCKER-USER.
# Public-facing 8088/8443 INPUT DROPs were removed on 2026-05-07 because the
# container is now bound to 127.0.0.1 only.
container_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' mtproto-proxy 2>/dev/null || true)
[ -n "$container_ip" ] || exit 0
iptables -C DOCKER-USER -i ens3 -p tcp -d "$container_ip" --dport 3128 -j DROP 2>/dev/null || iptables -I DOCKER-USER -i ens3 -p tcp -d "$container_ip" --dport 3128 -j DROP
