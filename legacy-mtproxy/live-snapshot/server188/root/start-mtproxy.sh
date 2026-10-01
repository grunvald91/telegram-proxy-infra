#!/usr/bin/env bash
set -euo pipefail
docker rm -f mtproto-proxy >/dev/null 2>&1 || true
docker run -d --name mtproto-proxy --restart unless-stopped -p 443:443 nineseconds/mtg:2 simple-run -n 1.1.1.1 -i prefer-ipv4 0.0.0.0:443 "<HEX_REDACTED>"
