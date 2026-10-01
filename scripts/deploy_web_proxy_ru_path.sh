#!/usr/bin/env bash
set -euo pipefail
umask 077

ROLE="${1:-}"
BASE_PATH="${2:-}"
SECRET="${3:-}"

die(){ echo "[web-proxy-ru] ERROR: $*" >&2; exit 1; }
log(){ echo "[web-proxy-ru] $*"; }

[ -n "$ROLE" ] || die "role required"
[ -n "$BASE_PATH" ] || die "base path required"
[ -n "$SECRET" ] || die "secret required"

case "$ROLE" in
  mirror188)
    CONF="/etc/nginx/conf.d/tproxy-web-ru-mirror-only.conf"
    [ -f /etc/nginx/sites-enabled/bandbook ] || die "BandBook nginx site missing"
    nginx -t >/dev/null 2>&1 || die "existing nginx invalid"

    if ss -lntH "sport = :3001" | grep -q .; then
      if [ -f "$CONF" ]; then
        log "mirror already active"
        exit 0
      fi
      die "port 3001 already busy"
    fi

    cat > "$CONF" <<'EOF'
server {
    listen 10.66.77.2:3001;
    server_name _;
    root /var/www/bandbook;
    index index.html;
    client_max_body_size 64M;

    location /assets/ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        try_files $uri =404;
    }

    location / {
        try_files $uri $uri/ /index.html;
    }
}
EOF
    nginx -t
    systemctl reload nginx
    curl --fail --silent --show-error --max-time 10 -H 'Host: bandbook.site'       -o /tmp/bandbook-mirror-check.html http://10.66.77.2:3001/
    rm -f /tmp/bandbook-mirror-check.html
    log "mirror188 SUCCESS"
    ;;

  edge188)
    NGINX_SITE="/etc/nginx/sites-enabled/bandbook"
    CONF="/etc/nginx/conf.d/tproxy-web-ru.conf"
    BACKUP="/root/tproxy-ru-edge-predeploy-$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$BACKUP"
    cp -a "$NGINX_SITE" "$BACKUP/bandbook"
    [ ! -e "$CONF" ] || cp -a "$CONF" "$BACKUP/tproxy-web-ru.conf"
    nginx -t >/dev/null 2>&1 || die "existing nginx invalid"

    curl --fail --silent --show-error --location --max-time 15       -o /tmp/bandbook-before.html https://bandbook.site/
    BEFORE_SHA="$(sha256sum /tmp/bandbook-before.html | awk '{print $1}')"
    rm -f /tmp/bandbook-before.html

    rollback_edge(){
      rc=$?
      trap - ERR
      cp -a "$BACKUP/bandbook" "$NGINX_SITE"
      if [ -f "$BACKUP/tproxy-web-ru.conf" ]; then cp -a "$BACKUP/tproxy-web-ru.conf" "$CONF"; else rm -f "$CONF"; fi
      nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
      exit "$rc"
    }
    trap rollback_edge ERR

    rm -f /etc/nginx/conf.d/tproxy-web-ru-mirror-only.conf

    cat > "$CONF" <<EOF
map \$http_upgrade \$tproxy_ru_connection_upgrade {
    default upgrade;
    ''      "";
}

upstream tproxy_ru_over_wireguard {
    server 10.66.77.1:8082;
    keepalive 32;
}

server {
    listen 10.66.77.2:3001;
    server_name _;
    root /var/www/bandbook;
    index index.html;
    client_max_body_size 64M;

    location = /sw.js {
        add_header Cache-Control "no-cache, no-store, must-revalidate";
        try_files \$uri =404;
    }

    location = /manifest.webmanifest {
        add_header Cache-Control "no-cache";
        default_type application/manifest+json;
        try_files \$uri =404;
    }

    location /assets/ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        try_files \$uri =404;
    }

    location / {
        try_files \$uri \$uri/ /index.html;
    }
}
EOF

    python3 - "$NGINX_SITE" "$BASE_PATH" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]); base=sys.argv[2]
s=p.read_text()
if 'proxy_pass http://tproxy_ru_over_wireguard;' in s:
    raise SystemExit('WEB proxy RU route already present')
marker='    location / {\n        try_files $uri $uri/ /index.html;\n    }'
if marker not in s:
    raise SystemExit('BandBook root location marker not found')
block=f'''    # Telegram WEB proxy via RU edge -> WireGuard -> foreign relay.
    location ^~ /{base}/ {{
        client_max_body_size 4m;
        proxy_pass http://tproxy_ru_over_wireguard;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $tproxy_ru_connection_upgrade;

        proxy_read_timeout 90s;
        proxy_send_timeout 90s;
        proxy_buffering off;
        proxy_request_buffering off;
        access_log off;
    }}

'''
s=s.replace(marker, block+marker, 1)
p.write_text(s)
PY

    nginx -t

    # First reload creates the WG-only mirror. The public hidden route is present too,
    # but deploy orchestration calls this role only after relay89 is ready.
    systemctl reload nginx

    # Confirm the WireGuard backend is reachable from the edge.
    curl --fail --silent --show-error --max-time 12       -H 'Host: bandbook.site'       -o /tmp/tproxy-ru-decoy.html       "http://10.66.77.1:8082/$BASE_PATH/not-a-real-route"
    rm -f /tmp/tproxy-ru-decoy.html

    curl --fail --silent --show-error --location --max-time 15       -o /tmp/bandbook-after.html https://bandbook.site/
    AFTER_SHA="$(sha256sum /tmp/bandbook-after.html | awk '{print $1}')"
    rm -f /tmp/bandbook-after.html
    [ "$BEFORE_SHA" = "$AFTER_SHA" ] || die "BandBook public root changed"

    trap - ERR
    log "edge188 SUCCESS"
    ;;

  relay89)
    STATE="/etc/tproxy-server-ru"
    MTPSTATE="/etc/mtproxy-ru"
    SOURCE="/opt/tproxy-server-src"
    BACKUP="/root/tproxy-ru-relay-predeploy-$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$BACKUP"

    for p in 2399 8082 8084 8085 8889; do
      if ss -lntH "sport = :$p" | grep -q .; then die "port $p busy"; fi
    done

    # Require the existing first WEB proxy source/binaries to be healthy.
    [ -x /usr/local/bin/tproxy-server ] || die "tproxy-server binary missing"
    [ -x /opt/MTProxy/objs/bin/mtproto-proxy ] || die "official MTProxy binary missing"
    [ -f /etc/mtproxy/proxy-secret ] || die "MTProxy proxy-secret missing"
    [ -f /etc/mtproxy/proxy-multi.conf ] || die "MTProxy proxy-multi.conf missing"

    # Verify the reverse decoy path over WireGuard before configuring the relay.
    curl --fail --silent --show-error --max-time 12       -H 'Host: bandbook.site' -o /tmp/bandbook-mirror.html http://10.66.77.2:3001/
    rm -f /tmp/bandbook-mirror.html

    rollback_relay(){
      rc=$?
      trap - ERR
      systemctl disable --now tproxy-server-ru.service mtproxy-ru.service tproxy-firewall-ru.service 2>/dev/null || true
      rm -f /etc/nginx/conf.d/tproxy-web-ru-bridge.conf
      nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
      exit "$rc"
    }
    trap rollback_relay ERR

    install -d -o root -g tproxy -m 0750 "$STATE"
    install -d -o root -g mtproxy -m 0750 "$MTPSTATE"

    cat > "$STATE/config.json" <<EOF
{
  "public_hostname": "bandbook.site",
  "base_path": "$BASE_PATH",
  "listen": "127.0.0.1:8084",
  "admin_listen": "127.0.0.1:8085",
  "public_upstream": "http://10.66.77.2:3001",
  "token_key_file": "$STATE/token.key",
  "static_routes": "exact",
  "profiles_file": "/run/credentials/tproxy-server-ru.service/profiles.json"
}
EOF
    cat > "$STATE/profiles.json" <<EOF
{"profiles":[{"name":"ru-wireguard","secret":"$SECRET","backend":"127.0.0.1:2399","carrier_mode":"https"}]}
EOF
    chown root:tproxy "$STATE/config.json"
    chmod 0640 "$STATE/config.json"
    chown root:root "$STATE/profiles.json"
    chmod 0400 "$STATE/profiles.json"

    head -c 32 /dev/urandom > "$STATE/token.key"
    chown root:tproxy "$STATE/token.key"
    chmod 0440 "$STATE/token.key"

    cat > "$MTPSTATE/mtproxy.env" <<EOF
MTPROXY_SECRET=$SECRET
MTPROXY_WORKERS=1
MTPROXY_MAX_CONNECTIONS=4096
MTPROXY_NAT_ARGS=
EOF
    chmod 0640 "$MTPSTATE/mtproxy.env"
    chown root:mtproxy "$MTPSTATE/mtproxy.env"

    LOCAL_ADDRESS="$(ip -4 route get 149.154.175.50 2>/dev/null | sed -n 's/.*[[:space:]]src[[:space:]]\+\([0-9.]*\).*/\1/p' | head -1)"
    PUBLIC_ADDRESS="$(curl --fail --silent --show-error --ipv4 --max-time 12 https://api.ipify.org 2>/dev/null | tr -d '[:space:]' || true)"
    if [ -n "$LOCAL_ADDRESS" ] && [ -n "$PUBLIC_ADDRESS" ] && [ "$LOCAL_ADDRESS" != "$PUBLIC_ADDRESS" ]; then
      sed -i "s#^MTPROXY_NAT_ARGS=.*#MTPROXY_NAT_ARGS=--nat-info $LOCAL_ADDRESS:$PUBLIC_ADDRESS#" "$MTPSTATE/mtproxy.env"
    fi

    cat > /etc/systemd/system/tproxy-firewall-ru.service <<'EOF'
[Unit]
Description=Firewall for second official MTProxy backend
Before=mtproxy-ru.service
After=network-pre.target
DefaultDependencies=no

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/tproxy-server-ru/firewall.nft
ExecStop=/usr/sbin/nft delete table inet tproxy_backend_ru

[Install]
WantedBy=multi-user.target
EOF

    cat > "$STATE/firewall.nft" <<'EOF'
table inet tproxy_backend_ru {
    chain local_backend {
        type filter hook input priority -9; policy accept;
        iifname != "lo" tcp dport { 2399, 8889 } drop
    }
}
EOF

    cat > /etc/systemd/system/mtproxy-ru.service <<'EOF'
[Unit]
Description=Second official Telegram MTProxy backend for RU-WireGuard WEB proxy
After=network-online.target tproxy-firewall-ru.service
Wants=network-online.target
Requires=tproxy-firewall-ru.service

[Service]
Type=simple
User=mtproxy
Group=mtproxy
EnvironmentFile=/etc/mtproxy-ru/mtproxy.env
WorkingDirectory=/opt/MTProxy
ExecStart=/bin/sh -c 'exec /opt/MTProxy/objs/bin/mtproto-proxy -u mtproxy -p 8889 -H 2399 -S "$MTPROXY_SECRET" $MTPROXY_NAT_ARGS --aes-pwd /etc/mtproxy/proxy-secret /etc/mtproxy/proxy-multi.conf -M "$MTPROXY_WORKERS" -C "$MTPROXY_MAX_CONNECTIONS"'
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
ProtectHome=true
ProtectProc=invisible
ProtectSystem=strict
ProcSubset=pid
ReadOnlyPaths=/etc/mtproxy /etc/mtproxy-ru
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=true
RestrictRealtime=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/tproxy-server-ru.service <<'EOF'
[Unit]
Description=Telegram WEB proxy relay reached through RU edge and WireGuard
After=network-online.target mtproxy-ru.service tproxy-firewall-ru.service
Wants=network-online.target mtproxy-ru.service
Requires=tproxy-firewall-ru.service

[Service]
Type=simple
User=tproxy
Group=tproxy
LoadCredential=profiles.json:/etc/tproxy-server-ru/profiles.json
ExecStart=/usr/local/bin/tproxy-server -config /etc/tproxy-server-ru/config.json
Restart=on-failure
RestartSec=3s
TimeoutStopSec=20s
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
ProtectClock=true
ProtectControlGroups=true
ProtectHome=true
ProtectHostname=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectProc=invisible
ProtectSystem=strict
ProcSubset=pid
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=
IPAddressDeny=any
IPAddressAllow=localhost
IPAddressAllow=10.66.77.2/32
SystemCallArchitectures=native
SystemCallFilter=@system-service
UMask=0077

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/nginx/conf.d/tproxy-web-ru-bridge.conf <<'EOF'
server {
    listen 10.66.77.1:8082;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:8084;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $http_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $http_connection;
        proxy_read_timeout 90s;
        proxy_send_timeout 90s;
        proxy_buffering off;
        proxy_request_buffering off;
        access_log off;
    }
}
EOF

    nginx -t

    /usr/local/bin/tproxy-server -config "$STATE/config.json" -profiles-file "$STATE/profiles.json" -check

    systemctl daemon-reload
    systemctl enable --now tproxy-firewall-ru.service
    systemctl enable --now mtproxy-ru.service
    systemctl enable --now tproxy-server-ru.service
    systemctl reload nginx

    READY=""
    for _ in $(seq 1 25); do
      if curl --fail --silent --output /dev/null http://127.0.0.1:8085/readyz; then READY=1; break; fi
      sleep 1
    done
    [ -n "$READY" ] || die "second relay readiness failed"
    systemctl is-active --quiet mtproxy-ru.service || die "second mtproxy inactive"

    # Check the WG-facing nginx bridge locally using the correct Host.
    curl --fail --silent --show-error --max-time 12       -H 'Host: bandbook.site'       -o /tmp/tproxy-ru-bridge.html       "http://10.66.77.1:8082/$BASE_PATH/not-a-real-route"
    rm -f /tmp/tproxy-ru-bridge.html

    trap - ERR
    log "relay89 SUCCESS"
    ;;

  *)
    die "unknown role: $ROLE"
    ;;
esac

# deploy-trigger: ru-web-v3
