#!/usr/bin/env bash
set -euo pipefail
umask 077

TPROXY_COMMIT="c8adb8b7c6b7fc46c12ae3acb68be9070c26a8e8"
HOSTNAME_PUBLIC="cdn.servgo.ru"
NGINX_SITE="/etc/nginx/sites-enabled/cdn-servgo"
RELAY_PORT="8080"
ADMIN_PORT="8081"
MTPROXY_PORT="2398"
MTPROXY_STATS_PORT="8888"
PUBLIC_MIRROR_PORT="3000"
SOURCE_DIR="/opt/tproxy-server-src"
STATE_DIR="/etc/tproxy-server"
CLIENT_FILE="/root/tproxy-web-client.txt"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="/root/tproxy-predeploy-$STAMP"

log() { printf '%s\n' "[web-proxy] $*"; }
die() { printf '%s\n' "[web-proxy] ERROR: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root"
[ "$(uname -m)" = "x86_64" ] || die "x86_64 required"
[ -f "$NGINX_SITE" ] || die "missing $NGINX_SITE"

for p in "$MTPROXY_PORT" "$RELAY_PORT" "$ADMIN_PORT" "$MTPROXY_STATS_PORT" "$PUBLIC_MIRROR_PORT"; do
  if ss -lntH "sport = :$p" | grep -q .; then
    die "required TCP port $p is already in use"
  fi
done

nginx -t >/dev/null 2>&1 || die "existing nginx config is invalid"
curl --fail --silent --show-error --location --max-time 15   --output /tmp/tproxy-site-before.html "https://$HOSTNAME_PUBLIC/"
SITE_BEFORE_SHA="$(sha256sum /tmp/tproxy-site-before.html | awk '{print $1}')"
rm -f /tmp/tproxy-site-before.html

mkdir -p "$BACKUP_DIR"
cp -a /etc/nginx/nginx.conf "$BACKUP_DIR/nginx.conf"
cp -a "$NGINX_SITE" "$BACKUP_DIR/cdn-servgo"
[ ! -e /etc/nginx/conf.d/tproxy-web.conf ] || cp -a /etc/nginx/conf.d/tproxy-web.conf "$BACKUP_DIR/tproxy-web.conf"
systemctl list-unit-files > "$BACKUP_DIR/systemd-before.txt"
ss -lntup > "$BACKUP_DIR/listeners-before.txt" || true

rollback() {
  rc=$?
  trap - ERR
  log "rollback after failure (rc=$rc)"
  systemctl disable --now tproxy-server.service mtproxy.service refresh-mtproxy-config.timer tproxy-firewall.service 2>/dev/null || true

  if [ -f "$BACKUP_DIR/cdn-servgo" ]; then
    cp -a "$BACKUP_DIR/cdn-servgo" "$NGINX_SITE"
  fi
  if [ -f "$BACKUP_DIR/tproxy-web.conf" ]; then
    cp -a "$BACKUP_DIR/tproxy-web.conf" /etc/nginx/conf.d/tproxy-web.conf
  else
    rm -f /etc/nginx/conf.d/tproxy-web.conf
  fi

  nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
  log "rollback complete; legacy proxy services were not modified"
  exit "$rc"
}
trap rollback ERR

export DEBIAN_FRONTEND=noninteractive
log "installing build/runtime prerequisites"
apt-get update -qq
apt-get install -y -qq --no-install-recommends   ca-certificates curl git build-essential iproute2 libssl-dev util-linux zlib1g-dev nftables openssl

log "fetching pinned Telegram Desktop tproxy-server source"
if [ -d "$SOURCE_DIR/.git" ]; then
  git -C "$SOURCE_DIR" fetch --quiet --prune origin
else
  rm -rf "$SOURCE_DIR"
  git clone --quiet https://github.com/telegramdesktop/tproxy-server.git "$SOURCE_DIR"
fi
git -C "$SOURCE_DIR" checkout --quiet --detach "$TPROXY_COMMIT"
[ "$(git -C "$SOURCE_DIR" rev-parse HEAD)" = "$TPROXY_COMMIT" ] || die "tproxy commit mismatch"

log "building/installing official MTProxy backend"
bash "$SOURCE_DIR/deploy/install-mtproxy.sh"

log "preparing Go toolchain"
GO_BIN=""
if command -v go >/dev/null 2>&1; then
  GO_MINOR="$(go env GOVERSION | sed -E 's/^go1\.([0-9]+).*/\1/' || true)"
  if [[ "$GO_MINOR" =~ ^[0-9]+$ ]] && [ "$GO_MINOR" -ge 20 ]; then
    GO_BIN="$(command -v go)"
  fi
fi
if [ -z "$GO_BIN" ]; then
  GO_VERSION="1.26.5"
  GO_SHA256="5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053"
  GO_ARCHIVE="/tmp/go-$GO_VERSION.tar.gz"
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2     -o "$GO_ARCHIVE" "https://go.dev/dl/go$GO_VERSION.linux-amd64.tar.gz"
  [ "$(sha256sum "$GO_ARCHIVE" | awk '{print $1}')" = "$GO_SHA256" ] || die "Go checksum mismatch"
  rm -rf "/opt/go$GO_VERSION"
  mkdir -p "/opt/go$GO_VERSION"
  tar -C "/opt/go$GO_VERSION" --strip-components=1 -xzf "$GO_ARCHIVE"
  rm -f "$GO_ARCHIVE"
  GO_BIN="/opt/go$GO_VERSION/bin/go"
fi

log "testing/building tproxy-server"
(cd "$SOURCE_DIR" && "$GO_BIN" test ./...)
(cd "$SOURCE_DIR" && "$GO_BIN" build -trimpath -ldflags='-s -w' -o /usr/local/bin/tproxy-server ./cmd/tproxy-server)
chown root:root /usr/local/bin/tproxy-server
chmod 0755 /usr/local/bin/tproxy-server

if ! id tproxy >/dev/null 2>&1; then
  useradd --system --home /nonexistent --shell /usr/sbin/nologin tproxy
fi

install -d -o root -g tproxy -m 0750 "$STATE_DIR"
install -d -o root -g mtproxy -m 0750 /etc/mtproxy

log "creating server-local WEB proxy credentials"
SECRET="$(openssl rand -hex 16)"
BASE_PATH="$(head -c 10 /dev/urandom | base32 | tr 'A-Z' 'a-z')"

cat > "$STATE_DIR/config.json" <<EOF
{
  "public_hostname": "$HOSTNAME_PUBLIC",
  "base_path": "$BASE_PATH",
  "listen": "127.0.0.1:$RELAY_PORT",
  "admin_listen": "127.0.0.1:$ADMIN_PORT",
  "public_upstream": "http://127.0.0.1:$PUBLIC_MIRROR_PORT",
  "token_key_file": "$STATE_DIR/token.key",
  "static_routes": "exact",
  "profiles_file": "/run/credentials/tproxy-server.service/profiles.json"
}
EOF

cat > "$STATE_DIR/profiles.json" <<EOF
{"profiles":[{"name":"default","secret":"$SECRET","backend":"127.0.0.1:$MTPROXY_PORT","carrier_mode":"https"}]}
EOF
chown root:tproxy "$STATE_DIR/config.json"
chmod 0640 "$STATE_DIR/config.json"
chown root:root "$STATE_DIR/profiles.json"
chmod 0400 "$STATE_DIR/profiles.json"

bash "$SOURCE_DIR/deploy/ensure-token-key.sh"

BACKEND_SECRET="$SECRET"
cat > /etc/mtproxy/mtproxy.env <<EOF
MTPROXY_SECRET=$BACKEND_SECRET
MTPROXY_WORKERS=1
MTPROXY_MAX_CONNECTIONS=4096
MTPROXY_NAT_ARGS=
EOF
chown root:mtproxy /etc/mtproxy/mtproxy.env
chmod 0640 /etc/mtproxy/mtproxy.env

LOCAL_ADDRESS="$(ip -4 route get 149.154.175.50 2>/dev/null | sed -n 's/.*[[:space:]]src[[:space:]]\+\([0-9.]*\).*/\1/p' | head -1)"
PUBLIC_ADDRESS="$(curl --fail --silent --show-error --ipv4 --max-time 12 https://api.ipify.org 2>/dev/null | tr -d '[:space:]' || true)"
if [ -n "$LOCAL_ADDRESS" ] && [ -n "$PUBLIC_ADDRESS" ] && [ "$LOCAL_ADDRESS" != "$PUBLIC_ADDRESS" ]; then
  sed -i "s#^MTPROXY_NAT_ARGS=.*#MTPROXY_NAT_ARGS=--nat-info $LOCAL_ADDRESS:$PUBLIC_ADDRESS#" /etc/mtproxy/mtproxy.env
fi

log "installing isolated systemd units"
install -m 0644 "$SOURCE_DIR/deploy/tproxy-server.service" /etc/systemd/system/tproxy-server.service
install -m 0644 "$SOURCE_DIR/deploy/mtproxy.service" /etc/systemd/system/mtproxy.service
install -m 0644 "$SOURCE_DIR/deploy/tproxy-firewall.service" /etc/systemd/system/tproxy-firewall.service
install -m 0644 "$SOURCE_DIR/deploy/refresh-mtproxy-config.service" /etc/systemd/system/refresh-mtproxy-config.service
install -m 0644 "$SOURCE_DIR/deploy/refresh-mtproxy-config.timer" /etc/systemd/system/refresh-mtproxy-config.timer
install -m 0644 "$SOURCE_DIR/deploy/firewall.nft" "$STATE_DIR/firewall.nft"
install -m 0755 "$SOURCE_DIR/deploy/refresh-mtproxy-config.sh" /usr/local/sbin/refresh-mtproxy-config

log "adding nginx loopback mirror and hidden relay route"
cat > /etc/nginx/conf.d/tproxy-web.conf <<EOF
map \$http_upgrade \$tproxy_connection_upgrade {
    default upgrade;
    ''      "";
}

upstream tproxy_relay {
    server 127.0.0.1:$RELAY_PORT;
    keepalive 32;
}

server {
    listen 127.0.0.1:$PUBLIC_MIRROR_PORT;
    server_name _;
    root /var/www/cdn-servgo;
    index index.html;
    charset utf-8;

    location / {
        try_files \$uri \$uri/ /index.html;
    }
}
EOF

python3 - "$NGINX_SITE" "$BASE_PATH" <<'PY'
from pathlib import Path
import sys

path=Path(sys.argv[1])
base=sys.argv[2]
text=path.read_text()
marker='    location / {\n        try_files $uri $uri/ /index.html;\n    }'
if marker not in text:
    raise SystemExit('expected cdn.servgo.ru static location not found')
if 'proxy_pass http://tproxy_relay;' in text:
    raise SystemExit('tproxy route already present unexpectedly')
block=f'''    # Telegram WEB proxy pilot: hidden Mode-B prefix.
    location ^~ /{base}/ {{
        client_max_body_size 4m;
        proxy_pass http://tproxy_relay;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $tproxy_connection_upgrade;

        proxy_read_timeout 90s;
        proxy_send_timeout 90s;
        proxy_buffering off;
        proxy_request_buffering off;
        access_log off;
    }}

'''
text=text.replace(marker, block+marker, 1)
path.write_text(text)
PY

nginx -t

log "validating relay config before start"
/usr/local/bin/tproxy-server   -config "$STATE_DIR/config.json"   -profiles-file "$STATE_DIR/profiles.json"   -check

systemctl daemon-reload
systemctl enable --now tproxy-firewall.service
systemctl enable --now mtproxy.service
systemctl restart mtproxy.service
systemctl enable --now tproxy-server.service
systemctl enable --now refresh-mtproxy-config.timer

READY=""
for _ in $(seq 1 25); do
  if curl --fail --silent --output /dev/null "http://127.0.0.1:$ADMIN_PORT/readyz"; then
    READY=1
    break
  fi
  sleep 1
done
[ -n "$READY" ] || die "tproxy-server readiness failed"

sleep 2
systemctl is-active --quiet mtproxy.service || die "mtproxy service is not active"
DISCONNECTS="$(journalctl -u mtproxy.service --since -2min --no-pager | grep -c 'Disconnected from RPC Middle-End' || true)"
[ "$DISCONNECTS" -lt 10 ] || die "mtproxy middle-end is repeatedly disconnecting"

systemctl reload nginx

log "verifying unchanged public site"
curl --fail --silent --show-error --location --max-time 15   --output /tmp/tproxy-site-after.html "https://$HOSTNAME_PUBLIC/"
SITE_AFTER_SHA="$(sha256sum /tmp/tproxy-site-after.html | awk '{print $1}')"
rm -f /tmp/tproxy-site-after.html
[ "$SITE_BEFORE_SHA" = "$SITE_AFTER_SHA" ] || die "public site changed after deployment"

log "verifying unauthenticated prefix decoy"
ROOT_STATUS="$(curl --silent --output /dev/null --write-out '%{http_code}' "https://$HOSTNAME_PUBLIC/")"
PREFIX_STATUS="$(curl --silent --output /dev/null --write-out '%{http_code}' "https://$HOSTNAME_PUBLIC/$BASE_PATH/not-a-real-route")"
[ "$ROOT_STATUS" = "$PREFIX_STATUS" ] || die "prefix decoy response status differs from public site"

MARKED_SECRET="$({
  printf '\x70'
  printf "$(printf %s "$SECRET" | sed 's/../\\x&/g')"
} | base64 | tr '+/' '-_' | tr -d '=\n')"

cat > "$CLIENT_FILE" <<EOF
Telegram WEB proxy pilot
Server: $HOSTNAME_PUBLIC/$BASE_PATH
Secret: $MARKED_SECRET
Link: tg://webproxy?server=${HOSTNAME_PUBLIC}%2F${BASE_PATH}&secret=${MARKED_SECRET}
Upstream tproxy-server commit: $TPROXY_COMMIT
Deployed UTC: $(date -u +%FT%TZ)
EOF
chmod 0600 "$CLIENT_FILE"

cat > "$STATE_DIR/deployment-meta.txt" <<EOF
hostname=$HOSTNAME_PUBLIC
base_path=$BASE_PATH
tproxy_commit=$TPROXY_COMMIT
deployed_utc=$(date -u +%FT%TZ)
public_site_sha256=$SITE_AFTER_SHA
EOF
chown root:tproxy "$STATE_DIR/deployment-meta.txt"
chmod 0640 "$STATE_DIR/deployment-meta.txt"

trap - ERR
log "SUCCESS"
log "public site unchanged"
log "relay ready on loopback"
log "client data written to $CLIENT_FILE (not printed)"
