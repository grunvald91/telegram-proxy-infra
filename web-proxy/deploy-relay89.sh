#!/usr/bin/env bash
set -euo pipefail
umask 077

: "${WEB_PROXY_SECRET:?WEB_PROXY_SECRET is required}"
TPROXY_HOSTNAME="${TPROXY_HOSTNAME:-cdn.servgo.ru}"
WEB_PROXY_BASE_PATH="${WEB_PROXY_BASE_PATH:-53wcvyyqhqse3u45}"
TPROXY_COMMIT="${TPROXY_COMMIT:-c8adb8b7c6b7fc46c12ae3acb68be9070c26a8e8}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "must run as root" >&2
  exit 1
fi
if [[ "$(uname -m)" != "x86_64" ]]; then
  echo "x86_64 required" >&2
  exit 1
fi
if [[ ! "$WEB_PROXY_SECRET" =~ ^([0-9a-f]{32}|dd[0-9a-f]{32})$ ]]; then
  echo "WEB_PROXY_SECRET must be 32 lowercase hex chars, optionally prefixed with dd" >&2
  exit 2
fi
if [[ ! "$TPROXY_HOSTNAME" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || [[ "$TPROXY_HOSTNAME" != *.* ]]; then
  echo "invalid hostname" >&2
  exit 2
fi
if [[ ! "$WEB_PROXY_BASE_PATH" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*(/[A-Za-z0-9][A-Za-z0-9_-]*)*$ ]]; then
  echo "invalid base path" >&2
  exit 2
fi

echo "Deploying isolated Telegram WEB proxy pilot"
echo "host=$TPROXY_HOSTNAME"
echo "base_path=$WEB_PROXY_BASE_PATH"
echo "upstream_commit=$TPROXY_COMMIT"
echo "secret=REDACTED"

CDN_SITE_LINK=/etc/nginx/sites-enabled/cdn-servgo
if [[ ! -e "$CDN_SITE_LINK" ]]; then
  echo "expected nginx site not found: $CDN_SITE_LINK" >&2
  exit 1
fi
CDN_SITE="$(readlink -f "$CDN_SITE_LINK")"

for port in 2398 8080 8081 8888 3000; do
  if ss -lntH "sport = :$port" | grep -q .; then
    case "$port" in
      2398|8888)
        systemctl is-active --quiet mtproxy.service || {
          echo "port $port is occupied by a non-pilot service" >&2
          ss -lntp "sport = :$port" >&2 || true
          exit 1
        }
        ;;
      8080|8081)
        systemctl is-active --quiet tproxy-server.service || {
          echo "port $port is occupied by a non-pilot service" >&2
          ss -lntp "sport = :$port" >&2 || true
          exit 1
        }
        ;;
      3000)
        if ! ss -lntp "sport = :3000" | grep -q nginx; then
          echo "port 3000 is occupied by a non-nginx service" >&2
          ss -lntp "sport = :3000" >&2 || true
          exit 1
        fi
        ;;
    esac
  fi
done

nginx -t >/dev/null
curl --fail --silent --show-error --location --max-time 15   --output /tmp/cdn-servgo.before.html "https://$TPROXY_HOSTNAME/"
before_hash="$(sha256sum /tmp/cdn-servgo.before.html | awk '{print $1}')"
rm -f /tmp/cdn-servgo.before.html
echo "public_site_before_sha256=$before_hash"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends   ca-certificates curl git nftables build-essential iproute2 libssl-dev util-linux zlib1g-dev

SRC=/opt/tproxy-server-src
if [[ -d "$SRC/.git" ]]; then
  git -C "$SRC" fetch -q --depth 1 origin "$TPROXY_COMMIT"
else
  rm -rf "$SRC"
  git clone -q --filter=blob:none --no-checkout https://github.com/telegramdesktop/tproxy-server.git "$SRC"
  git -C "$SRC" fetch -q --depth 1 origin "$TPROXY_COMMIT"
fi
git -C "$SRC" checkout -q --detach "$TPROXY_COMMIT"
test "$(git -C "$SRC" rev-parse HEAD)" = "$TPROXY_COMMIT"

# Build/install the stock official MTProxy backend using the upstream pinned recipe.
bash "$SRC/deploy/install-mtproxy.sh"

if ! id tproxy >/dev/null 2>&1; then
  useradd --system --home /nonexistent --shell /usr/sbin/nologin tproxy
fi

go_binary=
if command -v go >/dev/null 2>&1; then
  go_minor="$(go env GOVERSION 2>/dev/null | sed -E 's/^go1\.([0-9]+).*/\1/')"
  if [[ "$go_minor" =~ ^[0-9]+$ ]] && [[ "$go_minor" -ge 20 ]]; then
    go_binary="$(command -v go)"
  fi
fi
if [[ -z "$go_binary" ]]; then
  go_version=1.26.5
  go_checksum=5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053
  go_archive="$(mktemp /tmp/go-linux-amd64.XXXXXX.tar.gz)"
  go_directory="$(mktemp -d /tmp/go-linux-amd64.XXXXXX)"
  trap 'rm -f "$go_archive"; rm -rf "$go_directory"' EXIT
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2     --output "$go_archive" "https://go.dev/dl/go${go_version}.linux-amd64.tar.gz"
  test "$(sha256sum "$go_archive" | awk '{print $1}')" = "$go_checksum"
  tar -C "$go_directory" -xzf "$go_archive"
  if [[ ! -e "/opt/go${go_version}" ]]; then
    mv "$go_directory/go" "/opt/go${go_version}"
  fi
  rm -f "$go_archive"
  rm -rf "$go_directory"
  trap - EXIT
  go_binary="/opt/go${go_version}/bin/go"
fi

(
  cd "$SRC"
  "$go_binary" test ./...
  "$go_binary" build -trimpath -ldflags='-s -w' -o /usr/local/bin/tproxy-server ./cmd/tproxy-server
)
chown root:root /usr/local/bin/tproxy-server
chmod 0755 /usr/local/bin/tproxy-server

install -d -o root -g tproxy -m 0750 /etc/tproxy-server
bash "$SRC/deploy/ensure-token-key.sh"

cat > /etc/tproxy-server/config.json <<EOF
{
  "public_hostname": "$TPROXY_HOSTNAME",
  "base_path": "$WEB_PROXY_BASE_PATH",
  "listen": "127.0.0.1:8080",
  "admin_listen": "127.0.0.1:8081",
  "public_upstream": "http://127.0.0.1:3000",
  "token_key_file": "/etc/tproxy-server/token.key",
  "static_routes": "exact",
  "profiles_file": "/run/credentials/tproxy-server.service/profiles.json",
  "enable_pprof": false
}
EOF

cat > /etc/tproxy-server/profiles.json <<EOF
{"profiles":[{"name":"pilot-https","secret":"$WEB_PROXY_SECRET","backend":"127.0.0.1:2398","carrier_mode":"https"}]}
EOF
chown root:tproxy /etc/tproxy-server/config.json /etc/tproxy-server/profiles.json
chmod 0640 /etc/tproxy-server/config.json
chmod 0400 /etc/tproxy-server/profiles.json

backend_secret="$WEB_PROXY_SECRET"
if [[ "$backend_secret" == dd* ]] && [[ ${#backend_secret} -eq 34 ]]; then
  backend_secret="${backend_secret:2}"
fi

local_address="$(ip -4 route get 149.154.175.50 2>/dev/null | sed -n 's/.*[[:space:]]src[[:space:]]\+\([0-9.]\+\).*/\1/p' | head -n1)"
public_address="$(curl --fail --silent --show-error --ipv4 --max-time 15 https://api.ipify.org 2>/dev/null | tr -d '[:space:]' || true)"
mtproxy_nat_args=
if [[ -n "$local_address" && -n "$public_address" && "$local_address" != "$public_address" ]]; then
  mtproxy_nat_args="--nat-info $local_address:$public_address"
fi

install -d -o root -g mtproxy -m 0750 /etc/mtproxy
cat > /etc/mtproxy/mtproxy.env <<EOF
MTPROXY_SECRET=$backend_secret
MTPROXY_WORKERS=1
MTPROXY_MAX_CONNECTIONS=2048
MTPROXY_NAT_ARGS=$mtproxy_nat_args
EOF
chown root:mtproxy /etc/mtproxy/mtproxy.env
chmod 0640 /etc/mtproxy/mtproxy.env

install -m 0644 "$SRC/deploy/tproxy-server.service" /etc/systemd/system/tproxy-server.service
install -m 0644 "$SRC/deploy/mtproxy.service" /etc/systemd/system/mtproxy.service
install -m 0644 "$SRC/deploy/tproxy-firewall.service" /etc/systemd/system/tproxy-firewall.service
install -m 0644 "$SRC/deploy/refresh-mtproxy-config.service" /etc/systemd/system/refresh-mtproxy-config.service
install -m 0644 "$SRC/deploy/refresh-mtproxy-config.timer" /etc/systemd/system/refresh-mtproxy-config.timer
install -m 0644 "$SRC/deploy/firewall.nft" /etc/tproxy-server/firewall.nft
install -m 0755 "$SRC/deploy/refresh-mtproxy-config.sh" /usr/local/sbin/refresh-mtproxy-config

/usr/local/bin/tproxy-server   -config /etc/tproxy-server/config.json   -profiles-file /etc/tproxy-server/profiles.json   -check

systemctl daemon-reload
systemctl enable --now tproxy-firewall.service
systemctl enable --now mtproxy.service
systemctl restart mtproxy.service
systemctl enable --now tproxy-server.service
systemctl restart tproxy-server.service
systemctl enable --now refresh-mtproxy-config.timer

ready=
for _ in $(seq 1 30); do
  if curl --fail --silent --output /dev/null http://127.0.0.1:8081/readyz; then
    ready=1
    break
  fi
  sleep 1
done
if [[ -z "$ready" ]]; then
  echo "tproxy-server did not become ready; nginx left untouched" >&2
  systemctl --no-pager --full status mtproxy.service tproxy-server.service >&2 || true
  exit 1
fi

echo "relay_ready=yes"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="/root/proxy-backups/webproxy-$STAMP"
install -d -m 0700 "$BACKUP_DIR"
cp -a "$CDN_SITE" "$BACKUP_DIR/cdn-servgo.before"
[[ -e /etc/nginx/conf.d/tproxy-web-map.conf ]] && cp -a /etc/nginx/conf.d/tproxy-web-map.conf "$BACKUP_DIR/" || true
[[ -e /etc/nginx/conf.d/tproxy-web-public-mirror.conf ]] && cp -a /etc/nginx/conf.d/tproxy-web-public-mirror.conf "$BACKUP_DIR/" || true

rollback_nginx() {
  echo "Rolling back nginx WEB proxy integration" >&2
  cp -a "$BACKUP_DIR/cdn-servgo.before" "$CDN_SITE"
  rm -f /etc/nginx/conf.d/tproxy-web-map.conf /etc/nginx/conf.d/tproxy-web-public-mirror.conf
  nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
}
trap rollback_nginx ERR

cat > /etc/nginx/conf.d/tproxy-web-map.conf <<'EOF'
# Telegram WEB proxy carrier upgrade handling.
map $http_upgrade $tproxy_connection_upgrade {
    default upgrade;
    ''      "";
}
EOF

cat > /etc/nginx/conf.d/tproxy-web-public-mirror.conf <<'EOF'
# Loopback mirror of the real cdn.servgo.ru static site for unauthenticated
# requests that reach the WEB proxy base path.
server {
    listen 127.0.0.1:3000;
    server_name _;
    root /var/www/cdn-servgo;
    index index.html;
    charset utf-8;
    access_log off;

    location / {
        try_files $uri $uri/ /index.html;
    }
}
EOF

export CDN_SITE WEB_PROXY_BASE_PATH
python3 - <<'PY'
from pathlib import Path
import os

p = Path(os.environ["CDN_SITE"])
base = os.environ["WEB_PROXY_BASE_PATH"]
text = p.read_text()
begin = "    # BEGIN GRUNVALD WEB PROXY PILOT\n"
end = "    # END GRUNVALD WEB PROXY PILOT\n"

if begin in text:
    a = text.index(begin)
    b = text.index(end, a) + len(end)
    text = text[:a] + text[b:]

anchor = text.find("listen 127.0.0.1:4453 ssl http2;")
if anchor < 0:
    raise SystemExit("cdn.servgo.ru TLS listener not found")
loc = text.find("    location / {", anchor)
if loc < 0:
    raise SystemExit("cdn.servgo.ru fallback location not found")

snippet = f"""    # BEGIN GRUNVALD WEB PROXY PILOT
    location ^~ /{base}/ {{
        client_max_body_size 4m;
        proxy_pass http://127.0.0.1:8080;
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
    # END GRUNVALD WEB PROXY PILOT

"""
text = text[:loc] + snippet + text[loc:]
p.write_text(text)
PY

nginx -t
systemctl reload nginx
systemctl is-active --quiet nginx

curl --fail --silent --show-error --location --max-time 15   --output /tmp/cdn-servgo.after.html "https://$TPROXY_HOSTNAME/"
after_hash="$(sha256sum /tmp/cdn-servgo.after.html | awk '{print $1}')"
rm -f /tmp/cdn-servgo.after.html
if [[ "$after_hash" != "$before_hash" ]]; then
  echo "public site body changed unexpectedly" >&2
  exit 1
fi

curl --fail --silent --show-error --location --max-time 15   --output /tmp/cdn-servgo.prefix.html   "https://$TPROXY_HOSTNAME/$WEB_PROXY_BASE_PATH/probe-no-capability"
prefix_hash="$(sha256sum /tmp/cdn-servgo.prefix.html | awk '{print $1}')"
rm -f /tmp/cdn-servgo.prefix.html
if [[ "$prefix_hash" != "$before_hash" ]]; then
  echo "unauthenticated prefix response differs from public site body" >&2
  exit 1
fi

curl --fail --silent --output /dev/null http://127.0.0.1:8081/healthz
curl --fail --silent --output /dev/null http://127.0.0.1:8081/readyz

# Verify backend ports are protected from non-loopback interfaces.
nft list table inet tproxy_backend >/dev/null
if ! nft list table inet tproxy_backend | grep -q '2398'; then
  echo "backend firewall does not mention port 2398" >&2
  exit 1
fi

trap - ERR
echo "public_site_unchanged=yes"
echo "unauthenticated_prefix_matches_site=yes"
echo "backend_firewall_present=yes"
echo "deployment_success=yes"
echo "client_server=$TPROXY_HOSTNAME/$WEB_PROXY_BASE_PATH"
echo "client_secret=REDACTED"
