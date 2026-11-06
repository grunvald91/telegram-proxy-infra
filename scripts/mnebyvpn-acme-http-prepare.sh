#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
[[ "$(id -u)" == 0 ]] || exit 2
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -n 9 || { echo 'route lock unavailable'; exit 2; }
test "$(nginx -t >/dev/null 2>&1; echo $?)" = 0
test "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8792/healthz)" = 200
if ss -H -lnt | awk '{print $4}' | grep -Eq ':18449$'; then
  if ! grep -Fq 'listen 127.0.0.1:18449 ssl;' /etc/nginx/sites-available/mnebyvpn-tls.conf 2>/dev/null; then
    echo '18449 occupied by existing component'; exit 2
  fi
fi
test ! -e /etc/nginx/sites-enabled/mnebyvpn-http.conf || \
  test "$(readlink /etc/nginx/sites-enabled/mnebyvpn-http.conf)" = "/etc/nginx/sites-available/mnebyvpn-http.conf"
mkdir -p /var/www/mnebyvpn-acme/.well-known/acme-challenge
chmod 755 /var/www/mnebyvpn-acme /var/www/mnebyvpn-acme/.well-known /var/www/mnebyvpn-acme/.well-known/acme-challenge
cat > /etc/nginx/sites-available/mnebyvpn-http.conf <<'CONF'
# Dedicated ACME HTTP-only host. No existing HTTP/SNI services changed.
server {
    listen 80;
    server_name mnebyvpn.site www.mnebyvpn.site;
    access_log off;
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/mnebyvpn-acme;
        default_type text/plain;
        try_files $uri =404;
    }
    location / {
        return 301 https://mnebyvpn.site$request_uri;
    }
}
CONF
ln -sfn /etc/nginx/sites-available/mnebyvpn-http.conf /etc/nginx/sites-enabled/mnebyvpn-http.conf
if ! nginx -t >/dev/null 2>&1; then
  rm -f /etc/nginx/sites-enabled/mnebyvpn-http.conf
  echo 'Refused unsafe Nginx HTTP route'; exit 2
fi
systemctl reload nginx
probe_name="mnebyvpn-$(openssl rand -hex 12)"
probe_content="valid-mnebyvpn-challenge-$(openssl rand -hex 16)"
printf '%s\n' "$probe_content" > "/var/www/mnebyvpn-acme/.well-known/acme-challenge/$probe_name"
chmod 644 "/var/www/mnebyvpn-acme/.well-known/acme-challenge/$probe_name"
for domain in mnebyvpn.site www.mnebyvpn.site; do
  actual="$(curl -fsS --max-time 5 -H "Host: $domain" "http://127.0.0.1/.well-known/acme-challenge/$probe_name")"
  [[ "$actual" == "$probe_content" ]] || { echo 'Local challenge mismatch'; exit 2; }
done
echo "acme_probe_path=/.well-known/acme-challenge/$probe_name"
echo "acme_probe_content=$probe_content"
echo 'nginx_http_route_ready=true'
echo 'no_tls_map_changes=true'
