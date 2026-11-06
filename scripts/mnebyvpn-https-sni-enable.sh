#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
[[ "$(id -u)" == 0 ]] || exit 2
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -n 9 || { echo 'route lock unavailable'; exit 2; }
CERT=/etc/letsencrypt/live/mnebyvpn.site/fullchain.pem
KEY=/etc/letsencrypt/live/mnebyvpn.site/privkey.pem
test -s "$CERT" && test -s "$KEY" || { echo 'Trusted certificate missing'; exit 2; }
test "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8792/healthz)" = 200
if ss -H -lnt | awk '{print $4}' | grep -Eq ':18449$'; then
  if ! grep -Fq 'listen 127.0.0.1:18449 ssl;' /etc/nginx/sites-available/mnebyvpn-tls.conf 2>/dev/null; then
    echo 'Internal TLS port belongs to unrelated service'; exit 2
  fi
fi
mkdir -p /opt/mnebyvpn/backups
BACKUP="$(mktemp -d /opt/mnebyvpn/backups/nginx-site-XXXXXXXX)"
chmod 700 "$BACKUP"
MAP_PATH="$(python3 - <<'PY'
import pathlib,re
root=pathlib.Path('/etc/nginx')
pattern=re.compile(r'map\s+\$ssl_preread_server_name\s+\$stream_443_backend\s*\{')
candidates=[]
for file in root.rglob('*.conf'):
  if '/sites-enabled/' in str(file):continue
  try: content=file.read_text()
  except (OSError,UnicodeError):continue
  if pattern.search(content):candidates.append(file)
if len(candidates)!=1 or '/streams.d/' not in str(candidates[0]):
  raise SystemExit('Expected one original SNI map in streams.d')
source=candidates[0].read_text()
match=re.search(r'map\s+\$ssl_preread_server_name\s+\$stream_443_backend\s*\{([^{}]*)\}',source,re.S)
if not match or 'default' not in match.group(1):
  raise SystemExit('Unexpected SNI map structure')
if 'mnebyvpn.site' in match.group(1):
  for name in ['mnebyvpn.site','www.mnebyvpn.site']:
    if not re.search(r'^\s*'+re.escape(name)+r'\s+127\.0\.0\.1:18449\s*;',match.group(1),re.M):
      raise SystemExit('Existing domain route conflicts')
print(str(candidates[0]))
PY
)"
test -f "$MAP_PATH" || exit 2
cp -p "$MAP_PATH" "$BACKUP/original-stream.conf"
TLS=/etc/nginx/sites-available/mnebyvpn-tls.conf
if [[ -e "$TLS" ]]; then cp -p "$TLS" "$BACKUP/original-tls.conf"; fi
rollback() {
  echo 'Reverting only MNEBYVPN SNI route and HTTPS vhost'
  cp -p "$BACKUP/original-stream.conf" "$MAP_PATH"
  if [[ -f "$BACKUP/original-tls.conf" ]]; then
    cp -p "$BACKUP/original-tls.conf" "$TLS"
  else
    rm -f "$TLS" /etc/nginx/sites-enabled/mnebyvpn-tls.conf
  fi
  nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
}
trap 'rollback' ERR
cat > "$TLS" <<'CONF'
# Terminate TLS after the existing 443 stream SNI dispatcher.
# This server listens only on loopback; do not bind it to :443.
server {
    listen 127.0.0.1:18449 ssl;
    server_name mnebyvpn.site www.mnebyvpn.site;
    ssl_certificate /etc/letsencrypt/live/mnebyvpn.site/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mnebyvpn.site/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:mnebyvpn_site_ssl:2m;
    server_tokens off;
    client_max_body_size 128k;
    proxy_connect_timeout 4s;
    proxy_send_timeout 12s;
    proxy_read_timeout 12s;
    add_header Strict-Transport-Security "max-age=300" always;
    if ($host = www.mnebyvpn.site) {
        return 301 https://mnebyvpn.site$request_uri;
    }
    location / {
        proxy_pass http://127.0.0.1:8792;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header Connection "";
    }
}
CONF
ln -sfn "$TLS" /etc/nginx/sites-enabled/mnebyvpn-tls.conf
python3 - "$MAP_PATH" <<'PY'
import pathlib,re,sys,os,tempfile,shutil
path=pathlib.Path(sys.argv[1])
source=path.read_text()
pattern=re.compile(r'(map\s+\$ssl_preread_server_name\s+\$stream_443_backend\s*\{)([^{}]*)(\})',re.S)
found=pattern.search(source)
if not found:raise SystemExit('SNI map not found')
body=found.group(2)
if 'mnebyvpn.site' in body:
  print('sni_route_already_configured=yes')
else:
  new=found.group(1)+'\n    mnebyvpn.site 127.0.0.1:18449;\n    www.mnebyvpn.site 127.0.0.1:18449;'+body+found.group(3)
  modified=source[:found.start()]+new+source[found.end():]
  fd,tmp=tempfile.mkstemp(prefix='.mnebyvpn-map-',dir=str(path.parent))
  try:
    os.write(fd,modified.encode());os.close(fd)
    shutil.copymode(path,tmp)
    os.replace(tmp,path)
  finally:
    if os.path.exists(tmp):os.unlink(tmp)
  print('sni_route_added=yes')
PY
nginx -t
systemctl reload nginx
# Verify SNI routing with the public hostname, but on local loopback.
for i in $(seq 1 10); do
  if curl -fsS --max-time 6 --resolve mnebyvpn.site:443:127.0.0.1 \
     https://mnebyvpn.site/ -o /tmp/mnebyvpn-local-tls-smoke.html; then
    break
  fi
  sleep 1
done
grep -Fq 'MnebyVPN_bot' /tmp/mnebyvpn-local-tls-smoke.html
curl -fsS --max-time 6 --resolve mnebyvpn.site:443:127.0.0.1 \
  https://mnebyvpn.site/api/plans | python3 -c 'import json,sys; d=json.load(sys.stdin); assert not d["checkoutEnabled"] and not d["loginEnabled"]'
test "$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 7 --resolve mnebyvpn.site:443:127.0.0.1 https://mnebyvpn.site/auth/login)" = 503
trap - ERR
echo 'domain_tls_local_verify=true'
echo 'sni_existing_routes_preserved=true'
echo 'https_public_backend_read_only=true'
echo 'telegram_oidc=disabled'
echo 'checkout_enabled=false'
echo 'nginx_reload_success=true'
