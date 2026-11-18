#!/usr/bin/env bash
# Enable Smart DNS Apple/DoT website issuance and Telegram WebSocket proxy routes
# on 188.120.254.223 after verifying live DoT sidecar, DB migrations/grants, and
# promoting the tested public website container with rollback protection.
set -Eeuo pipefail
umask 077

SHA="${1:?CI verified main SHA required}"
PROMOTE_SCRIPT="${2:?Auto-web promote script path required}"
ROOT=/opt/mnebyvpn
PUBLIC="$ROOT/public"
ENV_FILE="$PUBLIC/web.env"
PROXY_ENV="$PUBLIC/web-proxy.env"
PG_CONTAINER=mnebyvpn-stage-postgres
DNS_CONTAINER=mnebydns-personal-dot-private
WORKER_CONTAINER=mnebyvpn-vpn-worker

[[ "$(id -u)" -eq 0 && "$SHA" =~ ^[a-f0-9]{40}$ ]] || { echo 'Invalid arguments or privileges'; exit 2; }
test -s "$PROMOTE_SCRIPT" && bash -n "$PROMOTE_SCRIPT"
test -s "$ENV_FILE"
test "$(cat "$PUBLIC/active_sha")" = "$SHA" || {
  echo "active_sha_mismatch expected=$SHA actual=$(cat "$PUBLIC/active_sha" 2>/dev/null || echo missing)"
  exit 2
}
docker image inspect "mnebyvpn-stage-web:$SHA" >/dev/null
for c in "$PG_CONTAINER" "$DNS_CONTAINER" mnebyvpn-public-web "$WORKER_CONTAINER"; do
  test "$(docker inspect -f '{{.State.Running}}' "$c")" = true || {
    echo "required_container_not_running=$c"; exit 2
  }
done

test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 4 http://127.0.0.1:8859/readyz)" = 200 || {
  echo 'personal_dot_private_readyz_failed=true'; exit 2
}

RAW_ROUTES="$(cat)"
CANONICAL_ROUTES="$(RAW_ROUTES="$RAW_ROUTES" python3 - <<'PY'
import json, os, re, sys

raw = os.environ.get('RAW_ROUTES', '').strip()
if not raw:
    sys.exit('Empty WebSocket proxy routes payload')
data = json.loads(raw)
if not isinstance(data, list) or not (1 <= len(data) <= 2):
    sys.exit('Routes payload must have 1 or 2 entries')
server_re = re.compile(r'^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?/[A-Za-z0-9_-]{4,64}$', re.I)
secret_re = re.compile(r'^(?:dd)?[a-f0-9]{32}$', re.I)
seen_routes, seen_servers = set(), set()
cleaned = []
for entry in data:
    if not isinstance(entry, dict) or sorted(entry.keys()) != ['route', 'secret', 'server']:
        sys.exit('Invalid WebSocket proxy route object keys')
    route = entry['route']
    server = entry['server']
    secret = entry['secret']
    if route not in ('ru', 'direct'):
        sys.exit(f'Unsupported route: {route!r}')
    if not isinstance(server, str) or not server_re.match(server) or '..' in server or server.startswith(('127.0.0.1/', 'localhost/')):
        sys.exit('Invalid WebSocket proxy server format')
    if not isinstance(secret, str) or not secret_re.match(secret):
        sys.exit('Invalid WebSocket proxy secret format')
    if route in seen_routes or server in seen_servers:
        sys.exit('Duplicate route or server in WebSocket proxy payload')
    seen_routes.add(route)
    seen_servers.add(server)
    cleaned.append({'route': route, 'server': server, 'secret': secret.lower()})
cleaned.sort(key=lambda item: 0 if item['route'] == 'ru' else 1)
print(json.dumps(cleaned, separators=(',', ':'), ensure_ascii=True))
PY
)"
test -n "$CANONICAL_ROUTES"

psql_exec() {
  docker exec -i "$PG_CONTAINER" psql -At -X -v ON_ERROR_STOP=1 -U mnebyvpn_stage -d mnebyvpn_stage "$@"
}

for mig in 0125_website_personal_dns_apple.sql 0132_yookassa_and_3in1_catalog.sql 0134_stars_ratio_and_3in1_bot.sql; do
  has_mig="$(psql_exec -c "SELECT count(*) FROM deployment_schema_migrations WHERE file_name = '$mig';")"
  test "${has_mig:-0}" -ge 1 || { echo "missing_migration=$mig"; exit 2; }
done

plan_count="$(psql_exec -c "SELECT count(*) FROM billing_plans WHERE enabled;")"
test "$plan_count" = 12 || { echo "unexpected_enabled_plans=$plan_count"; exit 2; }

psql_exec <<'SQL'
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mnebyvpn_site_auth') THEN
    EXECUTE 'GRANT EXECUTE ON FUNCTION website_personal_dns_status(text, uuid), website_issue_personal_dns_credential(text, uuid, text, text), website_rotate_personal_dns_credential(text, uuid, bigint, text, text) TO mnebyvpn_site_auth';
  END IF;
END
$$;
SQL

if [ "$(psql_exec -c "SELECT count(*) FROM pg_roles WHERE rolname = 'mnebyvpn_site_auth';")" = 1 ]; then
  for sig in \
    'website_personal_dns_status(text, uuid)' \
    'website_issue_personal_dns_credential(text, uuid, text, text)' \
    'website_rotate_personal_dns_credential(text, uuid, bigint, text, text)'; do
    priv="$(psql_exec -c "SELECT has_function_privilege('mnebyvpn_site_auth', '$sig', 'EXECUTE');")"
    test "$priv" = t || { echo "missing_site_auth_execute=$sig"; exit 2; }
  done
  echo 'site_auth_personal_dns_grants=verified'
fi

exec 7>/run/lock/mnebyvpn-commercial-activation.lock
flock -w 90 7

ENV_BACKUP="$(mktemp "$PUBLIC/web.env.pre-dnsproxy.XXXXXXXX")"
cp -p "$ENV_FILE" "$ENV_BACKUP"
chmod 600 "$ENV_BACKUP"
PROXY_HAD_PREV=no
PROXY_BACKUP=''
if [ -f "$PROXY_ENV" ]; then
  PROXY_HAD_PREV=yes
  PROXY_BACKUP="$(mktemp "$PUBLIC/web-proxy.env.pre.XXXXXXXX")"
  cp -p "$PROXY_ENV" "$PROXY_BACKUP"
  chmod 600 "$PROXY_BACKUP"
fi

restore() {
  result="$?"
  trap - ERR
  set +e
  if [ "$result" -ne 0 ]; then
    echo 'dns_wsproxy_activation=rolling_back'
    cp -p "$ENV_BACKUP" "$ENV_FILE"
    if [ "$PROXY_HAD_PREV" = yes ] && [ -n "$PROXY_BACKUP" ]; then
      cp -p "$PROXY_BACKUP" "$PROXY_ENV"
    else
      rm -f "$PROXY_ENV"
    fi
    bash "$PROMOTE_SCRIPT" "$SHA" >/dev/null 2>&1
    echo 'dns_wsproxy_config_restored=true'
  fi
  rm -f "$ENV_BACKUP" "$PROXY_BACKUP"
  exit "$result"
}
trap restore ERR

CANONICAL_ROUTES="$CANONICAL_ROUTES" python3 - "$PROXY_ENV" "$ENV_FILE" <<'PY'
import os, pathlib, sys, tempfile

proxy_path = pathlib.Path(sys.argv[1])
env_path = pathlib.Path(sys.argv[2])

routes_json = os.environ['CANONICAL_ROUTES']
if '\n' in routes_json or '\r' in routes_json:
    raise RuntimeError('Routes JSON must be single-line')

proxy_lines = [
    'WEB_TELEGRAM_WS_PROXY_ENABLED=yes',
    f'WEB_TELEGRAM_WS_PROXY_ROUTES_JSON={routes_json}',
]
fd, tmp_proxy = tempfile.mkstemp(dir=proxy_path.parent, prefix='.web-proxy.env.')
try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write('\n'.join(proxy_lines) + '\n')
    os.replace(tmp_proxy, proxy_path)
except Exception:
    if os.path.exists(tmp_proxy):
        os.unlink(tmp_proxy)
    raise

updates = {
    'WEB_PERSONAL_DNS_APPLE_ENABLED': 'yes',
    'WEB_PERSONAL_DNS_DOT_E2E_VERIFIED': 'yes',
}
existing = env_path.read_text(encoding='utf-8').splitlines()
out = []
seen = set()
for line in existing:
    if '=' in line and not line.lstrip().startswith('#'):
        k = line.split('=', 1)[0].strip()
        if k in updates:
            if k not in seen:
                out.append(f'{k}={updates[k]}')
                seen.add(k)
            continue
    out.append(line)
for k, v in updates.items():
    if k not in seen:
        out.append(f'{k}={v}')
fd2, tmp_env = tempfile.mkstemp(dir=env_path.parent, prefix='.web.env.')
try:
    os.fchmod(fd2, 0o600)
    with os.fdopen(fd2, 'w', encoding='utf-8') as f:
        f.write('\n'.join(out) + '\n')
    os.replace(tmp_env, env_path)
except Exception:
    if os.path.exists(tmp_env):
        os.unlink(tmp_env)
    raise
PY

chmod 600 "$PROXY_ENV" "$ENV_FILE"
bash "$PROMOTE_SCRIPT" "$SHA"

# Verify live public container flags and fail-closed HTTP contracts without printing secrets
for expected in \
  'WEB_TELEGRAM_WS_PROXY_ENABLED=yes' \
  'WEB_PERSONAL_DNS_APPLE_ENABLED=yes' \
  'WEB_PERSONAL_DNS_DOT_E2E_VERIFIED=yes'; do
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' mnebyvpn-public-web | grep -Fxq "$expected" || {
    echo "missing_web_env=$expected"; false
  }
done
docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$WORKER_CONTAINER" | grep -Fxq 'MNEBYDNS_SMART_DNS_WORKER=enabled' || {
  echo 'missing_worker_env=MNEBYDNS_SMART_DNS_WORKER'; false
}
test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 4 http://127.0.0.1:8794/readyz)" = 200

test "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -X POST -H 'Content-Type: application/json' -H 'Origin: https://mnebyvpn.site' -d '{}' http://127.0.0.1:8792/api/dns/personal/credentials)" = 401
test "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8792/api/telegram-proxy-bonus)" = 401

curl -fsS --max-time 5 http://127.0.0.1:8792/ | python3 -c '
import sys
html = sys.stdin.read()
assert "id=\"journey-order-switch\"" in html, "missing checkout switcher"
assert "footer-seller" not in html, "footer-seller still present"
assert "745214444705" not in html, "INN still present on home page"
'

for page in /terms /privacy /agreement; do
  curl -fsS --max-time 5 "http://127.0.0.1:8792$page" | python3 -c '
import re, sys
page = sys.argv[1]
html = sys.stdin.read()
footer = re.search(r"<footer[\s\S]*?</footer>", html)
assert footer and "745214444705" not in footer.group(0), "INN leaked into footer on " + page
assert "745214444705" in html, "Legal body seller details missing on " + page
' "$page"
done

rm -f "$ENV_BACKUP" "$PROXY_BACKUP"
trap - ERR

echo "dns_wsproxy_enabled=true"
echo "web_sha=$SHA"
echo "personal_dns_apple_dot=enabled"
echo "telegram_ws_proxy=enabled"
echo "smart_dns_worker=enabled"
