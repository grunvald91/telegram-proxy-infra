#!/usr/bin/env bash
# Owner-only Telemt reconciliation on RU188, over verified Unix SSH forwarding.
# Existing customer profiles, Telemt config, nginx, firewall and DNS unchanged.
set -Eeuo pipefail
umask 077
test "$(id -u)" -eq 0
EXPECTED=c264f2a040bf5be2590bf36fb48be6c17436bdac
ROOT=/opt/mnebyvpn
private=/etc/mnebyvpn-owner-mtproxy
botenv="$ROOT/bot/web.env"
worker="$private/worker.env"
image="mnebyvpn-stage-web:$EXPECTED"
container=mnebyvpn-dns-mtproxy-bonus-worker
promoter=/tmp/mnebyvpn-owner-mtproxy-bot-promote.sh
socket=/run/mnebyvpn-owner-mtproxy/telemt.sock
lock=/run/lock/mnebyvpn-owner-mtproxy-worker.lock
exec 9>"$lock"
flock -w 60 9
test "$(cat "$ROOT/staging/active_sha")" = "$EXPECTED"
test "$(docker inspect --format '{{.Config.Image}}' mnebyvpn-bot-info)" = "$image"
docker image inspect "$image" >/dev/null
test -r "$ROOT/releases/$EXPECTED/apps/service/src/dns-mtproxy-bonus-worker.ts"
test -r "$ROOT/releases/$EXPECTED/packages/web/src/telegram-proxy-unix-transport.ts"
test -s "$botenv" && test -s "$promoter"
test "$(stat -c '%a' "$botenv")" = 600
grep -Fxq 'MNEBYVPN_OFFLINE_SALES_ENABLED=yes' "$botenv"
test "$(docker inspect --format '{{.State.Running}}' mnebyvpn-stage-postgres)" = true
systemctl is-active --quiet mnebyvpn-owner-telemt-tunnel
test -S "$socket"
test "$(stat -c '%u:%g:%a' "$socket")" = '13096:13096:600'
setpriv --reuid=13096 --regid=13096 --clear-groups \
  curl --noproxy '*' --unix-socket "$socket" -fsS --max-time 6 \
  http://localhost/v1/system/info |
  python3 -c 'import json,sys;assert json.load(sys.stdin).get("ok") is True'
# Guard: do not automatically touch existing paid/proxy customers on rollout.
num_sales="$(docker exec mnebyvpn-stage-postgres psql -qAtX -v ON_ERROR_STOP=1 \
  -U mnebyvpn_stage -d mnebyvpn_stage -c 'SELECT count(*) FROM manual_sales')"
num_proxy="$(docker exec mnebyvpn-stage-postgres psql -qAtX -v ON_ERROR_STOP=1 \
  -U mnebyvpn_stage -d mnebyvpn_stage -c 'SELECT count(*) FROM dns_mtproxy_bonus_credentials')"
[[ "$num_sales" == 0 && "$num_proxy" == 0 ]] || {
  echo 'owner_proxy_first_release_requires_empty_ledger=true';exit 2;
}
if docker container inspect "$container" >/dev/null 2>&1; then
  test "$(docker inspect --format '{{.State.Running}}' "$container")" = true
  test "$(docker inspect --format '{{.Config.Image}}' "$container")" = "$image"
  test "$(docker inspect --format '{{.Config.User}}' "$container")" = '13096:13096'
  test -s "$worker"
  current_key="$(sed -n 's/^WEB_DNS_MT_PROXY_BONUS_KEY=//p' "$worker")"
  test "$(sed -n 's/^WEB_DNS_MT_PROXY_BONUS_KEY=//p' "$botenv")" = "$current_key"
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' mnebyvpn-bot-info |
    grep -Eq '^WEB_DNS_MT_PROXY_BONUS_KEY=[a-f0-9]{64}
fi
install -d -m 0700 "$private"
existing_key="$(sed -n 's/^WEB_DNS_MT_PROXY_BONUS_KEY=//p' "$botenv")"
if [[ -n "$existing_key" ]]; then
  [[ "$existing_key" =~ ^[a-f0-9]{64}$ ]] || exit 2
fi
if [[ ! -e "$worker" ]]; then
  role_exists="$(docker exec mnebyvpn-stage-postgres psql -qAtX -v ON_ERROR_STOP=1 \
    -U mnebyvpn_stage -d mnebyvpn_stage \
    -c "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='mnebyvpn_owner_telemt')")"
  [[ "$role_exists" == f ]] || {
    echo 'owner_telemt_role_exists_without_private_config=true';exit 2;
  }
  dbpass="$(openssl rand -hex 24)"
  key="$existing_key"
  if [[ -z "$key" ]]; then key="$(openssl rand -hex 32)"; fi
  dummy="$(openssl rand -hex 24)"
  next="$(mktemp "$private/.worker-env.XXXXXXXX")"
  chmod 600 "$next"
  {
    printf 'MNEBYVPN_ENV=production\n'
    printf 'DATABASE_URL=postgresql://mnebyvpn_owner_telemt:%s@127.0.0.1:5432/mnebyvpn_stage\n' "$dbpass"
    printf 'WEB_DNS_MT_PROXY_BONUS_KEY=%s\n' "$key"
    printf 'DNS_MT_PROXY_BONUS_WORKER=enabled\n'
    printf 'DNS_MT_PROXY_OWNER_ONLY=yes\n'
    printf 'DNS_MT_PROXY_TLS_DOMAIN=xapi.ozon.ru\n'
    printf 'DNS_MT_PROXY_TELEMT_AUTH=Bearer %s\n' "$dummy"
    printf 'DNS_MT_PROXY_TELEMT_SOCKET=/run/mnebyvpn-owner-mtproxy/telemt.sock\n'
  } > "$next"
  mv -f "$next" "$worker"
else
  test "$(stat -c '%a' "$worker")" = 600
  key="$(sed -n 's/^WEB_DNS_MT_PROXY_BONUS_KEY=//p' "$worker")"
  [[ "$key" =~ ^[a-f0-9]{64}$ ]]
  if [[ -n "$existing_key" ]]; then test "$key" = "$existing_key";fi
fi
dbpass="$(python3 - "$worker" <<'PY'
from urllib.parse import urlsplit
from pathlib import Path
import re,sys
env=dict(line.split('=',1) for line in Path(sys.argv[1]).read_text().splitlines() if '=' in line)
url=urlsplit(env.get('DATABASE_URL',''))
assert url.username=='mnebyvpn_owner_telemt' and url.hostname=='127.0.0.1'
assert url.port==5432 and url.path=='/mnebyvpn_stage'
assert re.fullmatch('[a-f0-9]{48}',url.password or '')
assert env.get('DNS_MT_PROXY_OWNER_ONLY')=='yes'
assert env.get('DNS_MT_PROXY_BONUS_WORKER')=='enabled'
assert env.get('DNS_MT_PROXY_TELEMT_SOCKET')=='/run/mnebyvpn-owner-mtproxy/telemt.sock'
assert re.fullmatch('[a-f0-9]{64}',env.get('WEB_DNS_MT_PROXY_BONUS_KEY',''))
print(url.password)
PY
)"
role_exists="$(docker exec mnebyvpn-stage-postgres psql -qAtX -v ON_ERROR_STOP=1 \
  -U mnebyvpn_stage -d mnebyvpn_stage \
  -c "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='mnebyvpn_owner_telemt')")"
if [[ "$role_exists" == f ]]; then
  # One narrowly privileged role; no access to accounts, payments, other apps,
  # or mutations of customer entitlements or orders.
  docker exec -i mnebyvpn-stage-postgres psql -q -v ON_ERROR_STOP=1 \
    -U mnebyvpn_stage -d mnebyvpn_stage >/dev/null <<SQL
BEGIN;
CREATE ROLE mnebyvpn_owner_telemt LOGIN NOINHERIT CONNECTION LIMIT 2 PASSWORD '$dbpass';
GRANT CONNECT ON DATABASE mnebyvpn_stage TO mnebyvpn_owner_telemt;
GRANT USAGE ON SCHEMA public TO mnebyvpn_owner_telemt;
GRANT SELECT (id,account_id,source_order_id,product,state,starts_at,expires_at)
  ON public.entitlements TO mnebyvpn_owner_telemt;
GRANT SELECT (id,account_id,state)
  ON public.orders TO mnebyvpn_owner_telemt;
GRANT SELECT (order_id)
  ON public.manual_sales TO mnebyvpn_owner_telemt;
GRANT SELECT,INSERT,UPDATE
  ON public.dns_mtproxy_bonus_credentials TO mnebyvpn_owner_telemt;
COMMIT;
SQL
fi
# Validate password and the minimum DB scope; never display the URI or key.
test "$(docker exec -e PGPASSWORD="$dbpass" mnebyvpn-stage-postgres \
    psql -h 127.0.0.1 -qAtX -v ON_ERROR_STOP=1 -U mnebyvpn_owner_telemt \
      -d mnebyvpn_stage -c 'SELECT count(*) FROM manual_sales')" = 0
test "$(docker exec -e PGPASSWORD="$dbpass" mnebyvpn-stage-postgres \
    psql -h 127.0.0.1 -qAtX -v ON_ERROR_STOP=1 -U mnebyvpn_owner_telemt \
      -d mnebyvpn_stage -c 'SELECT count(*) FROM dns_mtproxy_bonus_credentials')" = 0
echo 'owner_telemt_least_privilege_db_role=verified'
docker run -d --name "$container" --network host \
  --user 13096:13096 --read-only --tmpfs /tmp:rw,nosuid,nodev,size=8m \
  --mount type=bind,src=/run/mnebyvpn-owner-mtproxy,dst=/run/mnebyvpn-owner-mtproxy,readonly \
  --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 \
  --memory 160m --cpus 0.35 --restart unless-stopped \
  --env-file "$worker" --entrypoint node "$image" \
  --experimental-strip-types apps/service/src/dns-mtproxy-bonus-worker.ts >/dev/null
# A fresh worker has no manual customers: it must remain healthy without
# creating or changing any existing Telemt profiles.
sleep 8
test "$(docker inspect --format '{{.State.Running}}' "$container")" = true
test "$(docker inspect --format '{{.State.RestartCount}}' "$container")" = 0
test "$(docker inspect --format '{{.Config.User}}' "$container")" = '13096:13096'
num_after="$(docker exec mnebyvpn-stage-postgres psql -qAtX -v ON_ERROR_STOP=1 \
  -U mnebyvpn_stage -d mnebyvpn_stage -c 'SELECT count(*) FROM dns_mtproxy_bonus_credentials')"
[[ "$num_after" == 0 ]] || { echo 'unexpected_proxy_record_creation=true';exit 2; }
echo 'owner_mtproxy_worker=running_private_only'
# Bot needs the SAME key for later verified owner-only link retrieval.
# Never enable either public or owner delivery release flags at this stage.
if [[ -z "$existing_key" ]]; then
  test ! -e "$ROOT/bot/web.env.before-owner-telemt-key"
  cp -p "$botenv" "$ROOT/bot/web.env.before-owner-telemt-key"
  restore_bot_env(){
    code=$?
    trap - ERR
    cp -p "$ROOT/bot/web.env.before-owner-telemt-key" "$botenv" || true
    bash "$promoter" "$EXPECTED" || echo 'bot_env_manual_rollback_required=true'
    exit "$code"
  }
  trap restore_bot_env ERR
  tmp="$(mktemp "$ROOT/bot/.telemt-key.XXXXXXXX")"
  cp -p "$botenv" "$tmp"
  printf '\nWEB_DNS_MT_PROXY_BONUS_KEY=%s\n' "$key" >> "$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$botenv"
  bash "$promoter" "$EXPECTED"
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' mnebyvpn-bot-info |
    grep -Eq '^WEB_DNS_MT_PROXY_BONUS_KEY=[a-f0-9]{64}$'
  test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' \
    --max-time 5 http://127.0.0.1:8793/readyz)" = 200
  trap - ERR
  echo 'bot_owner_mtproxy_decryption_key=installed_private'
else
  echo 'bot_owner_mtproxy_decryption_key=existing_private'
fi
echo 'owner_mtproxy_public_delivery_flags=unchanged'
echo 'owner_mtproxy_real_customer_links=not_issued'

  echo 'owner_mtproxy_worker=already_running'
  exit 0
fi
install -d -m 0700 "$private"
existing_key="$(sed -n 's/^WEB_DNS_MT_PROXY_BONUS_KEY=//p' "$botenv")"
if [[ -n "$existing_key" ]]; then
  [[ "$existing_key" =~ ^[a-f0-9]{64}$ ]] || exit 2
fi
if [[ ! -e "$worker" ]]; then
  role_exists="$(docker exec mnebyvpn-stage-postgres psql -qAtX -v ON_ERROR_STOP=1 \
    -U mnebyvpn_stage -d mnebyvpn_stage \
    -c "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='mnebyvpn_owner_telemt')")"
  [[ "$role_exists" == f ]] || {
    echo 'owner_telemt_role_exists_without_private_config=true';exit 2;
  }
  dbpass="$(openssl rand -hex 24)"
  key="$existing_key"
  if [[ -z "$key" ]]; then key="$(openssl rand -hex 32)"; fi
  dummy="$(openssl rand -hex 24)"
  next="$(mktemp "$private/.worker-env.XXXXXXXX")"
  chmod 600 "$next"
  {
    printf 'MNEBYVPN_ENV=production\n'
    printf 'DATABASE_URL=postgresql://mnebyvpn_owner_telemt:%s@127.0.0.1:5432/mnebyvpn_stage\n' "$dbpass"
    printf 'WEB_DNS_MT_PROXY_BONUS_KEY=%s\n' "$key"
    printf 'DNS_MT_PROXY_BONUS_WORKER=enabled\n'
    printf 'DNS_MT_PROXY_OWNER_ONLY=yes\n'
    printf 'DNS_MT_PROXY_TLS_DOMAIN=xapi.ozon.ru\n'
    printf 'DNS_MT_PROXY_TELEMT_AUTH=Bearer %s\n' "$dummy"
    printf 'DNS_MT_PROXY_TELEMT_SOCKET=/run/mnebyvpn-owner-mtproxy/telemt.sock\n'
  } > "$next"
  mv -f "$next" "$worker"
else
  test "$(stat -c '%a' "$worker")" = 600
  key="$(sed -n 's/^WEB_DNS_MT_PROXY_BONUS_KEY=//p' "$worker")"
  [[ "$key" =~ ^[a-f0-9]{64}$ ]]
  if [[ -n "$existing_key" ]]; then test "$key" = "$existing_key";fi
fi
dbpass="$(python3 - "$worker" <<'PY'
from urllib.parse import urlsplit
from pathlib import Path
import re,sys
env=dict(line.split('=',1) for line in Path(sys.argv[1]).read_text().splitlines() if '=' in line)
url=urlsplit(env.get('DATABASE_URL',''))
assert url.username=='mnebyvpn_owner_telemt' and url.hostname=='127.0.0.1'
assert url.port==5432 and url.path=='/mnebyvpn_stage'
assert re.fullmatch('[a-f0-9]{48}',url.password or '')
assert env.get('DNS_MT_PROXY_OWNER_ONLY')=='yes'
assert env.get('DNS_MT_PROXY_BONUS_WORKER')=='enabled'
assert env.get('DNS_MT_PROXY_TELEMT_SOCKET')=='/run/mnebyvpn-owner-mtproxy/telemt.sock'
assert re.fullmatch('[a-f0-9]{64}',env.get('WEB_DNS_MT_PROXY_BONUS_KEY',''))
print(url.password)
PY
)"
role_exists="$(docker exec mnebyvpn-stage-postgres psql -qAtX -v ON_ERROR_STOP=1 \
  -U mnebyvpn_stage -d mnebyvpn_stage \
  -c "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='mnebyvpn_owner_telemt')")"
if [[ "$role_exists" == f ]]; then
  # One narrowly privileged role; no access to accounts, payments, other apps,
  # or mutations of customer entitlements or orders.
  docker exec -i mnebyvpn-stage-postgres psql -q -v ON_ERROR_STOP=1 \
    -U mnebyvpn_stage -d mnebyvpn_stage >/dev/null <<SQL
BEGIN;
CREATE ROLE mnebyvpn_owner_telemt LOGIN NOINHERIT CONNECTION LIMIT 2 PASSWORD '$dbpass';
GRANT CONNECT ON DATABASE mnebyvpn_stage TO mnebyvpn_owner_telemt;
GRANT USAGE ON SCHEMA public TO mnebyvpn_owner_telemt;
GRANT SELECT (id,account_id,source_order_id,product,state,starts_at,expires_at)
  ON public.entitlements TO mnebyvpn_owner_telemt;
GRANT SELECT (id,account_id,state)
  ON public.orders TO mnebyvpn_owner_telemt;
GRANT SELECT (order_id)
  ON public.manual_sales TO mnebyvpn_owner_telemt;
GRANT SELECT,INSERT,UPDATE
  ON public.dns_mtproxy_bonus_credentials TO mnebyvpn_owner_telemt;
COMMIT;
SQL
fi
# Validate password and the minimum DB scope; never display the URI or key.
test "$(docker exec -e PGPASSWORD="$dbpass" mnebyvpn-stage-postgres \
    psql -h 127.0.0.1 -qAtX -v ON_ERROR_STOP=1 -U mnebyvpn_owner_telemt \
      -d mnebyvpn_stage -c 'SELECT count(*) FROM manual_sales')" = 0
test "$(docker exec -e PGPASSWORD="$dbpass" mnebyvpn-stage-postgres \
    psql -h 127.0.0.1 -qAtX -v ON_ERROR_STOP=1 -U mnebyvpn_owner_telemt \
      -d mnebyvpn_stage -c 'SELECT count(*) FROM dns_mtproxy_bonus_credentials')" = 0
echo 'owner_telemt_least_privilege_db_role=verified'
docker run -d --name "$container" --network host \
  --user 13096:13096 --read-only --tmpfs /tmp:rw,nosuid,nodev,size=8m \
  --mount type=bind,src=/run/mnebyvpn-owner-mtproxy,dst=/run/mnebyvpn-owner-mtproxy,readonly \
  --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 \
  --memory 160m --cpus 0.35 --restart unless-stopped \
  --env-file "$worker" --entrypoint node "$image" \
  --experimental-strip-types apps/service/src/dns-mtproxy-bonus-worker.ts >/dev/null
# A fresh worker has no manual customers: it must remain healthy without
# creating or changing any existing Telemt profiles.
sleep 8
test "$(docker inspect --format '{{.State.Running}}' "$container")" = true
test "$(docker inspect --format '{{.State.RestartCount}}' "$container")" = 0
test "$(docker inspect --format '{{.Config.User}}' "$container")" = '13096:13096'
num_after="$(docker exec mnebyvpn-stage-postgres psql -qAtX -v ON_ERROR_STOP=1 \
  -U mnebyvpn_stage -d mnebyvpn_stage -c 'SELECT count(*) FROM dns_mtproxy_bonus_credentials')"
[[ "$num_after" == 0 ]] || { echo 'unexpected_proxy_record_creation=true';exit 2; }
echo 'owner_mtproxy_worker=running_private_only'
# Bot needs the SAME key for later verified owner-only link retrieval.
# Never enable either public or owner delivery release flags at this stage.
if [[ -z "$existing_key" ]]; then
  test ! -e "$ROOT/bot/web.env.before-owner-telemt-key"
  cp -p "$botenv" "$ROOT/bot/web.env.before-owner-telemt-key"
  restore_bot_env(){
    code=$?
    trap - ERR
    cp -p "$ROOT/bot/web.env.before-owner-telemt-key" "$botenv" || true
    bash "$promoter" "$EXPECTED" || echo 'bot_env_manual_rollback_required=true'
    exit "$code"
  }
  trap restore_bot_env ERR
  tmp="$(mktemp "$ROOT/bot/.telemt-key.XXXXXXXX")"
  cp -p "$botenv" "$tmp"
  printf '\nWEB_DNS_MT_PROXY_BONUS_KEY=%s\n' "$key" >> "$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$botenv"
  bash "$promoter" "$EXPECTED"
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' mnebyvpn-bot-info |
    grep -Eq '^WEB_DNS_MT_PROXY_BONUS_KEY=[a-f0-9]{64}$'
  test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' \
    --max-time 5 http://127.0.0.1:8793/readyz)" = 200
  trap - ERR
  echo 'bot_owner_mtproxy_decryption_key=installed_private'
else
  echo 'bot_owner_mtproxy_decryption_key=existing_private'
fi
echo 'owner_mtproxy_public_delivery_flags=unchanged'
echo 'owner_mtproxy_real_customer_links=not_issued'
