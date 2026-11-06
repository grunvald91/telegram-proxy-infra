#!/usr/bin/env bash
# Add a read-only public brochure instance on localhost, without exposing a port.
set -Eeuo pipefail
umask 077
ROOT=/opt/mnebyvpn
PUBLIC="$ROOT/public"
STAGE="$ROOT/staging"
[[ "$(id -u)" -eq 0 ]] || exit 2
exec 9>/run/lock/mnebyvpn-public-prepare.lock
flock -n 9 || { echo 'Another public deployment is running'; exit 2; }
SHA="$(cat "$STAGE/active_sha")"
[[ "$SHA" =~ ^[a-f0-9]{40}$ ]] || { echo 'Invalid stage SHA'; exit 2; }
RELEASE="$ROOT/releases/$SHA"
test -f "$RELEASE/db/migrations/0015_dns_credit_metering.sql"
IMAGE="mnebyvpn-stage-web:$SHA"
docker image inspect "$IMAGE" >/dev/null
test "$(docker inspect -f '{{.State.Running}}' mnebyvpn-stage-postgres)" = true
if ! docker ps -a --format '{{.Names}}' | grep -qx 'mnebyvpn-public-web'; then
  if ss -H -lnt | awk '{print $4}' | grep -Eq ':8792$'; then
    echo 'Port 8792 is already used; refusing'; exit 2
  fi
fi
mkdir -p "$PUBLIC"
chmod 700 "$PUBLIC"
if [[ ! -f "$PUBLIC/db-role-secret" ]]; then
  openssl rand -hex 32 > "$PUBLIC/db-role-secret"
  chmod 600 "$PUBLIC/db-role-secret"
fi
DB_PASS="$(cat "$PUBLIC/db-role-secret")"
[[ "$DB_PASS" =~ ^[a-f0-9]{64}$ ]] || { echo 'Invalid stored role secret'; exit 2; }
admin_psql() {
  docker exec -i mnebyvpn-stage-postgres psql -X -v ON_ERROR_STOP=1 -q -U mnebyvpn_stage -d postgres "$@"
}
role="$(admin_psql -Atqc "SELECT COUNT(*) FROM pg_roles WHERE rolname='mnebyvpn_public'")"
if [[ "$role" == 0 ]]; then
  admin_psql -c "CREATE ROLE mnebyvpn_public LOGIN PASSWORD '$DB_PASS'" >/dev/null
fi
db="$(admin_psql -Atqc "SELECT COUNT(*) FROM pg_database WHERE datname='mnebyvpn_public'")"
if [[ "$db" == 0 ]]; then
  admin_psql -c 'CREATE DATABASE mnebyvpn_public OWNER mnebyvpn_stage' >/dev/null
fi
public_psql() {
  docker exec -i mnebyvpn-stage-postgres psql -X -v ON_ERROR_STOP=1 -q -U mnebyvpn_stage -d mnebyvpn_public "$@"
}
public_psql -c 'CREATE TABLE IF NOT EXISTS deployment_schema_migrations(file_name text PRIMARY KEY,applied_at timestamptz NOT NULL DEFAULT clock_timestamp());' >/dev/null
for file in "$RELEASE"/db/migrations/*.sql; do
  name="$(basename "$file")"
  [[ "$name" =~ ^[0-9]{4}_[A-Za-z0-9_]+\.sql$ ]] || exit 2
  applied="$(public_psql -Atqc "SELECT COUNT(*) FROM deployment_schema_migrations WHERE file_name='$name'")"
  if [[ "$applied" == 0 ]]; then
    public_psql < "$file" >/dev/null
    public_psql -c "INSERT INTO deployment_schema_migrations(file_name) VALUES('$name')" >/dev/null
    echo "public_db_migration_applied=$name"
  fi
done
public_psql -c 'REVOKE ALL ON DATABASE mnebyvpn_public FROM PUBLIC;' >/dev/null
admin_psql -c 'GRANT CONNECT ON DATABASE mnebyvpn_public TO mnebyvpn_public;' >/dev/null
public_psql -c 'GRANT USAGE ON SCHEMA public TO mnebyvpn_public;' >/dev/null
public_psql -c 'GRANT SELECT ON billing_plans TO mnebyvpn_public;' >/dev/null
# Authentication, trial, paid checkout and metered access stay disabled.
# The read-only role cannot mutate orders, subscriptions or website sessions.
if [[ ! -f "$PUBLIC/web.env" ]]; then
  SECRET="$(openssl rand -hex 48)"
  cat > "$PUBLIC/web.env" <<EOF
MNEBYVPN_ENV=production
WEB_RELEASE_APPROVED=yes
WEB_BASE_URL=https://mnebyvpn.site
WEB_PORT=8792
DATABASE_URL=postgresql://mnebyvpn_public:$DB_PASS@127.0.0.1:55433/mnebyvpn_public
WEB_SESSION_SECRET=$SECRET
WEB_TELEGRAM_OIDC_ENABLED=no
WEB_PRODAMUS_WEBHOOK_ENABLED=no
WEB_PAYMENT_PROVIDER_TESTED=no
WEB_CHECKOUT_ENABLED=0
WEB_NETWORK_PROVISIONING_VERIFIED=no
WEB_LEGAL_PAGES_PUBLISHED=no
WEB_TRIAL_ENABLED=no
WEB_DNS_METERING_VERIFIED=no
EOF
  chmod 600 "$PUBLIC/web.env"
fi
for expected in \
  MNEBYVPN_ENV=production WEB_BASE_URL=https://mnebyvpn.site \
  WEB_TELEGRAM_OIDC_ENABLED=no WEB_PRODAMUS_WEBHOOK_ENABLED=no \
  WEB_CHECKOUT_ENABLED=0 WEB_TRIAL_ENABLED=no \
  WEB_NETWORK_PROVISIONING_VERIFIED=no WEB_DNS_METERING_VERIFIED=no; do
  grep -Fxq "$expected" "$PUBLIC/web.env" || { echo 'Unsafe environment flags'; exit 2; }
done
if docker ps -a --format '{{.Names}}' | grep -qx 'mnebyvpn-public-web'; then
  docker stop -t 8 mnebyvpn-public-web >/dev/null
  docker rm mnebyvpn-public-web >/dev/null
fi
docker run -d --name mnebyvpn-public-web --restart unless-stopped \
  --network host --user 1000:1000 --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=32m --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 96 --memory 300m --cpus 0.4 \
  --env-file "$PUBLIC/web.env" "$IMAGE" >/dev/null
ok=no
for i in $(seq 1 30); do
  if curl -fsS --max-time 3 http://127.0.0.1:8792/healthz >/dev/null; then ok=yes; break; fi
  sleep 1
done
test "$ok" = yes || { echo 'Public brochure backend unhealthy'; exit 2; }
curl -fsS http://127.0.0.1:8792/api/plans | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d["checkoutEnabled"] is False and d["loginEnabled"] is False'
test "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8792/auth/login)" = 503
test "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8792/readyz)" = 503
test "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8792/healthz)" = 200
if ! ss -H -lnt | awk '{print $4}' | grep -Fqx '127.0.0.1:8792'; then
  echo 'Backend unexpectedly bound outside loopback'; exit 2
fi
echo 'public_brochure_backend=healthy'
echo 'public_brochure_port=127.0.0.1:8792'
echo 'public_database_role=read_only'
echo 'telegram_oidc=disabled_pending_client_credentials'
echo 'customer_payments=disabled'
echo 'stage_unchanged=true'
echo "public_sha=$SHA"
