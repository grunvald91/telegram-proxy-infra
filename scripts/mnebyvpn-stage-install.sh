#!/usr/bin/env bash
# Isolated pre-production MNEBYVPN web/billing pilot on server188.
# Does not edit nginx, firewall, DNS, proxy systemd units or relay89.
set -Eeuo pipefail
umask 077
ARCHIVE="$1"
SHA="$2"
ROOT=/opt/mnebyvpn
STAGE="$ROOT/staging"
RELEASE="$ROOT/releases/$SHA"
LOCK=/run/lock/mnebyvpn-stage-deploy.lock
[[ "$(id -u)" -eq 0 ]] || { echo 'root required'; exit 2; }
[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || { echo 'Invalid git SHA'; exit 2; }
[[ -f "$ARCHIVE" ]] || { echo 'Release archive missing'; exit 2; }
exec 9>"$LOCK"
flock -n 9 || { echo 'Staging deployment already active'; exit 2; }
command -v docker >/dev/null
command -v curl >/dev/null
command -v ss >/dev/null
docker info >/dev/null 2>&1 || { echo 'Docker daemon unavailable'; exit 2; }
# A tested staging-only service uses at most two loopback ports.
for port in 8791 55433; do
  if ss -H -lnt | awk '{print $4}' | grep -Eq ":$port$"; then
    case "$port" in
      8791) owner=mnebyvpn-stage-web ;;
      55433) owner=mnebyvpn-stage-postgres ;;
    esac
    docker ps --format '{{.Names}}' | grep -qx "$owner" || {
      echo "Refusing to occupy an existing unowned port $port"; exit 2;
    }
  fi
done
mkdir -p "$STAGE/data/postgres" "$ROOT/releases" "$STAGE/backups"
chmod 700 "$STAGE" "$STAGE/data" "$STAGE/data/postgres" "$STAGE/backups"
if [[ ! -d "$RELEASE" ]]; then
  mkdir -p "$RELEASE"
  tar -xzf "$ARCHIVE" --no-same-owner -C "$RELEASE"
fi
test -f "$RELEASE/package.json"
test -f "$RELEASE/apps/web/src/server.ts"
if [[ ! -e "$STAGE/postgres.env" ]]; then
  PG_PASSWORD="$(openssl rand -hex 32)"
  printf 'POSTGRES_DB=mnebyvpn_stage\nPOSTGRES_USER=mnebyvpn_stage\nPOSTGRES_PASSWORD=%s\n' "$PG_PASSWORD" > "$STAGE/postgres.env"
  chmod 600 "$STAGE/postgres.env"
fi
PG_PASSWORD="$(sed -n 's/^POSTGRES_PASSWORD=//p' "$STAGE/postgres.env")"
test -n "$PG_PASSWORD"
if [[ ! -e "$STAGE/web.env" ]]; then
  WEB_SECRET="$(openssl rand -hex 48)"
  cat > "$STAGE/web.env" <<EOF
NODE_ENV=production
MNEBYVPN_ENV=offline-test
WEB_BASE_URL=http://127.0.0.1:8791
WEB_PORT=8791
DATABASE_URL=postgresql://mnebyvpn_stage:$PG_PASSWORD@127.0.0.1:55433/mnebyvpn_stage
WEB_SESSION_SECRET=$WEB_SECRET
TELEGRAM_OIDC_CLIENT_ID=123456
TELEGRAM_OIDC_CLIENT_SECRET=STAGING_ONLY_DISABLED_NOT_REAL_CREDENTIALS
WEB_RELEASE_APPROVED=no
WEB_PRODAMUS_WEBHOOK_ENABLED=no
WEB_PAYMENT_PROVIDER_TESTED=no
WEB_CHECKOUT_ENABLED=0
WEB_NETWORK_PROVISIONING_VERIFIED=no
WEB_LEGAL_PAGES_PUBLISHED=no
WEB_TRIAL_ENABLED=no
WEB_DNS_METERING_VERIFIED=no
EOF
  chmod 600 "$STAGE/web.env"
fi
# Never accidentally enable customer-facing functions from this staging job.
grep -qx 'MNEBYVPN_ENV=offline-test' "$STAGE/web.env"
grep -qx 'WEB_CHECKOUT_ENABLED=0' "$STAGE/web.env"
grep -qx 'WEB_TRIAL_ENABLED=no' "$STAGE/web.env"
grep -qx 'WEB_NETWORK_PROVISIONING_VERIFIED=no' "$STAGE/web.env"
grep -qx 'WEB_DNS_METERING_VERIFIED=no' "$STAGE/web.env"
if ! docker ps -a --format '{{.Names}}' | grep -qx 'mnebyvpn-stage-postgres'; then
  docker run -d --name mnebyvpn-stage-postgres --restart unless-stopped \
    --memory 512m --cpus 0.65 \
    --publish 127.0.0.1:55433:5432 \
    --env-file "$STAGE/postgres.env" \
    --volume "$STAGE/data/postgres:/var/lib/postgresql/data" \
    postgres:17.6-alpine >/dev/null
fi
if [[ "$(docker inspect --format '{{.State.Running}}' mnebyvpn-stage-postgres)" != true ]]; then
  docker start mnebyvpn-stage-postgres >/dev/null
fi
ready=no
for attempt in $(seq 1 50); do
  if docker exec mnebyvpn-stage-postgres pg_isready -U mnebyvpn_stage -d mnebyvpn_stage >/dev/null 2>&1; then
    ready=yes; break
  fi
  sleep 1
done
[[ "$ready" == yes ]] || { echo 'Staging PostgreSQL did not become ready'; exit 2; }
psql_stage() {
  docker exec -i mnebyvpn-stage-postgres psql -v ON_ERROR_STOP=1 -U mnebyvpn_stage -d mnebyvpn_stage "$@"
}
psql_stage -q -c 'CREATE TABLE IF NOT EXISTS deployment_schema_migrations (file_name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT clock_timestamp());' >/dev/null
for file in "$RELEASE"/db/migrations/*.sql; do
  name="$(basename "$file")"
  [[ "$name" =~ ^[0-9]{4}_[A-Za-z0-9_]+\.sql$ ]] || { echo 'Unexpected migration name'; exit 2; }
  exists="$(psql_stage -At -c "SELECT COUNT(*) FROM deployment_schema_migrations WHERE file_name='$name'")"
  if [[ "$exists" == 0 ]]; then
    # All SQL migrations in this release have explicit BEGIN/COMMIT. A failing
    # migration stops the promotion; never delete or reset the database.
    psql_stage -q < "$file" >/dev/null
    psql_stage -q -c "INSERT INTO deployment_schema_migrations(file_name) VALUES('$name')" >/dev/null
    echo "Applied $name"
  fi
done
cat > "$STAGE/Dockerfile.web" <<'DOCKER'
FROM node:22.16.0-alpine
WORKDIR /srv/mnebyvpn
COPY package.json ./
RUN npm install --omit=dev --ignore-scripts --no-audit --no-fund
COPY apps ./apps
COPY packages ./packages
USER node
CMD ["node","--experimental-strip-types","apps/web/src/server.ts"]
DOCKER
docker build -q -t "mnebyvpn-stage-web:$SHA" -f "$STAGE/Dockerfile.web" "$RELEASE" >/dev/null
previous=""
if [[ -f "$STAGE/active_sha" ]]; then previous="$(cat "$STAGE/active_sha")"; fi
if docker ps -a --format '{{.Names}}' | grep -qx 'mnebyvpn-stage-web'; then
  docker stop -t 12 mnebyvpn-stage-web >/dev/null
  docker rm mnebyvpn-stage-web >/dev/null
fi
start_web() {
  docker run -d --name mnebyvpn-stage-web --restart unless-stopped \
    --network host --user 1000:1000 --read-only --tmpfs /tmp:rw,nosuid,nodev,size=32m \
    --cap-drop ALL --security-opt no-new-privileges --pids-limit 96 \
    --memory 300m --cpus 0.5 \
    --env-file "$STAGE/web.env" "mnebyvpn-stage-web:$1" >/dev/null
}
start_web "$SHA"
healthy=no
for attempt in $(seq 1 35); do
  code="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 2 http://127.0.0.1:8791/healthz || true)"
  if [[ "$code" == 200 ]]; then healthy=yes; break; fi
  sleep 1
done
if [[ "$healthy" != yes ]]; then
  echo 'Stage web /healthz failed'
  docker stop -t 5 mnebyvpn-stage-web >/dev/null 2>&1 || true
  docker rm mnebyvpn-stage-web >/dev/null 2>&1 || true
  if [[ -n "$previous" ]] && docker image inspect "mnebyvpn-stage-web:$previous" >/dev/null 2>&1; then
    start_web "$previous"
    echo 'Previous stage image restored'
  fi
  exit 2
fi
curl -fsS --max-time 5 http://127.0.0.1:8791/api/plans | python3 -c 'import json,sys; assert json.load(sys.stdin)["checkoutEnabled"] is False'
ready_status="$(curl -s --output /dev/null --write-out '%{http_code}' --max-time 5 http://127.0.0.1:8791/readyz)"
[[ "$ready_status" == 503 ]] || { echo 'Unexpected commercial readiness status'; exit 2; }
printf '%s\n' "$SHA" > "$STAGE/active_sha"
chmod 600 "$STAGE/active_sha"
echo "stage_web_health=200"
echo "stage_commercial_readiness=503_expected"
echo "stage_checkout_enabled=false"
echo "stage_listen_address=127.0.0.1:8791"
echo "stage_db_listen_address=127.0.0.1:55433"
echo "stage_sha=$SHA"
echo 'other_services_unchanged_by_script=yes'
