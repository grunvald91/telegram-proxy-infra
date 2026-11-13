#!/usr/bin/env bash
# Disposable RU-host canary. This script has NO commands that can alter
# mnebyvpn production containers, CoreDNS, Nginx, firewall or their databases.
# Only our uniquely named disposable containers/network and /tmp folder.
set -Eeuo pipefail

[[ "$#" -eq 2 ]] || { echo 'CANARY_ARGS_INVALID'; exit 2; }
runid="$1"
work="$2"
[[ "$runid" =~ ^[0-9]{6,20}$ ]] || { echo 'CANARY_RUN_ID_INVALID'; exit 2; }
[[ "$work" == "/tmp/mnebydns-personal-dot-$runid" ]] || {
  echo 'CANARY_WORKDIR_INVALID'; exit 2;
}
[[ -f "$work/app/package.json" && -d "$work/app/packages/dns-policy/src" &&
   -d "$work/app/db/migrations" &&
   -f "$work/config/test.crt" && -f "$work/config/test.key" &&
   -f "$work/config/routes.json" && -f "$work/migration-list.txt" ]] || {
  echo 'CANARY_INPUTS_INCOMPLETE'; exit 2;
}

pg="mnebydns-canary-pg-$runid"
node="mnebydns-canary-node-$runid"
net="mnebydns-canary-net-$runid"
own_pg=false
own_node=false
own_network=false
cleanup(){
  set +e
  if [[ "$own_node" == true ]]; then docker rm -f "$node" >/dev/null 2>&1; fi
  if [[ "$own_pg" == true ]]; then docker rm -f "$pg" >/dev/null 2>&1; fi
  if [[ "$own_network" == true ]]; then docker network rm "$net" >/dev/null 2>&1; fi
  if [[ "$work" == "/tmp/mnebydns-personal-dot-$runid" ]]; then
    rm -rf -- "$work"
  fi
  echo 'CANARY_DISPOSABLE_RESOURCES_CLEANED=true'
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

available="$(awk '/^MemAvailable:/ {print int($2/1024)}' /proc/meminfo)"
free_disk="$(df -Pm /tmp | awk 'NR==2 {print $4}')"
if ((available < 1150 || free_disk < 1200)); then
  echo "CANARY_INSUFFICIENT_RESOURCES available_mib=$available disk_mib=$free_disk"
  exit 2
fi

for name in "$pg" "$node"; do
  if docker container inspect "$name" >/dev/null 2>&1; then
    echo 'CANARY_CONTAINER_NAME_ALREADY_EXISTS'; exit 2
  fi
done
if docker network inspect "$net" >/dev/null 2>&1; then
  echo 'CANARY_NETWORK_NAME_ALREADY_EXISTS';exit 2
fi

pg_image="$(docker inspect --format '{{.Config.Image}}' mnebyvpn-stage-postgres)"
node_image="$(docker inspect --format '{{.Config.Image}}' mnebyvpn-stage-web)"
[[ "$pg_image" == postgres:17.6-alpine && "$node_image" == mnebyvpn-stage-web:* ]] || {
  echo 'CANARY_IMAGE_NOT_PINNED_OR_NOT_INSTALLED';exit 2;
}
# No image pulls and no builds on this live host.
docker image inspect "$pg_image" >/dev/null
docker image inspect "$node_image" >/dev/null

docker network create --driver bridge --label mnebydns-disposable-canary=true "$net" >/dev/null
own_network=true
password="$(openssl rand -hex 16)"
docker run --detach --rm --name "$pg" --network "$net" \
  --memory 320m --memory-swap 320m --cpus 0.5 --pids-limit 100 \
  --security-opt no-new-privileges:true \
  --tmpfs /var/lib/postgresql/data:rw,nosuid,size=256m \
  --tmpfs /tmp:rw,nosuid,size=16m \
  --env POSTGRES_USER=canary --env "POSTGRES_PASSWORD=$password" \
  --env POSTGRES_DB=mnebyvpn_canary \
  --volume "$work/app/db:/suite/db:ro" \
  "$pg_image" >/dev/null
own_pg=true

ready=false
for i in $(seq 1 90); do
  # pg_isready alone can report READY during entrypoint initialization,
  # before POSTGRES_DB has actually been created. Use a real SQL connection.
  if [[ "$(docker exec "$pg" psql -AtX -U canary -d mnebyvpn_canary -c 'SELECT 1' 2>/dev/null || true)" == 1 ]]; then
    ready=true;break
  fi
  sleep 0.25
done
[[ "$ready" == true ]] || { echo 'CANARY_DISPOSABLE_POSTGRES_NOT_READY';exit 2; }
count=0
while IFS= read -r migration; do
  [[ "$migration" =~ ^db/migrations/[0-9]{4}_[a-z0-9_]+\.sql$ ]] || {
    echo 'CANARY_MIGRATION_PATH_INVALID';exit 2;
  }
  docker exec "$pg" psql -X -v ON_ERROR_STOP=1 -U canary -d mnebyvpn_canary \
    -f "/suite/$migration" >/dev/null
  count=$((count+1))
done < "$work/migration-list.txt"
((count >= 30)) || { echo 'CANARY_REQUIRED_SCHEMA_NOT_APPLIED';exit 2; }
echo "CANARY_DISPOSABLE_MIGRATIONS_APPLIED=$count"

docker exec -i "$pg" psql -X -v ON_ERROR_STOP=1 -U canary -d mnebyvpn_canary \
  < "$work/config/fixture.sql" >/dev/null

policy_hash="$(sha256sum "$work/config/routes.json" | cut -d' ' -f1)"
docker run --detach --name "$node" --network "$net" \
  --user 0:0 \
  --memory 320m --memory-swap 320m --cpus 0.75 --pids-limit 80 \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,nosuid,size=32m \
  --volume "$work/app/apps:/srv/mnebyvpn/apps:ro" \
  --volume "$work/app/packages:/srv/mnebyvpn/packages:ro" \
  --volume "$work/config:/run/mnebydns-canary:ro" \
  --env MNEBYVPN_ENV=offline-test \
  --env MNEBYDNS_PERSONAL_DOT_GATEWAY=canary \
  --env MNEBYDNS_CANARY_PORT=8853 \
  --env MNEBYDNS_CANARY_UPSTREAM_MODE=verified-dot \
  --env MNEBYDNS_CANARY_VERIFIED_UPSTREAM_APPROVED=yes \
  --env MNEBYDNS_CANARY_MAPPED_DOT_IP=89.125.90.101 \
  --env MNEBYDNS_CANARY_MAPPED_DOT_TLS_NAME=dns.mnebyvpn.site \
  --env MNEBYDNS_CANARY_DIRECT_DOT_IP=1.1.1.1 \
  --env MNEBYDNS_CANARY_DIRECT_DOT_TLS_NAME=one.one.one.one \
  --env MNEBYDNS_CANARY_ROUTE_POLICY_FILE=/run/mnebydns-canary/routes.json \
  --env "MNEBYDNS_CANARY_ROUTE_POLICY_SHA256=$policy_hash" \
  --env MNEBYDNS_CANARY_TLS_KEY_FILE=/run/mnebydns-canary/test.key \
  --env MNEBYDNS_CANARY_TLS_CERT_FILE=/run/mnebydns-canary/test.crt \
  --env "MNEBYDNS_CANARY_DATABASE_URL=postgresql://canary:$password@$pg:5432/mnebyvpn_canary" \
  --env MNEBYDNS_CANARY_SMOKE_APPROVED=yes \
  --env MNEBYDNS_SMOKE_ACCOUNT_ID=44333333-3333-4333-8333-333333333333 \
  --env MNEBYDNS_SMOKE_ENTITLEMENT_ID=66555555-5555-4555-8555-555555555555 \
  --entrypoint node "$node_image" \
    --experimental-strip-types /srv/mnebyvpn/apps/service/src/personal-dot-canary.ts >/dev/null
own_node=true

ready=false
for i in $(seq 1 80); do
  if docker logs "$node" 2>&1 | grep -Fq 'Private DNS canary listening on loopback only'; then
    ready=true;break
  fi
  [[ "$(docker inspect --format '{{.State.Running}}' "$node")" == true ]] || break
  sleep 0.2
done
if [[ "$ready" != true ]]; then
  echo 'CANARY_TLS_LISTENER_FAILED'
  docker inspect --format 'CANARY_NODE_EXIT_CODE={{.State.ExitCode}}' "$node" 2>/dev/null || true
  docker logs --tail 20 "$node" 2>&1 | sed -E \
    's#postgresql://[^ ]+#<redacted-dsn>#g' || true
  exit 2
fi
echo 'CANARY_NODE_TLS_LOOPBACK_READY=true'
# The only client is docker exec inside this disposable Node container.
# Node listener binds 127.0.0.1:8853 in the private Docker network namespace.
docker exec "$node" node --experimental-strip-types \
  /srv/mnebyvpn/apps/service/src/personal-dot-remote-smoke.ts
echo 'CANARY_RU_TO_FOREIGN_DOT_DISPOSABLE=PASS'
