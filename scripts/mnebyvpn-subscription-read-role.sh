#!/usr/bin/env bash
# Set up a SELECT-only reader for the Telegram VPN entitlements held in the
# existing mnebyvpn_stage PostgreSQL database. Do not modify the public site's
# primary DATABASE_URL, users, payments, nginx or Xray.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" -eq 0 ]] || exit 2
ROOT=/opt/mnebyvpn
DEST="$ROOT/public/subscription-db.env"
DB_CONTAINER=mnebyvpn-stage-postgres
ROLE=mnebyvpn_sub_ro

test "$(docker inspect --format '{{.State.Running}}' "$DB_CONTAINER")" = true
psql_admin() {
  docker exec -i "$DB_CONTAINER" psql -v ON_ERROR_STOP=1 -U mnebyvpn_stage -d mnebyvpn_stage "$@"
}
for table in accounts entitlements provisioning_state vpn_subscription_links; do
  exists="$(psql_admin -At -c "SELECT to_regclass('public.$table');")"
  [[ "$exists" == "$table" ]] ||
    { echo "Required subscription table missing: $table"; exit 2; }
done

if [[ -f "$DEST" ]]; then
  chmod 600 "$DEST"
  if ! grep -Eq '^VPN_SUBSCRIPTION_DATABASE_URL=postgresql://mnebyvpn_sub_ro:[a-f0-9]{64}@127[.]0[.]0[.]1:55433/mnebyvpn_stage$' "$DEST"; then
    echo 'Existing subscription DB env is malformed; refusing to overwrite'
    exit 2
  fi
  PASSWORD="$(sed -n 's!^VPN_SUBSCRIPTION_DATABASE_URL=postgresql://mnebyvpn_sub_ro:\([a-f0-9]\{64\}\)@127\.0\.0\.1:55433/mnebyvpn_stage$!\1!p' "$DEST")"
else
  PASSWORD="$(openssl rand -hex 32)"
fi
[[ "$PASSWORD" =~ ^[0-9a-f]{64}$ ]] || exit 2

# Exact role is fixed, password is uniformly generated lowercase hex.
# psql's stdin is internal; do not enable shell tracing or print SQL.
psql_admin -q >/dev/null <<'SQL'
BEGIN;
DO $$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='mnebyvpn_sub_ro') THEN
    CREATE ROLE mnebyvpn_sub_ro LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
  END IF;
END
$$;
GRANT CONNECT ON DATABASE mnebyvpn_stage TO mnebyvpn_sub_ro;
GRANT USAGE ON SCHEMA public TO mnebyvpn_sub_ro;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM mnebyvpn_sub_ro;
GRANT SELECT ON TABLE public.accounts,public.entitlements,
  public.provisioning_state,public.vpn_subscription_links TO mnebyvpn_sub_ro;
-- The AWG read-only site endpoint requires the SAME canonical entitlement
-- and bearer token, but no INSERT/UPDATE/DELETE and no private key access.
-- AWG tables can be absent on an older node: grant nothing in that case.
DO $$
BEGIN
  IF to_regclass('public.vpn_awg_node_pools') IS NOT NULL AND
     to_regclass('public.vpn_awg_peer_allocations') IS NOT NULL AND
     to_regclass('public.vpn_node_enrollment_inventory') IS NOT NULL AND
     to_regclass('public.vpn_awg_command_outbox') IS NOT NULL AND
     to_regclass('public.vpn_release_flags') IS NOT NULL THEN
    GRANT SELECT (node_id,endpoint_host,listen_port,subnet_cidr,state,
                  verified_at,server_public_key)
      ON public.vpn_awg_node_pools TO mnebyvpn_sub_ro;
    GRANT SELECT (node_id,entitlement_id,peer_public_key,client_ipv4,
                  state,revision,expires_at,last_command_sha256)
      ON public.vpn_awg_peer_allocations TO mnebyvpn_sub_ro;
    GRANT SELECT (node_id,status)
      ON public.vpn_node_enrollment_inventory TO mnebyvpn_sub_ro;
    GRANT SELECT (node_id,entitlement_id,revision,op,signed_command,
                  command_sha256,state,billing_revision,node_receipt_sha256)
      ON public.vpn_awg_command_outbox TO mnebyvpn_sub_ro;
    GRANT SELECT (feature,enabled)
      ON public.vpn_release_flags TO mnebyvpn_sub_ro;
  END IF;
END
$$;
COMMIT;
SQL
printf "ALTER ROLE mnebyvpn_sub_ro WITH LOGIN PASSWORD '%s';\n" "$PASSWORD" |
  psql_admin -q >/dev/null

# Verify password authentication and SELECT-only privileges, not just role
# existence. Secrets are provided in Docker env, never printed to CI logs.
psql_reader() {
  docker exec -e "PGPASSWORD=$PASSWORD" "$DB_CONTAINER" \
    psql -v ON_ERROR_STOP=1 -At -h 127.0.0.1 -U "$ROLE" \
    -d mnebyvpn_stage -c "$1"
}
test "$(psql_reader "SELECT count(*) FROM vpn_subscription_links WHERE false;")" = 0
test "$(psql_reader "SELECT has_table_privilege('public.vpn_subscription_links','INSERT');")" = f
test "$(psql_reader "SELECT has_table_privilege('public.accounts','UPDATE');")" = f
# Must have exactly the columns needed by the AWG material reader,
# not table-wide rights or permission to update signed receipts.
awg_present="$(psql_admin -At -c "
SELECT CASE WHEN to_regclass('public.vpn_awg_node_pools') IS NOT NULL
 AND to_regclass('public.vpn_awg_peer_allocations') IS NOT NULL
 AND to_regclass('public.vpn_node_enrollment_inventory') IS NOT NULL
 AND to_regclass('public.vpn_awg_command_outbox') IS NOT NULL
 AND to_regclass('public.vpn_release_flags') IS NOT NULL
 THEN 'all' ELSE 'absent' END;")"
[[ "$awg_present" == all || "$awg_present" == absent ]] || exit 2
if [[ "$awg_present" == all ]]; then
  # Query succeeds only when all column-scoped read privileges are present.
  test "$(psql_reader "SELECT count(*) FROM public.vpn_awg_node_pools p
    JOIN public.vpn_node_enrollment_inventory n ON n.node_id=p.node_id
    JOIN public.vpn_awg_peer_allocations a ON a.node_id=p.node_id
    JOIN public.vpn_awg_command_outbox o
      ON o.node_id=a.node_id AND o.entitlement_id=a.entitlement_id
    JOIN public.vpn_release_flags f ON f.feature='vpn_awg_clients'
    WHERE false;")" = 0
  test "$(psql_reader "SELECT has_column_privilege('public.vpn_awg_command_outbox','signed_command','SELECT');")" = t
  test "$(psql_reader "SELECT has_column_privilege('public.vpn_awg_command_outbox','node_receipt_sha256','SELECT');")" = t
  test "$(psql_reader "SELECT has_column_privilege('public.vpn_awg_command_outbox','attempts','SELECT');")" = f
  test "$(psql_reader "SELECT has_table_privilege('public.vpn_awg_peer_allocations','UPDATE');")" = f
  test "$(psql_reader "SELECT has_table_privilege('public.vpn_release_flags','UPDATE');")" = f
fi

if [[ ! -f "$DEST" ]]; then
  tmp="$(mktemp "$ROOT/public/subscription-db.env.XXXXXXXX")"
  printf 'VPN_SUBSCRIPTION_DATABASE_URL=postgresql://%s:%s@127.0.0.1:55433/mnebyvpn_stage\n' \
    "$ROLE" "$PASSWORD" > "$tmp"
  chmod 600 "$tmp"
  mv "$tmp" "$DEST"
fi
echo 'vpn_subscription_db_role=read_only'
echo 'vpn_subscription_db_credentials=validated_not_logged'
echo 'public_primary_database_untouched=yes'
