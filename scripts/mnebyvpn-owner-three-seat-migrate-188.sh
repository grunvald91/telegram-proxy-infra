#!/usr/bin/env bash
# Apply ONLY approved 0142 inventory; no AWG grants, site or bot restarts.
set -Eeuo pipefail
umask 077
test "$(id -u)" -eq 0
expected="$1"
[[ "$expected" =~ ^[a-f0-9]{64}$ ]]
migration=/tmp/mnebyvpn-owner-three-seat-0142.sql
test -s "$migration"
test "$(sha256sum "$migration" | awk '{print $1}')" = "$expected"
exec 9>/run/lock/mnebyvpn-stage-deploy.lock
flock -w 75 9
name=mnebyvpn-stage-postgres
test "$(docker inspect -f '{{.State.Running}}' "$name")" = true
psql_stage(){
  docker exec -i "$name" psql -qAtX -v ON_ERROR_STOP=1 \
    -U mnebyvpn_stage -d mnebyvpn_stage "$@"
}
test "$(psql_stage -c "SELECT EXISTS(SELECT 1 FROM deployment_schema_migrations WHERE file_name='0141_owner_manual_sales.sql')")" = t
test "$(psql_stage -c "SELECT to_regclass('public.manual_sales') IS NOT NULL")" = t
test "$(psql_stage -c "SELECT count(*) FROM manual_sales")" = 0
before_awg="$(psql_stage -c 'SELECT count(*) FROM vpn_awg_peer_allocations')"
before_sub="$(psql_stage -c 'SELECT count(*) FROM vpn_subscription_links')"
exists="$(psql_stage -c "SELECT to_regclass('public.owner_vpn_device_seats') IS NOT NULL")"
ledger="$(psql_stage -c "SELECT count(*) FROM deployment_schema_migrations WHERE file_name='0142_owner_vpn_three_device_seats.sql'")"
if [[ "$exists" = t && "$ledger" = 1 ]];then
  echo 'owner_three_seat_migration=already_applied'
elif [[ "$exists" = f && "$ledger" = 0 ]];then
  backups=/opt/mnebyvpn/staging/backups
  test -d "$backups"
  test "$(stat -c %a "$backups")" = 700
  backup="$(mktemp "$backups/pre-owner-three-device-0142.XXXXXXXX.dump")"
  chmod 600 "$backup"
  docker exec "$name" pg_dump -Fc -U mnebyvpn_stage -d mnebyvpn_stage > "$backup"
  test "$(stat -c %s "$backup")" -gt 128
  test "$(head -c 5 "$backup")" = PGDMP
  echo 'owner_three_seat_premigration_backup=verified'
  psql_stage < "$migration" >/dev/null
  psql_stage -c "INSERT INTO deployment_schema_migrations(file_name) VALUES('0142_owner_vpn_three_device_seats.sql')" >/dev/null
  echo 'owner_three_seat_migration=applied'
else
  echo 'owner_three_seat_schema_ledger_mismatch=refused'
  exit 2
fi
test "$(psql_stage -c "SELECT to_regclass('public.owner_vpn_device_seats') IS NOT NULL")" = t
test "$(psql_stage -c "SELECT count(*) FROM owner_vpn_device_seats")" = 0
test "$(psql_stage -c "SELECT count(*) FROM manual_sales")" = 0
test "$(psql_stage -c "SELECT count(*) FROM vpn_awg_peer_allocations")" = "$before_awg"
test "$(psql_stage -c "SELECT count(*) FROM vpn_subscription_links")" = "$before_sub"
test "$(psql_stage -c "SELECT count(*) FROM pg_trigger WHERE tgrelid='public.entitlements'::regclass AND tgname='owner_vpn_prepare_three_seats' AND NOT tgisinternal")" = 1
echo 'owner_three_seat_slots=zero_until_first_real_manual_sale'
echo 'owner_three_seat_active_awg_profiles=unchanged'
echo 'owner_three_seat_vpn_subscription_tokens=unchanged'
echo 'owner_three_seat_no_public_enrollment=yes'
