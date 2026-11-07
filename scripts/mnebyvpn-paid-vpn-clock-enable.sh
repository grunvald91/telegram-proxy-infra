#!/usr/bin/env bash
# Final guarded production switch for node-acknowledged paid VPN start time.
# NO payment captures, profiles, customer subscriptions or node configuration
# are modified here. A green source release and verified worker are mandatory.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" -eq 0 ]] || { echo 'root required';exit 2; }
SHA="${1:?Exact green source SHA required}"
[[ "$SHA" =~ ^[a-f0-9]{40}$ ]] || exit 2
ROOT=/opt/mnebyvpn
exec 9>/run/lock/mnebyvpn-paid-vpn-clock-enable.lock
flock -w 30 9 || { echo 'Paid activation clock rollout already in progress';exit 2; }

test "$(cat "$ROOT/public/active_sha")" = "$SHA" || {
  echo 'Public billing code does not match reviewed commit';exit 2;
}
test "$(cat "$ROOT/staging/active_sha")" = "$SHA" || {
  echo 'Worker staging does not match reviewed commit';exit 2;
}
test "$(docker inspect --format '{{.Config.Image}}' mnebyvpn-vpn-worker)" = "mnebyvpn-stage-web:$SHA" || {
  echo 'Running VPN worker image not yet updated';exit 2;
}
test "$(docker inspect --format '{{.State.Running}}' mnebyvpn-vpn-worker)" = true
for url in \
  http://127.0.0.1:8794/readyz \
  http://127.0.0.1:8792/healthz \
  http://10.66.77.1:18944/healthz; do
  test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' \
    --connect-timeout 3 --max-time 7 "$url")" = 200 || {
    echo 'Worker/public/node readiness check failed; clock unchanged';exit 2;
  }
done

# Verify live customer credentials and relative hard deadlines on the node,
# not just the application database state.
AUDIT=/tmp/mnebyvpn-live-node-readonly-check.py
test -s "$AUDIT"
python3 "$AUDIT"
test "$(docker inspect --format '{{.Config.Image}}' mnebyvpn-vpn-worker)" = "mnebyvpn-stage-web:$SHA"

sql() {
  docker exec -i mnebyvpn-stage-postgres psql -AtX -v ON_ERROR_STOP=1 \
    -U mnebyvpn_stage -d mnebyvpn_stage "$@"
}
test "$(sql -c "SELECT count(*) FROM vpn_release_flags WHERE feature='paid_vpn_clock_on_node'")" = 1 || {
  echo 'Missing or ambiguous migration feature gate';exit 2;
}
# Both DB functions must be present before switching billable timekeeping.
test "$(sql -c "SELECT (
  to_regprocedure('public.acknowledge_provisioning(uuid,text,bigint,bigint,boolean)') IS NOT NULL
  AND to_regprocedure('public.settle_verified_payment(uuid,text,text,text,text,bigint,text,bigint,bigint)') IS NOT NULL)::int")" = 1 || {
  echo 'Paid activation SQL functions missing';exit 2;
}
# The flag is changed atomically only after every check above has succeeded.
# Keep the new worker running while new payments are being accepted.
result="$(sql <<'SQL'
BEGIN;
SELECT pg_advisory_xact_lock(hashtext('mnebyvpn:paid_clock'),hashtext('release'));
DO $enable$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM vpn_release_flags
                  WHERE feature='paid_vpn_clock_on_node') THEN
    RAISE EXCEPTION 'Feature flag row not found';
  END IF;
  UPDATE vpn_release_flags SET enabled=true WHERE feature='paid_vpn_clock_on_node';
END
$enable$;
COMMIT;
SELECT 'paid_vpn_clock_on_node='||enabled::text FROM vpn_release_flags
WHERE feature='paid_vpn_clock_on_node';
SQL
)"
echo "$result" | grep -Fxq 'paid_vpn_clock_on_node=true' || {
  echo 'Paid clock enable not verified';exit 2;
}
echo 'paid_vpn_clock_on_node=true'
echo "verified_worker_sha=$SHA"
echo 'live_customer_deadlines=inspected_without_change'
echo 'payment_checkout=not_modified'
echo 'existing_subscriptions=not_modified'
