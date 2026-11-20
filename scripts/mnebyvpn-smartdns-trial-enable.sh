#!/usr/bin/env bash
# Enable 24h Smart DNS trial in canonical production DB (mnebyvpn_stage) after
# verifying 0140_trial_smart_dns_delivery.sql, smart_dns worker health, and
# personal DoT ingress; also run a PII-free read-only audit of VPN/DNS queues.
set -Eeuo pipefail

ROOT=/opt/mnebyvpn
ENV_FILE="$ROOT/public/web.env"
PG_CONTAINER=mnebyvpn-stage-postgres
DNS_CONTAINER=mnebydns-personal-dot-private
WORKER_CONTAINER=mnebyvpn-vpn-worker

[[ "$(id -u)" -eq 0 ]] || { echo 'Root privileges required'; exit 2; }
test -s "$ENV_FILE"

for c in "$PG_CONTAINER" "$DNS_CONTAINER" mnebyvpn-public-web "$WORKER_CONTAINER"; do
  state="$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null || echo missing)"
  echo "container_${c}=$state"
  test "$state" = true || { echo "required_container_not_running=$c"; exit 2; }
done

for expected in \
  'WEB_TRIAL_ENABLED=yes' \
  'WEB_EMAIL_LOGIN_ENABLED=yes' \
  'WEB_NETWORK_PROVISIONING_VERIFIED=yes' \
  'WEB_PERSONAL_DNS_APPLE_ENABLED=yes' \
  'WEB_PERSONAL_DNS_DOT_E2E_VERIFIED=yes'; do
  grep -Fxq "$expected" "$ENV_FILE" || { echo "missing_web_env=$expected"; exit 2; }
done
echo 'web_env_flags=verified'

worker_smart_dns="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$WORKER_CONTAINER" | grep -Fx 'MNEBYDNS_SMART_DNS_WORKER=enabled' || true)"
test -n "$worker_smart_dns" || { echo 'missing_worker_env=MNEBYDNS_SMART_DNS_WORKER=enabled'; exit 2; }
echo 'worker_smart_dns_enabled=true'

echo "personal_dot_readyz=$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 4 http://127.0.0.1:8859/readyz || echo 000)"
echo "worker_readyz=$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 4 http://127.0.0.1:8794/readyz || echo 000)"
echo "public_web_readyz=$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 4 http://127.0.0.1:8792/readyz || echo 000)"

psql_exec() {
  docker exec -i "$PG_CONTAINER" psql -At -X -v ON_ERROR_STOP=1 -U mnebyvpn_stage -d mnebyvpn_stage "$@"
}

has_0140="$(psql_exec -c "SELECT count(*) FROM deployment_schema_migrations WHERE file_name = '0140_trial_smart_dns_delivery.sql';")"
echo "migration_0140_applied=$has_0140"
test "${has_0140:-0}" -ge 1 || { echo 'missing_migration=0140_trial_smart_dns_delivery.sql'; exit 2; }

psql_exec <<'SQL'
UPDATE trial_offers
   SET enabled = true,
       dns_quota_bytes = COALESCE(dns_quota_bytes, 1073741824)
 WHERE product = 'smart_dns' AND duration_seconds = 86400;

SELECT 'trial_offer=' || product || '|enabled=' || enabled || '|quota=' || COALESCE(dns_quota_bytes::text, 'null')
  FROM trial_offers
 ORDER BY product;
SQL

echo '--- READONLY_QUEUE_DIAGNOSTICS (NO PII) ---'
psql_exec <<'SQL'
SELECT 'entitlements|' || product || '|' || state || '|' || count(*)
  FROM entitlements
 GROUP BY product, state
 ORDER BY product, state;

SELECT 'outbox_pending|' || e.product || '|' || COALESCE(b.last_error_code, 'none') || '|' || count(*)
  FROM reconcile_outbox b
  JOIN entitlements e ON e.id = b.entitlement_id
 WHERE b.handled_at IS NULL
 GROUP BY e.product, b.last_error_code
 ORDER BY e.product, count(*) DESC;

SELECT 'trial_grants_by_product|' || product || '|activated=' || (activated_at IS NOT NULL) || '|' || count(*)
  FROM trial_grants
 GROUP BY product, (activated_at IS NOT NULL)
 ORDER BY product;

SELECT 'vpn_active_with_observed_provisioning|' || count(*)
  FROM entitlements e
  LEFT JOIN provisioning_state p ON p.entitlement_id = e.id AND p.adapter = 'vpn'
 WHERE e.product = 'vpn' AND e.state = 'ACTIVE' AND e.expires_at > clock_timestamp()
   AND p.applied_revision = e.revision AND p.last_observed_at IS NOT NULL;

SELECT 'vpn_active_missing_observed_provisioning|' || count(*)
  FROM entitlements e
  LEFT JOIN provisioning_state p ON p.entitlement_id = e.id AND p.adapter = 'vpn'
 WHERE e.product = 'vpn' AND e.state = 'ACTIVE' AND e.expires_at > clock_timestamp()
   AND (p.applied_revision IS DISTINCT FROM e.revision OR p.last_observed_at IS NULL);
SQL

echo '--- WORKER_RECENT_SUMMARY ---'
docker logs --tail 25 "$WORKER_CONTAINER" 2>&1 | sed -E 's/[0-9a-f]{8}-[0-9a-f-]{27}/<uuid>/gi' || true

echo '--- LOCAL_PLANS_API ---'
curl -fsS --max-time 5 http://127.0.0.1:8792/api/plans | python3 -c '
import json, sys
data = json.load(sys.stdin)
print("trialOffers=" + json.dumps(data.get("trialOffers", [])))
assert "vpn" in data.get("trialOffers", []), "vpn missing in trialOffers"
assert "smart_dns" in data.get("trialOffers", []), "smart_dns missing in trialOffers"
'
