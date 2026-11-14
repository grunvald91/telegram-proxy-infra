#!/usr/bin/env python3
"""Read-only owner-trial premium DoT query meter (NO bearer key/ID disclosure).

Only queries the existing database. Counts successfully settled premium
DNS lookups since the beginning of the isolated 24h trial.
Ordinary/direct DNS requests are NOT counted by the product's current meter.
"""
import datetime
import pathlib
import re
import subprocess
import sys

BOT_ENV = pathlib.Path("/opt/mnebyvpn/bot/web.env")
DB_CONTAINER = "mnebyvpn-stage-postgres"
DB_SHELL = ('PGPASSWORD="$POSTGRES_PASSWORD" exec psql -XAt '
            '-v ON_ERROR_STOP=1 -h 127.0.0.1 '
            '-U "$POSTGRES_USER" -d "$POSTGRES_DB"')


def run() -> None:
    # Never send the user's secret, Telegram ID or entitlement UUID to logs.
    env = {}
    for line in BOT_ENV.read_text(encoding="utf-8").splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, val = line.split("=", 1)
        if key in ("DNS_ADMIN_TELEGRAM_ID", "SUPPORT_TELEGRAM_OPERATOR_ID"):
            env[key] = val.strip().strip("\"'")
    owner = env.get("DNS_ADMIN_TELEGRAM_ID") or env.get(
        "SUPPORT_TELEGRAM_OPERATOR_ID", "")
    if not re.fullmatch(r"[1-9][0-9]{0,15}", owner):
        raise ValueError("Owner configuration is unavailable")
    # Owner is validated decimal digits, never a public/guessed DNS hostname.
    sql = f"""
    SELECT
      EXTRACT(EPOCH FROM clock_timestamp())::bigint,
      EXTRACT(EPOCH FROM e.starts_at)::bigint,
      EXTRACT(EPOCH FROM e.expires_at)::bigint,
      COALESCE((SELECT SUM(w.used_queries)
                FROM personal_dns_query_windows w
                WHERE w.entitlement_id=e.id), 0)::bigint,
      COALESCE((SELECT SUM(w.reserved_queries)
                FROM personal_dns_query_windows w
                WHERE w.entitlement_id=e.id), 0)::bigint,
      c.query_limit_per_30d::bigint
    FROM accounts a
    JOIN entitlements e ON e.account_id=a.id
    JOIN orders o ON o.id=e.source_order_id
    JOIN personal_dns_credentials c ON c.entitlement_id=e.id
    WHERE a.telegram_user_id={owner}::bigint
      AND e.product='smart_dns'
      AND o.provider='internal_trial'
      AND o.state='TRIAL'
      AND e.starts_at>clock_timestamp()-interval '72 hours'
      AND c.revoked_at IS NULL
    ORDER BY e.starts_at DESC
    LIMIT 1;
    """
    proc = subprocess.run(
        ["docker", "exec", "-i", DB_CONTAINER, "sh", "-c", DB_SHELL],
        input=sql, capture_output=True, text=True, timeout=25, check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError("Read-only owner trial counter query failed")
    lines = [x.strip() for x in proc.stdout.splitlines() if x.strip()]
    if len(lines) != 1:
        raise RuntimeError("No unique recent owner 24-hour trial found")
    fields = lines[0].split("|")
    if len(fields) != 6 or any(not re.fullmatch(r"[0-9]{1,15}", f) for f in fields):
        raise RuntimeError("Unexpected counters response format")
    observed, start, expiry, premium, pending, cap = map(int, fields)
    if not (start <= observed + 180 and start < expiry and
            premium >= 0 and pending >= 0 and 1 <= cap <= 100000000):
        raise RuntimeError("Invalid owner trial metrics")
    def utc(epoch: int) -> str:
        return datetime.datetime.fromtimestamp(
            epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print("OWNER_PERSONAL_METER=READ_ONLY", flush=True)
    print("OWNER_PERSONAL_METER_AT_UTC=" + utc(observed), flush=True)
    print("OWNER_PERSONAL_TRIAL_START_UTC=" + utc(start), flush=True)
    print("OWNER_PERSONAL_TRIAL_END_UTC=" + utc(expiry), flush=True)
    print("OWNER_PERSONAL_PREMIUM_QUERIES_SETTLED=" + str(premium), flush=True)
    print("OWNER_PERSONAL_PREMIUM_QUERIES_PENDING=" + str(pending), flush=True)
    print("OWNER_PERSONAL_PREMIUM_QUERY_LIMIT=" + str(cap), flush=True)
    print("OWNER_PERSONAL_ORDINARY_DNS_QUERIES=NOT_METERED", flush=True)
    print("OWNER_PERSONAL_BEARER_EXPOSED=false", flush=True)
    print("OWNER_PERSONAL_DB_MUTATIONS=false", flush=True)


if __name__ == "__main__":
    try:
        run()
    except Exception as exc:
        # Do not echo exception text, SQL, secrets, private IDs or hostname.
        print("OWNER_PERSONAL_METER_FAILED=" + type(exc).__name__, flush=True)
        sys.exit(1)
