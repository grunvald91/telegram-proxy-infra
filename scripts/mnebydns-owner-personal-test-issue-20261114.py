#!/usr/bin/env python3
"""One-shot OWNER-only real DoT test credential.
Provisions an unpaid, 24-hour TRIAL order and ACTIVE Smart DNS entitlement,
stores only SHA256(label), verifies a real local DNS-over-TLS query and
privately sends the bearer hostname with the already-owned Telegram bot.
No payable plan, webhook, public DNS, or VPN configuration is modified.
Never emit Telegram IDs, bot token, DNS bearer label or database secrets.
"""
from __future__ import annotations
import hashlib
import json
import pathlib
import re
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import urllib.request
import uuid

ZONE = "dns.mnebyvpn.site"
ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"
ALLOWED_KEYS = ("DNS_ADMIN_TELEGRAM_ID", "SUPPORT_TELEGRAM_OPERATOR_ID",
                "TELEGRAM_TOKEN_BOT")
DB_SHELL = ('PGPASSWORD="$POSTGRES_PASSWORD" exec psql -XAt '
            '-v ON_ERROR_STOP=1 -v VERBOSITY=sqlstate -h 127.0.0.1 '
            '-U "$POSTGRES_USER" -d "$POSTGRES_DB"')
DB_CONTAINER = "mnebyvpn-stage-postgres"


def env_values():
    result = {}
    for row in pathlib.Path("/opt/mnebyvpn/bot/web.env").read_text().splitlines():
        if not row or row.lstrip().startswith("#") or "=" not in row:
            continue
        key, val = row.split("=", 1)
        if key in ALLOWED_KEYS:
            result[key] = val.strip().strip('"').strip("'")
    owner = result.get("DNS_ADMIN_TELEGRAM_ID") or result.get(
        "SUPPORT_TELEGRAM_OPERATOR_ID", "")
    token = result.get("TELEGRAM_TOKEN_BOT", "")
    if not re.fullmatch(r"[1-9][0-9]{0,15}", owner):
        raise RuntimeError("OWNER_TELEGRAM_CONFIG_INVALID")
    if not re.fullmatch(r"[0-9]{5,20}:[A-Za-z0-9_-]{25,}", token):
        raise RuntimeError("BOT_TOKEN_CONFIG_INVALID")
    return int(owner), token


def sqlrun(sql: str) -> list[str]:
    r = subprocess.run(
        ["docker", "exec", "-i", DB_CONTAINER, "sh", "-c", DB_SHELL],
        input=sql, capture_output=True, text=True, timeout=25, check=False,
    )
    if r.returncode:
        # SQLSTATE contains no DNS bearer, user ID or application data.
        code = re.search(r"(?<![A-Z0-9])[0-9A-Z]{5}(?![A-Z0-9])", r.stderr)
        print("OWNER_PERSONAL_POSTGRES_SQLSTATE=" + (
            code.group(0) if code else "UNAVAILABLE"), flush=True)
        raise RuntimeError("POSTGRES_TRANSACTION_FAILED")
    return [v.strip() for v in r.stdout.splitlines() if v.strip()]


def new_label() -> str:
    n = secrets.randbelow(36 ** 12)
    label = ""
    for _ in range(12):
        n, rem = divmod(n, 36)
        label = ALPHABET[rem] + label
    assert re.fullmatch(r"[a-z0-9]{12}", label)
    return label


def create_trial(owner: int, label: str, order_id: uuid.UUID,
                 entitlement_id: uuid.UUID) -> None:
    token_sha256 = hashlib.sha256(label.encode("ascii")).hexdigest()
    owner_id = str(owner)
    assert re.fullmatch(r"[1-9][0-9]{0,15}", owner_id)
    assert re.fullmatch(r"[a-f0-9]{64}", token_sha256)
    sql = f"""
    BEGIN;
    SELECT set_config('mnebydns.test_owner_id', '{owner_id}', true) IS NOT NULL;
    SELECT set_config('mnebydns.test_label', '{label}', true) IS NOT NULL;
    SELECT set_config('mnebydns.test_sha256', '{token_sha256}', true) IS NOT NULL;
    DO $test$
    DECLARE
      v_account uuid;
      v_status text;
      v_order uuid := '{order_id}'::uuid;
      v_entitlement uuid := '{entitlement_id}'::uuid;
    BEGIN
      PERFORM pg_advisory_xact_lock(hashtext('mnebydns-owner-test-personal-dot'));
      SELECT a.id INTO v_account FROM accounts a
        WHERE a.telegram_user_id=current_setting('mnebydns.test_owner_id')::bigint
        FOR UPDATE;
      IF v_account IS NULL THEN
        RAISE EXCEPTION 'Owner account missing';
      END IF;
      IF EXISTS (
        SELECT 1 FROM entitlements
        WHERE account_id=v_account AND product='smart_dns'
          AND state='ACTIVE' AND expires_at>clock_timestamp()
      ) THEN RAISE EXCEPTION 'Owner already has active DNS entitlement'; END IF;
      IF EXISTS (SELECT 1 FROM billing_plans WHERE id='personal_dns_30d_stars'
                 AND enabled) THEN
        RAISE EXCEPTION 'Paid plan unexpectedly enabled'; END IF;
      INSERT INTO orders (id,account_id,product,provider,amount_minor,currency,state)
        VALUES(v_order,v_account,'smart_dns','internal_trial',0,'RUB','TRIAL');
      INSERT INTO entitlements (
        id,account_id,source_order_id,product,state,revision,starts_at,expires_at,
        quota_limit_bytes,dns_query_quota_per_30d
      ) VALUES (
        v_entitlement,v_account,v_order,'smart_dns','ACTIVE',1,
        clock_timestamp(),clock_timestamp()+INTERVAL '24 hours',NULL,1000000
      );
      SELECT issue_personal_dns_credential(
        v_entitlement,current_setting('mnebydns.test_label'),
        current_setting('mnebydns.test_sha256'),1000000
      ) INTO v_status;
      IF v_status <> 'ISSUED' THEN
        RAISE EXCEPTION 'Personal DNS credential provisioning denied';
      END IF;
      IF NOT recognize_personal_dns_credential(current_setting('mnebydns.test_label'))
      THEN RAISE EXCEPTION 'Personal credential not recognized'; END IF;
    END
    $test$;
    COMMIT;
    """
    sqlrun(sql)
    print("OWNER_PERSONAL_TRIAL_DB=COMMITTED_ACTIVE_24H", flush=True)


def cancel_trial(order: uuid.UUID, entitlement: uuid.UUID) -> None:
    """Compensate an undeliverable trial; never modify a paid entitlement."""
    try:
        sqlrun(f"""
        BEGIN;
        UPDATE personal_dns_credentials
          SET revoked_at=COALESCE(revoked_at,clock_timestamp())
          WHERE entitlement_id='{entitlement}'::uuid;
        UPDATE entitlements SET state='CANCELLED'
          WHERE id='{entitlement}'::uuid
            AND product='smart_dns' AND source_order_id='{order}'::uuid;
        UPDATE orders SET state='CANCELLED'
          WHERE id='{order}'::uuid AND provider='internal_trial' AND state='TRIAL'
            AND product='smart_dns';
        COMMIT;
        """)
        print("OWNER_TEST_FAILURE_COMPENSATION=TRIAL_REVOKED", flush=True)
    except Exception:
        print("OWNER_TEST_FAILURE_COMPENSATION=UNVERIFIED", flush=True)


def dns_probe(hostname: str) -> None:
    query_id = secrets.randbelow(65534) + 1
    q = (struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
         + b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1))
    with socket.create_connection(("10.66.77.2", 8856), timeout=8) as raw:
        raw.settimeout(8)
        with ssl.create_default_context().wrap_socket(
                raw, server_hostname=hostname) as tls:
            assert tls.getpeercert()
            tls.sendall(struct.pack("!H", len(q)) + q)
            prefix = tls.recv(2)
            if len(prefix) != 2:
                raise RuntimeError("PERSONAL_TEST_DOT_NO_RESPONSE")
            length = struct.unpack("!H", prefix)[0]
            if not 12 <= length <= 16384:
                raise RuntimeError("PERSONAL_TEST_DOT_BAD_FRAME")
            body = b""
            while len(body) < length:
                part = tls.recv(length - len(body))
                if not part:
                    raise RuntimeError("PERSONAL_TEST_DOT_TRUNCATED")
                body += part
            if body[:2] != q[:2] or not body[2] & 128:
                raise RuntimeError("PERSONAL_TEST_DOT_INVALID_RESPONSE")
    print("OWNER_PERSONAL_TRIAL_PRIVATE_DOT_REAL_QUERY=PASS", flush=True)


def send_private(owner: int, bot_token: str, hostname: str) -> None:
    msg = (
        "🔑 Ваш персональный Smart DNS — тест на 24 часа.\n\n"
        + hostname
        + "\n\nAndroid → Настройки → Частный DNS → "
          "Имя хоста провайдера частного DNS.\n"
          "Вставьте адрес целиком и сохраните. VPN для этого теста выключите.\n\n"
          "Доступ настоящий: запросы идут через персональный шлюз, "
          "платные маршруты доступны 24 часа, квота — до 1 000 000 "
          "успешных премиальных DNS-запросов за период.\n"
          "Адрес является секретным ключом. Не пересылайте его.\n\n"
          "После проверки сообщите, работает ли подключение "
          "через Wi-Fi и мобильную сеть."
    )
    payload = {
        "chat_id": owner, "text": msg, "protect_content": True,
        "reply_markup": {"inline_keyboard": [
            [{"text": "📋 Скопировать DNS",
              "copy_text": {"text": hostname}}]
        ]}
    }
    url = "https://api.telegram.org/bot" + bot_token + "/sendMessage"
    req = urllib.request.Request(
        url, data=json.dumps(payload, ensure_ascii=False).encode("utf8"),
        headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=17) as resp:
        result = json.load(resp)
    if result.get("ok") is not True or result.get("result", {}).get(
            "chat", {}).get("id") != owner:
        raise RuntimeError("TELEGRAM_PRIVATE_DELIVERY_NOT_ACKNOWLEDGED")
    print("OWNER_PERSONAL_TEST_KEY_SENT_IN_PRIVATE_TELEGRAM=PASS", flush=True)


def main() -> None:
    owner, bot_token = env_values()
    # No payment flags, old CoreDNS, or existing personal sidecars are changed.
    p = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", "mnebydns-personal-dot-private"],
        capture_output=True, text=True, timeout=8,
    )
    if p.returncode != 0 or p.stdout.strip() != "true":
        raise RuntimeError("PERSONAL_PRODUCTION_GATEWAY_NOT_RUNNING")
    label = new_label()
    hostname = label + "." + ZONE
    oid, eid = uuid.uuid4(), uuid.uuid4()
    create_trial(owner, label, oid, eid)
    try:
        dns_probe(hostname)
        send_private(owner, bot_token, hostname)
    except Exception:
        cancel_trial(oid, eid)
        raise
    print("OWNER_PERSONAL_TEST_TTL_HOURS=24")
    print("OWNER_PERSONAL_TEST_QUERY_QUOTA=1000000")
    print("OWNER_PERSONAL_PAID_PLAN_TOUCHED=false")
    print("OWNER_PERSONAL_FREE_LEGACY_DOT_TOUCHED=false")
    print("OWNER_PERSONAL_REAL_ANDROID_E2E=AWAITING_OWNER_TEST")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Explicitly avoid traceback, exception messages containing credentials,
        # request URLs, Telegram IDs or database connection strings.
        code = str(exc)
        code = code if re.fullmatch(r"[A-Z0-9_]{4,90}", code) else "UNCLASSIFIED"
        print("OWNER_PERSONAL_TEST_ISSUE_ERROR_CODE=" + code)
        print("OWNER_PERSONAL_TEST_ISSUE_ERROR_CLASS=" + type(exc).__name__)
        sys.exit(2)
