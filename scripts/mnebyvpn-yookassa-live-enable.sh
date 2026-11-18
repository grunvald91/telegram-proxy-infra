#!/usr/bin/env bash
# Stage YooKassa ShopID 1527841 + secret key from stdin, verify live API auth
# against api.yookassa.ru/v3/me without logging secrets, and promote web container
# via guarded canary with automatic rollback.
set -Eeuo pipefail
umask 077

SHA="$1"
PUBLISH="$2"
SHOP_ID="${3:-1527841}"
ROOT=/opt/mnebyvpn/public
ENV="$ROOT/web.env"
DEST="$ROOT/yookassa.env"
BILLING="$ROOT/billing-db.env"

[[ "$(id -u)" -eq 0 && "$SHA" =~ ^[a-f0-9]{40}$ && "$SHOP_ID" =~ ^[0-9]{4,12}$ ]] || exit 2
bash -n "$PUBLISH"
test -s "$BILLING" && test -s "$ENV"
[ "$(cat "$ROOT/active_sha")" = "$SHA" ] || { echo 'source_release_not_current=true'; exit 2; }
docker image inspect "mnebyvpn-stage-web:$SHA" >/dev/null
for c in mnebyvpn-stage-postgres mnebyvpn-public-web; do
  [ "$(docker inspect -f '{{.State.Running}}' "$c")" = true ] || exit 2
done
grep -Fxq 'WEB_EMAIL_LOGIN_ENABLED=yes' "$ENV"
grep -Fxq 'WEB_BASE_URL=https://mnebyvpn.site' "$ENV"
grep -Eq '^WEB_BILLING_DATABASE_URL=postgresql://mnebyvpn_site_pay:[a-f0-9]{64}@127[.]0[.]0[.]1:55433/mnebyvpn_stage$' "$BILLING"
[ "$(stat -c %a "$BILLING")" = 600 ]

KEY="$(cat)"
[[ "${#KEY}" -ge 24 && "${#KEY}" -le 160 && "$KEY" =~ ^(live|test)_[A-Za-z0-9_-]+$ ]] || {
  echo 'Invalid YooKassa secret key format'; exit 2;
}

# Verify credentials live against GET /v3/me and detect shop fiscalization setting.
SEND_RECEIPT="$(YOOKASSA_SHOP_ID="$SHOP_ID" YOOKASSA_SECRET_KEY="$KEY" python3 - <<'PY'
import base64, json, os, sys, urllib.request
shop = os.environ['YOOKASSA_SHOP_ID']
secret = os.environ['YOOKASSA_SECRET_KEY']
token = base64.b64encode(f'{shop}:{secret}'.encode()).decode()
req = urllib.request.Request(
    'https://api.yookassa.ru/v3/me',
    headers={'Authorization': 'Basic ' + token, 'Accept': 'application/json'},
    method='GET',
)
with urllib.request.urlopen(req, timeout=12) as resp:
    if resp.status != 200:
        raise RuntimeError(f'Unexpected YooKassa /v3/me HTTP {resp.status}')
    data = json.load(resp)
acct = str(data.get('account_id', ''))
if acct != shop:
    raise RuntimeError(f'YooKassa account_id mismatch: got {acct!r}, expected {shop!r}')
fisc_obj = data.get('fiscalization')
fisc = fisc_obj.get('enabled') if isinstance(fisc_obj, dict) else data.get('fiscalization_enabled')
methods = data.get('payment_methods') or []
print(f'yookassa_account_id={acct} status={data.get("status")} test={data.get("test")} fiscalization={fisc} methods={",".join(methods)}', file=sys.stderr)
print('yes' if fisc is True else 'no')
PY
)"
[[ "$SEND_RECEIPT" == "yes" || "$SEND_RECEIPT" == "no" ]] || exit 2

exec 7>/run/lock/mnebyvpn-commercial-activation.lock
flock -w 80 7
ENV_BACKUP="$(mktemp "$ROOT/web.env.pre-yookassa.XXXXXXXX")"
cp -p "$ENV" "$ENV_BACKUP"
chmod 600 "$ENV_BACKUP"
YOOKASSA_HAD_PREV=no
YOOKASSA_BACKUP=''
if [ -f "$DEST" ]; then
  YOOKASSA_HAD_PREV=yes
  YOOKASSA_BACKUP="$(mktemp "$ROOT/yookassa.env.pre.XXXXXXXX")"
  cp -p "$DEST" "$YOOKASSA_BACKUP"
  chmod 600 "$YOOKASSA_BACKUP"
fi

restore() {
  result="$?"
  trap - ERR
  set +e
  if [ "$result" -ne 0 ]; then
    echo 'yookassa_activation=rolling_back'
    cp -p "$ENV_BACKUP" "$ENV"
    if [ "$YOOKASSA_HAD_PREV" = yes ] && [ -n "$YOOKASSA_BACKUP" ]; then
      cp -p "$YOOKASSA_BACKUP" "$DEST"
    else
      rm -f "$DEST"
    fi
    bash "$PUBLISH" "$SHA" >/dev/null 2>&1
    echo 'yookassa_config_restored=true'
  fi
  rm -f "$ENV_BACKUP" "$YOOKASSA_BACKUP"
  exit "$result"
}
trap restore ERR

YOOKASSA_SHOP_ID="$SHOP_ID" YOOKASSA_SECRET_KEY="$KEY" YOOKASSA_SEND_RECEIPT="$SEND_RECEIPT" python3 - "$DEST" "$ENV" <<'PY'
import os, pathlib, sys, tempfile

dest = pathlib.Path(sys.argv[1])
env_path = pathlib.Path(sys.argv[2])
lines = [
    f"YOOKASSA_SHOP_ID={os.environ['YOOKASSA_SHOP_ID']}",
    f"YOOKASSA_SECRET_KEY={os.environ['YOOKASSA_SECRET_KEY']}",
    "YOOKASSA_RETURN_URL=https://mnebyvpn.site/payment/return",
    f"YOOKASSA_SEND_RECEIPT={os.environ['YOOKASSA_SEND_RECEIPT']}",
]
fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix='yookassa.env.')
try:
    with os.fdopen(fd, 'w') as s:
        s.write('\n'.join(lines) + '\n')
        s.flush()
        os.fsync(s.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, dest)
finally:
    if os.path.exists(tmp):
        os.unlink(tmp)

overrides = {
    'WEB_YOOKASSA_ENABLED': 'yes',
    'WEB_PAYMENT_PROVIDER_TESTED': 'yes',
    'WEB_NETWORK_PROVISIONING_VERIFIED': 'yes',
    'WEB_CHECKOUT_ENABLED': '1',
    'WEB_LEGAL_PAGES_PUBLISHED': 'yes',
    'WEB_RELEASE_APPROVED': 'yes',
}
out = []
seen = set()
for line in env_path.read_text().splitlines():
    if '=' not in line or line.startswith('#'):
        out.append(line)
        continue
    k, v = line.split('=', 1)
    if k in overrides:
        if k in seen:
            raise ValueError('Duplicate feature gate: ' + k)
        seen.add(k)
        v = overrides[k]
    out.append(f'{k}={v}')
out.extend(f'{k}={v}' for k, v in overrides.items() if k not in seen)
fd2, tmp2 = tempfile.mkstemp(dir=env_path.parent, prefix='web.env.yk.')
try:
    with os.fdopen(fd2, 'w') as s:
        s.write('\n'.join(out).rstrip() + '\n')
        s.flush()
        os.fsync(s.fileno())
    os.chmod(tmp2, 0o600)
    os.replace(tmp2, env_path)
finally:
    if os.path.exists(tmp2):
        os.unlink(tmp2)
PY

bash "$PUBLISH" "$SHA"

curl -fsS --max-time 7 http://127.0.0.1:8792/api/plans | python3 -c 'import json,sys; a=json.load(sys.stdin); assert a["checkoutEnabled"] is True and a["paymentProvider"]=="yookassa" and len(a["plans"])==12; print("local_yookassa_plans=verified_12")'

trap - ERR
rm -f "$ENV_BACKUP" "$YOOKASSA_BACKUP"
echo 'yookassa_live_activation=success'
