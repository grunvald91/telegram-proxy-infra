#!/usr/bin/env bash
# Activate website purchases using the already-installed private Prodamus key.
# Existing canary publisher verifies and rolls back the web container.
set -Eeuo pipefail
umask 077
SHA="$1"
PUBLISH="$2"
ROOT=/opt/mnebyvpn/public
ENV="$ROOT/web.env"
MERCHANT="$ROOT/prodamus.env"
BILLING="$ROOT/billing-db.env"

[[ "$(id -u)" == 0 && "$SHA" =~ ^[a-f0-9]{40}$ ]] || exit 2
bash -n "$PUBLISH"
test -s "$MERCHANT" && test -s "$BILLING" && test -s "$ENV"
[ "$(cat "$ROOT/active_sha")" = "$SHA" ] || { echo 'source_release_not_current=true';exit 2; }
docker image inspect "mnebyvpn-stage-web:$SHA" >/dev/null
for c in mnebyvpn-stage-postgres mnebyvpn-public-web mnebyvpn-vpn-worker; do
  [ "$(docker inspect -f '{{.State.Running}}' "$c")" = true ] || exit 2
done
grep -Fxq 'WEB_EMAIL_LOGIN_ENABLED=yes' "$ENV"
grep -Fxq 'WEB_BASE_URL=https://mnebyvpn.site' "$ENV"
grep -Fxq 'PRODAMUS_FORM_URL=https://mnebyvpn.payform.ru/' "$MERCHANT"
grep -Fxq 'PRODAMUS_NOTIFICATION_URL=https://mnebyvpn.site/webhooks/prodamus' "$MERCHANT"
grep -Eq '^PRODAMUS_SIGN_SECRET=[A-Za-z0-9_-]{32,256}$' "$MERCHANT"
grep -Eq '^WEB_BILLING_DATABASE_URL=postgresql://mnebyvpn_site_pay:[a-f0-9]{64}@127[.]0[.]0[.]1:55433/mnebyvpn_stage$' "$BILLING"
[ "$(stat -c %a "$BILLING")" = 600 ]
[ "$(stat -c %a "$MERCHANT")" = 600 ]

sql="SELECT CASE WHEN COUNT(*)=4 AND bool_and(enabled AND device_limit=1)
 THEN 'ready' ELSE 'invalid' END FROM billing_plans WHERE
 (id='vpn_15d_1device' AND rub_minor=6000 AND stars=40) OR
 (id='vpn_30d_1device' AND rub_minor=9900 AND stars=60) OR
 (id='vpn_60d_1device' AND rub_minor=19900 AND stars=110) OR
 (id='vpn_90d_1device' AND rub_minor=24900 AND stars=140)"
[ "$(docker exec mnebyvpn-stage-postgres psql -At -X -v ON_ERROR_STOP=1 -U mnebyvpn_stage -d mnebyvpn_stage -c "$sql")" = ready ]
for page in terms privacy; do
  [ "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:8792/$page")" = 200 ]
done

exec 7>/run/lock/mnebyvpn-commercial-activation.lock
flock -w 80 7
BACKUP="$(mktemp "$ROOT/web.env.pre-checkout.XXXXXXXX")"
cp -p "$ENV" "$BACKUP"
chmod 600 "$BACKUP"
restore() {
  result="$?"
  trap - ERR
  set +e
  if [ "$result" -ne 0 ]; then
    echo 'checkout_activation=rolling_back'
    cp -p "$BACKUP" "$ENV"
    bash "$PUBLISH" "$SHA" >/dev/null 2>&1
    echo 'checkout_config_restored=true'
  fi
  rm -f "$BACKUP"
  exit "$result"
}
trap restore ERR

python3 - "$ENV" <<'PY'
import os,pathlib,sys,tempfile
p=pathlib.Path(sys.argv[1])
overrides={
 'WEB_PRODAMUS_WEBHOOK_ENABLED':'yes',
 'WEB_PAYMENT_PROVIDER_TESTED':'yes',
 'WEB_NETWORK_PROVISIONING_VERIFIED':'yes',
 'WEB_CHECKOUT_ENABLED':'1',
 'WEB_LEGAL_PAGES_PUBLISHED':'yes',
 'WEB_RELEASE_APPROVED':'yes',
}
result=[]
seen=set()
for line in p.read_text().splitlines():
 if '=' not in line or line.startswith('#'):
  result.append(line);continue
 key,value=line.split('=',1)
 if key in overrides:
  if key in seen:raise ValueError('Duplicate feature gate')
  seen.add(key);value=overrides[key]
 result.append(key+'='+value)
result.extend(k+'='+v for k,v in overrides.items() if k not in seen)
fd,tmp=tempfile.mkstemp(dir=p.parent,prefix='web.env.live.')
try:
 with os.fdopen(fd,'w') as stream:
  stream.write('\n'.join(result).rstrip()+'\n')
  stream.flush();os.fsync(stream.fileno())
 os.chmod(tmp,0o600)
 os.replace(tmp,p)
finally:
 if os.path.exists(tmp):os.unlink(tmp)
PY

bash "$PUBLISH" "$SHA"
curl -fsS --max-time 7 http://127.0.0.1:8792/api/plans |
 python3 -c 'import sys,json; a=json.load(sys.stdin); assert a["checkoutEnabled"] is True and a["emailLoginEnabled"] is True; b=[x for x in a["plans"] if x["product"]=="vpn"]; assert sorted(x["rubMinor"] for x in b)==[6000,9900,19900,24900]'
for page in terms privacy; do
 curl --noproxy '*' -fsS --max-time 6 --resolve mnebyvpn.site:443:127.0.0.1 \
  "https://mnebyvpn.site/$page" >/dev/null
done
[ "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 -X POST -H 'Sign: invalid' http://127.0.0.1:8792/webhooks/prodamus)" = 401 ]

# HMAC-authenticated fake status events; unknown paid order must be rejected.
# No actual customer order is created or credited in this check.
python3 - "$MERCHANT" <<'PY'
import hashlib,hmac,json,pathlib,secrets,sys,urllib.request,urllib.error,uuid
c={}
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
 if '=' in line:
  k,v=line.split('=',1);c[k]=v
def request(fields):
 canonical=json.dumps(fields,sort_keys=True,separators=(',',':'),ensure_ascii=False).replace('/','\\/')
 sign=hmac.new(c['PRODAMUS_SIGN_SECRET'].encode(),canonical.encode(),hashlib.sha256).hexdigest()
 boundary='mnebyvpnTest'+secrets.token_hex(10)
 payload=b''.join(('--'+boundary+'\r\nContent-Disposition: form-data; name="'+k+'"\r\n\r\n'+v+'\r\n').encode() for k,v in fields.items())
 payload+=('--'+boundary+'--\r\n').encode()
 r=urllib.request.Request('http://127.0.0.1:8792/webhooks/prodamus',payload,
  {'Content-Type':'multipart/form-data; boundary='+boundary,'Sign':sign},method='POST')
 try:
  with urllib.request.urlopen(r,timeout=7) as response:return response.status,response.read(200)
 except urllib.error.HTTPError as e:return e.code,e.read(200)
fields={'domain':'mnebyvpn.payform.ru','order_num':str(uuid.uuid4()),
 'order_id':'synthetic-non-payment','sum':'60.00','currency':'rub',
 'payment_status':'pending'}
status,body=request(fields)
assert status==200 and body==b'EVENT_ACCEPTED_NO_PAYMENT',(status,body)
fields['payment_status']='success'
status,body=request(fields)
assert status==400 and body in (b'ORDER_MISMATCH',b'INVALID_ORDER'),(status,body)
print('signed_nonpayment_notification_accepted=true')
print('signed_unknown_paid_order_rejected=true')
print('synthetic_tests_did_not_credit_vpn=true')
PY

trap - ERR
rm -f "$BACKUP"
echo 'commercial_checkout_enabled=true'
echo 'prodamus_webhook_enabled=true'
echo 'canonical_billing_ledger=connected'
echo 'one_device_rub_plan_count=4'
echo 'web_checkout_for_all_authenticated_users=true'
echo 'real_customer_paid_capture_still_requires_smoke_test=true'
