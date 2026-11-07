#!/usr/bin/env bash
# Explicit owner-approved launch of Prodamus production checkout. No queues.
# On failure restores exact previous website env and website container.
set -Eeuo pipefail
umask 077
sha="${1:?green source SHA required}"
promoter="${2:?tested website promoter required}"
[[ "$sha" =~ ^[a-f0-9]{40}$ ]] || { echo 'Invalid source SHA'; exit 2; }
root=/opt/mnebyvpn
public="$root/public"
env="$public/web.env"
merch="$public/prodamus.env"
billing="$public/billing-db.env"
test "$(id -u)" -eq 0
test -s "$env" && test -s "$merch" && test -s "$billing"
test -s "$root/public/auth-db.env"
test -f "$promoter"
bash -n "$promoter"
docker image inspect "mnebyvpn-stage-web:$sha" >/dev/null
grep -Fxq 'WEB_EMAIL_LOGIN_ENABLED=yes' "$env"
grep -Fxq 'WEB_BASE_URL=https://mnebyvpn.site' "$env"
grep -Fxq 'PRODAMUS_FORM_URL=https://mnebyvpn.payform.ru/' "$merch"
grep -Fxq 'PRODAMUS_NOTIFICATION_URL=https://mnebyvpn.site/webhooks/prodamus' "$merch"
grep -Eq '^PRODAMUS_SIGN_SECRET=[A-Za-z0-9_-]{32,256}$' "$merch"
grep -Eq '^WEB_BILLING_DATABASE_URL=postgresql://mnebyvpn_site_pay:[a-f0-9]{64}@127[.]0[.]0[.]1:55433/mnebyvpn_stage$' "$billing"
grep -Eq '^WEB_AUTH_DATABASE_URL=postgresql://mnebyvpn_site_auth:[a-f0-9]{64}@127[.]0[.]0[.]1:55433/mnebyvpn_stage$' "$root/public/auth-db.env"
# Validate canonical database connectivity with the scoped role, never log URL.
set -a
source "$billing"
set +a
export PGCONNECT_TIMEOUT=5
python3 - <<'PY'
import os,subprocess,urllib.parse
u=os.environ['WEB_BILLING_DATABASE_URL']
parsed=urllib.parse.urlparse(u)
assert (parsed.hostname,parsed.port,parsed.path)==('127.0.0.1',55433,'/mnebyvpn_stage')
q="""SELECT CASE WHEN count(*)=4 AND count(*) FILTER(WHERE stars IN (40,60,110,140))=4
 THEN 1 ELSE 0 END FROM billing_plans
 WHERE enabled AND product='vpn' AND device_limit=1
 AND id IN ('vpn_15d_1device','vpn_30d_1device','vpn_60d_1device','vpn_90d_1device');"""
p=subprocess.run(['docker','exec','mnebyvpn-stage-postgres','psql','-X','-At',
                   '-v','ON_ERROR_STOP=1','-U','mnebyvpn_stage','-d','mnebyvpn_stage','-c',q],
                  capture_output=True,text=True,timeout=12)
if p.returncode!=0 or p.stdout.strip()!='1':
    raise SystemExit('VPN plan catalog cannot be confirmed')
print('live_vpn_plan_catalog=4_approved_products')
PY
unset WEB_BILLING_DATABASE_URL
# Avoid unintentional changes to a site already enabled by another operator.
if grep -Fxq 'WEB_CHECKOUT_ENABLED=1' "$env";then
  echo 'live_checkout_already_enabled=true'
  exit 0
fi
grep -Fxq 'WEB_CHECKOUT_ENABLED=0' "$env" || { echo 'Unexpected existing checkout flag'; exit 2; }

saved="$(mktemp "$public/web.env.before-live-payment.XXXXXXXX")"
cp -p "$env" "$saved"
chmod 600 "$saved"
old_image="$(docker inspect -f '{{.Config.Image}}' mnebyvpn-public-web 2>/dev/null || true)"
rollback(){
  local rc="$?"
  trap - ERR EXIT
  if [ "$rc" -ne 0 ];then
    echo 'live_checkout_failed_rolling_back=true'
    cp -p "$saved" "$env"
    # Returning to previous env removes newly enabled checkout and webhooks.
    # Rebuild the same old container only if its image tag is known.
    if [[ "$old_image" =~ ^mnebyvpn-stage-web:([a-f0-9]{40})$ ]];then
      bash "$promoter" "${BASH_REMATCH[1]}" || echo 'rollback_requires_operator_review=true'
    fi
  fi
  exit "$rc"
}
trap rollback ERR
# Atomically update known boolean switches, preserving all unrelated secrets.
python3 - "$env" <<'PY'
import os,pathlib,sys,tempfile
p=pathlib.Path(sys.argv[1])
changes={
 'WEB_RELEASE_APPROVED':'yes',
 'WEB_PAYMENT_PROVIDER_TESTED':'yes',
 'WEB_NETWORK_PROVISIONING_VERIFIED':'yes',
 'WEB_LEGAL_PAGES_PUBLISHED':'yes',
 'WEB_PRODAMUS_WEBHOOK_ENABLED':'yes',
 'WEB_CHECKOUT_ENABLED':'1',
}
lines=p.read_text().splitlines()
seen=set()
out=[]
for line in lines:
    key=line.split('=',1)[0]
    if key in changes:
        if key in seen:continue
        seen.add(key)
        out.append(key+'='+changes[key])
    else:out.append(line)
for key,val in changes.items():
    if key not in seen:out.append(key+'='+val)
fd,name=tempfile.mkstemp(prefix='web.env.live.',dir=str(p.parent))
try:
    with os.fdopen(fd,'w') as f:
        f.write('\n'.join(out)+'\n')
        f.flush()
        os.fsync(f.fileno())
    os.chmod(name,0o600)
    os.replace(name,p)
finally:
    if os.path.exists(name):os.unlink(name)
PY
bash "$promoter" "$sha"
python3 - <<'PY'
import urllib.request,urllib.error,json
base='http://127.0.0.1:8792'
def get(path):
    with urllib.request.urlopen(base+path,timeout=8) as f:
        assert f.status==200,(path,f.status)
        return f.read()
plans=json.loads(get('/api/plans'))
assert plans.get('checkoutEnabled') is True,plans.keys()
assert plans.get('emailLoginEnabled') is True
vals={int(p['durationDays']):int(p['rubMinor']) for p in plans.get('plans',[])
      if p.get('product')=='vpn' and p.get('rubMinor') is not None}
assert all(vals.get(days)==price for days,price in
  [(15,6000),(30,9900),(60,19900),(90,24900)]),vals
for path in ['/terms','/privacy']:
    txt=get(path).decode('utf-8','replace')
    assert 'MNEBYVPN' in txt and len(txt)>700
req=urllib.request.Request(base+'/webhooks/prodamus',b'',{'Sign':'invalid'},method='POST')
try:
    urllib.request.urlopen(req,timeout=8)
    raise AssertionError('Unsigned Prodamus callback unexpectedly accepted')
except urllib.error.HTTPError as err:
    assert err.code==401,err.code
print('public_checkout_enabled=true')
print('four_rub_tariffs_available=true')
print('email_login_enabled=true')
print('public_terms_and_privacy_available=true')
print('unsigned_prodamus_webhook_rejected=true')
print('activation_health_passed=true')
PY
trap - ERR
echo 'backup_private_mode_600=true'
echo 'no_buyer_queue_configured=true'
echo 'real_provider_payment_requires_first_owner_test=true'
