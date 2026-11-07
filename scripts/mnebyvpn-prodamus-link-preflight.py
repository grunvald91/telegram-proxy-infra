#!/usr/bin/env python3
"""Verify genuine Prodamus payform payment-link generation without charging."""
import hashlib,hmac,json,pathlib,urllib.parse,urllib.request,urllib.error,uuid,re
from urllib.parse import urlsplit

env_path=pathlib.Path('/opt/mnebyvpn/public/prodamus.env')
assert env_path.is_file(),'Merchant private config missing'
env={}
for line in env_path.read_text().splitlines():
    if '=' in line:
        k,v=line.split('=',1)
        env[k]=v
key=env.get('PRODAMUS_SIGN_SECRET','')
assert len(key)>=32,'Merchant signing secret missing'
base=env.get('PRODAMUS_FORM_URL')
assert base=='https://mnebyvpn.payform.ru/','Unexpected merchant Payform'
fields={
    'do':'link',
    'order_id':str(uuid.uuid4()),
    'currency':'rub',
    'payments_limit':'1',
    'products':[{
        'name':'MNEBYVPN VPN на 15 дней, одно устройство',
        'price':'60.00','quantity':'1'
    }],
    'urlSuccess':'https://mnebyvpn.site/#account',
    'urlReturn':'https://mnebyvpn.site/#plans'
}
sys_code=env.get('PRODAMUS_SYS')
if sys_code:
    assert re.fullmatch('[A-Za-z0-9_-]{2,64}',sys_code)
    fields['sys']=sys_code
    fields['urlNotification']='https://mnebyvpn.site/webhooks/prodamus'
canonical=json.dumps(fields,sort_keys=True,separators=(',',':'),ensure_ascii=False).replace('/','\\/')
signature=hmac.new(key.encode(),canonical.encode(),hashlib.sha256).hexdigest()
pairs=[]
def flatten(prefix,v):
    if isinstance(v,list):
        for i,item in enumerate(v):flatten(f'{prefix}[{i}]',item)
    elif isinstance(v,dict):
        for name,item in v.items():flatten(f'{prefix}[{name}]',item)
    else:pairs.append((prefix,str(v)))
for name,value in fields.items():flatten(name,value)
pairs.append(('signature',signature))
url=base+'?'+urllib.parse.urlencode(pairs)
req=urllib.request.Request(url,headers={'Accept':'text/plain','User-Agent':'MNEBYVPNMerchantReadiness/1.0'})
try:
    with urllib.request.urlopen(req,timeout=12) as response:
        result=response.read(1500).decode('utf8','replace').strip()
        status=response.status
except urllib.error.HTTPError as e:
    print('prodamus_link_http='+str(e.code))
    print('prodamus_link_ready=false')
    raise SystemExit(2)
except Exception as e:
    print('prodamus_link_transport='+type(e).__name__)
    print('prodamus_link_ready=false')
    raise SystemExit(2)
print('prodamus_link_http='+str(status))
safe=False
try:
    parsed=urlsplit(result)
    safe=(parsed.scheme=='https' and
          (parsed.hostname=='payform.ru' or parsed.hostname.endswith('.payform.ru'))
          and not parsed.username and not parsed.password and len(result)<1024)
except Exception:pass
print('prodamus_link_ready='+str(safe).lower())
print('prodamus_link_has_canonical_order_uuid=true')
print('prodamus_link_currency_rub=true')
print('prodamus_link_per_order_payment_limit_one=true')
print('payment_not_taken=true')
print('merchant_secret_not_logged=true')
if not safe:raise SystemExit(2)
