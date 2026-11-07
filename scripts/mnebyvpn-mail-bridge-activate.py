#!/usr/bin/env python3
"""Server188 ONLY. Activate authenticated ServGo email login without enabling
trial, checkout, Telegram OIDC or any unrelated production feature.
Never print shared secrets, OTPs, tokens or customer email addresses.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT=Path('/opt/mnebyvpn')
WEB_ENV=ROOT/'public/web.env'
KEY=ROOT/'private/mail-bridge-oaep.pem'
BACKUP=ROOT/'private/mail-login-prev.env'
ENDPOINT='https://servgo.ru/api/auth/mnebyvpn/email-code'
BASE='http://127.0.0.1:8792'
PRODUCTION_SHA='23334b455ff6100b40a0df877a21ca107961ff36'
RECIPIENT='Grunvaldlab@gmail.com'

def request(url:str, data:bytes|None=None, headers:dict|None=None)->tuple[int,bytes]:
    req=urllib.request.Request(url,method='POST' if data is not None else 'GET',
        data=data,headers=headers or {})
    try:
        with urllib.request.urlopen(req,timeout=12) as resp:
            return resp.status,resp.read(65536)
    except urllib.error.HTTPError as exc:
        return exc.code,exc.read(65536)

def encrypted_secret(blob_path:Path)->str:
    if not KEY.is_file():
        raise RuntimeError('Private mail decryption key unavailable on server 188')
    blob=base64.b64decode(blob_path.read_text().strip(),validate=True)
    if len(blob)!=384:
        raise RuntimeError('Invalid RSA-3072 ciphertext size')
    result=subprocess.run(['openssl','pkeyutl','-decrypt','-inkey',str(KEY),
        '-pkeyopt','rsa_padding_mode:oaep','-pkeyopt','rsa_oaep_md:sha256'],
        input=blob,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
        check=True,timeout=15)
    secret=result.stdout.decode('ascii')
    if not re.fullmatch(r'[0-9a-f]{96}',secret):
        raise RuntimeError('Invalid decrypted mail credential')
    return secret

def prove_servgo_shared_key(secret:str)->None:
    # Malformed signed payload proves signature acceptance without dispatching
    # an actual code, claiming a nonce, or creating a subscriber.
    raw=b'{"probe":"signature-only-no-email"}'
    timestamp=str(int(time.time()))
    nonce=secrets.token_urlsafe(32)
    signed=timestamp.encode()+b'.'+nonce.encode()+b'.'+raw
    mac=hmac.new(secret.encode(),signed,hashlib.sha256).hexdigest()
    code,body=request(ENDPOINT,raw,{
      'Content-Type':'application/json',
      'X-Mnebyvpn-Timestamp':timestamp,
      'X-Mnebyvpn-Nonce':nonce,
      'X-Mnebyvpn-Signature':mac,
    })
    if code!=400 or b'Invalid request' not in body:
        raise RuntimeError('ServGo did not validate shared HMAC signature')
    print('servgo_hmac_signature_verified=true')

def set_email_login(secret:str)->None:
    if os.geteuid()!=0:
        raise RuntimeError('Activation requires root')
    if not (ROOT/'public/auth-db.env').is_file():
        raise RuntimeError('Scoped canonical auth database was not provisioned')
    if (ROOT/'public/active_sha').read_text().strip()!=PRODUCTION_SHA:
        raise RuntimeError('Production SHA changed; refuse to update unrelated release')
    current=WEB_ENV.read_text()
    for must in (
      'MNEBYVPN_ENV=production',
      'WEB_CHECKOUT_ENABLED=0',
      'WEB_TRIAL_ENABLED=no',
      'WEB_PRODAMUS_WEBHOOK_ENABLED=no',
      'WEB_TELEGRAM_OIDC_ENABLED=no',
      'WEB_NETWORK_PROVISIONING_VERIFIED=no',
    ):
        if must not in current.splitlines():
            raise RuntimeError('Production safety flag changed: '+must.split('=')[0])
    if BACKUP.exists():
        raise RuntimeError('Previous activation rollback record exists')
    BACKUP.parent.mkdir(mode=0o700,exist_ok=True)
    BACKUP.write_bytes(current.encode())
    BACKUP.chmod(0o600)
    newlines=[x for x in current.splitlines()
        if not x.startswith('MNEBYVPN_MAIL_GATEWAY_SECRET=')
        and not x.startswith('WEB_EMAIL_LOGIN_ENABLED=')]
    newlines+=['MNEBYVPN_MAIL_GATEWAY_SECRET='+secret,'WEB_EMAIL_LOGIN_ENABLED=yes']
    newtext='\n'.join(newlines)+'\n'
    fd,tmp=tempfile.mkstemp(prefix='web.env.mail.',dir=str(WEB_ENV.parent))
    try:
        with os.fdopen(fd,'w') as stream:
            stream.write(newtext)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp,0o600)
        os.replace(tmp,WEB_ENV)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    print('web_email_config_staged=true')

def verify_enabled()->None:
    code,body=request(BASE+'/api/plans')
    if code!=200:
        raise RuntimeError('Website plans unavailable after email activation')
    plans=json.loads(body)
    if not(plans.get('emailLoginEnabled') is True and
           plans.get('loginEnabled') is True and
           plans.get('checkoutEnabled') is False and
           plans.get('trialOffers')==[]):
        raise RuntimeError('Email login or commercial safety gate mismatch')
    code,body=request(BASE+'/auth/login')
    if code!=503:
        raise RuntimeError('Unexpected Telegram OIDC authentication enabled')
    code,body=request(BASE+'/readyz')
    if code!=503:
        raise RuntimeError('Unexpected VPN commercial readiness')
    # Independently exercise the exact TLS/fetch stack used inside the
    # production Node container. A signed malformed payload must return 400.
    js = """
const {createHmac,randomBytes}=require('node:crypto');
const ts=String(Math.floor(Date.now()/1000));
const nonce=randomBytes(24).toString('base64url');
const raw=JSON.stringify({probe:'signed-only'});
const signature=createHmac('sha256',process.env.MNEBYVPN_MAIL_GATEWAY_SECRET)
  .update(ts+'.'+nonce+'.'+raw).digest('hex');
fetch('https://servgo.ru/api/auth/mnebyvpn/email-code',{
  method:'POST',redirect:'error',signal:AbortSignal.timeout(7000),
  headers:{'Content-Type':'application/json','X-Mnebyvpn-Timestamp':ts,
           'X-Mnebyvpn-Nonce':nonce,'X-Mnebyvpn-Signature':signature},
  body:raw
}).then(r=>console.log('node_mail_gateway_status='+r.status))
  .catch(e=>{console.log('node_mail_gateway_error='+String(e.cause?.code||e.name));process.exitCode=2;});
"""
    probe=subprocess.run(['docker','exec','mnebyvpn-public-web','node','-e',js],
        capture_output=True,text=True,timeout=14)
    for line in probe.stdout.splitlines():
        if re.fullmatch(r'node_mail_gateway_(status|error)=[A-Za-z0-9_]+',line):
            print(line)
    if probe.returncode!=0 or 'node_mail_gateway_status=400' not in probe.stdout:
        raise RuntimeError('Node runtime could not validate ServGo HMAC mail gateway')
    payload=json.dumps({'email':RECIPIENT},separators=(',',':')).encode()
    code,body=request(BASE+'/api/auth/email/start',payload,{
      'Content-Type':'application/json',
      'Origin':'https://mnebyvpn.site',
    })
    if code!=200 or json.loads(body).get('status')!='CODE_SENT':
        try: failure=json.loads(body).get('code','UNEXPECTED_RESPONSE')
        except Exception: failure='NON_JSON_RESPONSE'
        if not re.fullmatch(r'[A-Z_]{2,50}',str(failure)):
            failure='UNRECOGNIZED_ERROR'
        raise RuntimeError('Live email code round trip failed: HTTP '+str(code)+' '+failure)
    print('email_otp_dispatch_via_web=accepted')
    print('web_login_enabled=true')
    print('vpn_checkout_enabled=false')
    print('vpn_trial_enabled=false')

def rollback()->None:
    if BACKUP.is_file():
        WEB_ENV.write_bytes(BACKUP.read_bytes())
        WEB_ENV.chmod(0o600)
        BACKUP.unlink()
    print('email_login_configuration_rolled_back=true')

def finalize()->None:
    if BACKUP.is_file():BACKUP.unlink()
    print('email_login_configuration_committed=true')

def main():
    mode=sys.argv[1] if len(sys.argv)>1 else ''
    if mode=='stage':
        if len(sys.argv)!=3:raise RuntimeError('Expected ciphertext path')
        secret=encrypted_secret(Path(sys.argv[2]))
        prove_servgo_shared_key(secret)
        set_email_login(secret)
    elif mode=='verify':
        verify_enabled()
    elif mode=='rollback':
        rollback()
    elif mode=='finalize':
        finalize()
    else:raise RuntimeError('Unknown operation')

if __name__=='__main__':
    main()
