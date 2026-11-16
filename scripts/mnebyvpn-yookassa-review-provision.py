#!/usr/bin/env python3
"""Operator-only MNEBYVPN reviewer bootstrap. Never prints credentials or SQL."""
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import urllib.request
import uuid
from pathlib import Path

ROOT=Path('/opt/mnebyvpn')
MAILBOX='yookassa-review@mnebyvpn.site'

def settings(path):
    return dict(line.split('=',1) for line in path.read_text().splitlines()
                if line and not line.startswith('#') and '=' in line)

def db(sql):
    result=subprocess.run(['docker','exec','-i','mnebyvpn-stage-postgres','psql',
            '-X','-v','ON_ERROR_STOP=1','-qAt','-U','mnebyvpn_stage','-d','mnebyvpn_stage'],
        input=sql,text=True,capture_output=True,timeout=25)
    if result.returncode:
        raise RuntimeError('Database step failed; details deliberately suppressed')
    return result.stdout.strip()

def call(path,payload=None,cookie=None,csrf=None):
    headers={'Origin':'https://mnebyvpn.site','Content-Type':'application/json'}
    if cookie: headers['Cookie']=cookie
    if csrf: headers['X-CSRF-Token']=csrf
    data=None if payload is None else json.dumps(payload).encode()
    request=urllib.request.Request('http://127.0.0.1:8792'+path,
        data=data,headers=headers,method='GET' if data is None else 'POST')
    with urllib.request.urlopen(request,timeout=8) as response:
        return response.status,json.load(response),response.headers.get('Set-Cookie')

def revoke():
    db("""BEGIN;
        UPDATE web_review_login SET enabled=false,updated_at=clock_timestamp()
          WHERE singleton=true;
        UPDATE website_sessions SET revoked_at=clock_timestamp()
          WHERE account_id=(SELECT account_id FROM web_review_login WHERE singleton=true)
          AND revoked_at IS NULL;
        COMMIT;""")

def main():
    if os.geteuid()!=0 or len(sys.argv)!=2 or not re.fullmatch('[0-9a-f]{40}',sys.argv[1]):
        raise RuntimeError('Required root and verified source commit SHA')
    if (ROOT/'public/active_sha').read_text().strip()!=sys.argv[1]:
        raise RuntimeError('Deployed website is not the expected tested source SHA')
    web=settings(ROOT/'public/web.env')
    bot=settings(ROOT/'bot/worker.env')
    if web.get('WEB_BASE_URL')!='https://mnebyvpn.site' or web.get('WEB_EMAIL_LOGIN_ENABLED')!='yes':
        raise RuntimeError('Public email login not enabled')
    pepper=web.get('WEB_SESSION_SECRET','')
    token=bot.get('TELEGRAM_TOKEN_BOT',web.get('TELEGRAM_TOKEN_BOT',''))
    operator=bot.get('SUPPORT_TELEGRAM_OPERATOR_ID',web.get('SUPPORT_TELEGRAM_OPERATOR_ID',''))
    if len(pepper)<32 or not re.fullmatch('[0-9]{5,20}:[A-Za-z0-9_-]{25,}',token) or not re.fullmatch('[1-9][0-9]{0,15}',operator):
        raise RuntimeError('Private reviewer delivery configuration unavailable')
    role=db("""SELECT
      to_regclass('public.web_review_login') IS NOT NULL AND
      has_table_privilege('mnebyvpn_site_auth','public.web_review_login','SELECT') AND
      has_column_privilege('mnebyvpn_site_auth','public.web_review_login','failed_attempts','UPDATE')
    """)
    if role!='t':raise RuntimeError('Reviewer schema or scoped role permission missing')
    old=db("SELECT count(*) FROM web_review_login WHERE singleton=true")
    if old not in ('0','1'):raise RuntimeError('Unexpected reviewer schema state')
    if old=='1':
        existing=db("SELECT a.email_address||'|'||coalesce(a.telegram_user_id::text,'') FROM accounts a JOIN web_review_login l ON l.account_id=a.id WHERE l.singleton=true")
        if existing!=MAILBOX+'|':raise RuntimeError('Reviewer account identity changed; refusing rotation')
    else:
        collision=db("SELECT count(*) FROM accounts WHERE email_address='"+MAILBOX+"'")
        if collision!='0':raise RuntimeError('Reviewer email already belongs to customer')
    code=f'{secrets.randbelow(100000000):08d}'
    salt=secrets.token_hex(16)
    digest=hashlib.scrypt((MAILBOX+':'+code+':'+pepper).encode(),
        salt=bytes.fromhex(salt),n=16384,r=8,p=1,dklen=32,maxmem=64*1024*1024).hex()
    account_id=str(uuid.uuid4())
    # No plaintext code in SQL, subprocess args, GitHub secrets, or logs.
    db(f"""BEGIN;
        INSERT INTO accounts(id,email_address)
          SELECT '{account_id}'::uuid,'{MAILBOX}'
          WHERE NOT EXISTS(SELECT 1 FROM web_review_login WHERE singleton=true);
        INSERT INTO web_review_login(singleton,account_id,email,code_salt,code_hash,enabled)
          VALUES(true,
            coalesce((SELECT account_id FROM web_review_login WHERE singleton=true),'{account_id}'::uuid),
            '{MAILBOX}','{salt}','{digest}',true)
          ON CONFLICT(singleton) DO UPDATE SET
            code_salt=EXCLUDED.code_salt,code_hash=EXCLUDED.code_hash,
            enabled=true,failed_attempts=0,locked_until=NULL,updated_at=clock_timestamp();
        UPDATE website_sessions SET revoked_at=clock_timestamp()
          WHERE account_id=(SELECT account_id FROM web_review_login WHERE singleton=true)
          AND revoked_at IS NULL;
        COMMIT;""")
    try:
        for _ in range(2):
            status,start,_=call('/api/auth/email/start',{'email':MAILBOX})
            if status!=200 or start.get('status')!='REVIEW_CODE_REQUIRED':
                raise RuntimeError('Live review start check failed')
            status,verified,set_cookie=call('/api/auth/email/verify',{'email':MAILBOX,'code':code})
            if status!=200 or verified.get('status')!='SIGNED_IN' or not set_cookie:
                raise RuntimeError('Live review code check failed')
            cookie=set_cookie.split(';',1)[0]
            status,me,_=call('/api/me',cookie=cookie)
            if status!=200 or me.get('identity',{}).get('email')!=MAILBOX:
                raise RuntimeError('Live account isolation check failed')
            status,_,_=call('/api/logout',{},cookie=cookie,csrf=me['csrf'])
            if status!=200:raise RuntimeError('Live logout check failed')
        message=('MNEBYVPN / ЮKassa: тестовый доступ\\n'
                 'Вход: https://mnebyvpn.site/#account\\n'
                 'Email: '+MAILBOX+'\\n'
                 'Постоянный код: '+code+'\\n'
                 'Передайте проверяющему через личный защищённый канал.')
        req=urllib.request.Request('https://api.telegram.org/bot'+token+'/sendMessage',
            data=json.dumps({'chat_id':int(operator),'text':message}).encode(),
            headers={'Content-Type':'application/json'},method='POST')
        with urllib.request.urlopen(req,timeout=15) as response:
            result=json.load(response)
        if result.get('ok') is not True:
            raise RuntimeError('Private code delivery could not be confirmed')
    except Exception:
        revoke()
        raise RuntimeError('Review login disabled because smoke test or private delivery failed') from None
    finally:
        code=None
        digest=None
    print('reviewer_live_login_verified=true')
    print('reviewer_credentials_delivered_to_operator=true')

if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(str(exc),file=sys.stderr)
        sys.exit(1)
