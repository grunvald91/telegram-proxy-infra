#!/usr/bin/env python3
"""Server188 ONLY: least-privilege MNEBYVPN auth DB role, zero secret logging."""
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile

ROOT=Path('/opt/mnebyvpn')
ENV=ROOT/'public/auth-db.env'
ROLE='mnebyvpn_site_auth'
DB='mnebyvpn_stage'

def run_sql(sql:str)->None:
    call=subprocess.run(['docker','exec','-i','mnebyvpn-stage-postgres',
        'psql','-v','ON_ERROR_STOP=1','-U','mnebyvpn_stage','-d',DB,
        '-q','-X'],input=sql,text=True,capture_output=True,timeout=40)
    if call.returncode:
        # stderr can contain statements with sensitive passwords. Never show it.
        raise RuntimeError('Canonical PostgreSQL auth GRANT failed; details suppressed')

def main()->None:
    if os.geteuid()!=0:
        raise RuntimeError('Database setup requires server root')
    if ENV.exists():
        raw=ENV.read_text().strip()
        m=re.fullmatch(r'WEB_AUTH_DATABASE_URL=postgresql://mnebyvpn_site_auth:([0-9a-f]{64})@127\.0\.0\.1:55433/mnebyvpn_stage',raw)
        if not m:raise RuntimeError('Unknown preexisting auth database config')
        password=m.group(1)
    else:
        password=secrets.token_hex(32)
    sql=f"""
BEGIN;
DO $role$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{ROLE}') THEN
   CREATE ROLE {ROLE} LOGIN;
 END IF;
END
$role$;
ALTER ROLE {ROLE} LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
GRANT CONNECT ON DATABASE {DB} TO {ROLE};
GRANT USAGE ON SCHEMA public TO {ROLE};
GRANT SELECT(id, telegram_user_id, email_address), INSERT(id,email_address),
      UPDATE(email_address,telegram_user_id) ON public.accounts TO {ROLE};
GRANT SELECT,INSERT,UPDATE,DELETE ON
      public.website_sessions,public.web_email_codes TO {ROLE};
GRANT SELECT,INSERT,UPDATE ON public.web_email_rate_limits TO {ROLE};
GRANT SELECT ON public.entitlements,public.orders,public.order_terms,
      public.provisioning_state,public.vpn_subscription_links TO {ROLE};
GRANT INSERT(token_sha256,entitlement_id) ON public.vpn_subscription_links TO {ROLE};
COMMIT;
"""
    run_sql(sql)
    if not ENV.exists():
        text=f"WEB_AUTH_DATABASE_URL=postgresql://{ROLE}:{password}@127.0.0.1:55433/{DB}\n"
        fd,tmp=tempfile.mkstemp(dir=str(ENV.parent),prefix='auth-db.env.')
        try:
            with os.fdopen(fd,'w') as out:
                out.write(text);out.flush();os.fsync(out.fileno())
            os.chmod(tmp,0o600)
            os.replace(tmp,ENV)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    ENV.chmod(0o600)
    # Ensure this role cannot settle orders or alter paid entitlements.
    verify=f"""
DO $check$
BEGIN
 IF NOT (
   has_column_privilege('{ROLE}','public.accounts','email_address','UPDATE')
   AND has_table_privilege('{ROLE}','public.web_email_codes','INSERT')
   AND has_table_privilege('{ROLE}','public.web_email_rate_limits','UPDATE')
   AND has_table_privilege('{ROLE}','public.website_sessions','INSERT')
   AND has_table_privilege('{ROLE}','public.entitlements','SELECT')
   AND NOT has_table_privilege('{ROLE}','public.orders','INSERT')
   AND NOT has_table_privilege('{ROLE}','public.entitlements','UPDATE')
 ) THEN
   RAISE EXCEPTION 'Auth DB grant check failed';
 END IF;
END;
$check$;
"""
    run_sql(verify)
    print('canonical_auth_db_role_ready=true')
    print('auth_role_order_writes_disabled=true')
    print('auth_db_private_env_mode=600')

if __name__=='__main__':main()
