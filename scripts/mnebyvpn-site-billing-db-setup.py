#!/usr/bin/env python3
"""Idempotent private least-privilege web billing role on existing VPN database.

Does not enable live charges, migrate customer data, alter VPN nodes or
change public nginx. Keeps the public brochure/support DB separate.
"""
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile

ROOT=Path('/opt/mnebyvpn')
ENV=ROOT/'public/billing-db.env'
ROLE='mnebyvpn_site_pay'
DB='mnebyvpn_stage'
PATTERN=re.compile(r'WEB_BILLING_DATABASE_URL=postgresql://mnebyvpn_site_pay:([a-f0-9]{64})@127\.0\.0\.1:55433/mnebyvpn_stage')

def sql_exec(query):
    cp=subprocess.run([
        'docker','exec','-i','mnebyvpn-stage-postgres','psql',
        '-X','-q','-v','ON_ERROR_STOP=1','-U','mnebyvpn_stage','-d',DB,
    ],input=query,text=True,capture_output=True,timeout=45)
    if cp.returncode:
        # postgres may echo the ALTER ROLE password in diagnostics.
        raise RuntimeError('Scoped billing role SQL failed; confidential stderr suppressed')

def main():
    if os.geteuid()!=0:raise RuntimeError('Server root required')
    if ENV.exists():
        m=PATTERN.fullmatch(ENV.read_text().strip())
        if not m:raise RuntimeError('Existing billing config differs; manual review required')
        password=m.group(1)
    else:password=secrets.token_hex(32)
    # No billing role may write web login codes or impersonate accounts.
    # SQL functions perform the actual credit/refund/outbox transition; the
    # dedicated role only touches enumerated billing ledger tables.
    query=f"""
BEGIN;
DO $newrole$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{ROLE}') THEN
    CREATE ROLE {ROLE} LOGIN;
  END IF;
END
$newrole$;
ALTER ROLE {ROLE} LOGIN PASSWORD '{password}'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT CONNECT ON DATABASE {DB} TO {ROLE};
GRANT USAGE ON SCHEMA public TO {ROLE};

GRANT SELECT ON public.accounts,public.billing_plans,public.trial_offers,
  public.referral_invites,public.provisioning_state TO {ROLE};
-- SELECT ... FOR UPDATE/SHARE requires UPDATE on at least one column.
-- Do not allow this role to edit email, telegram IDs or published prices.
GRANT UPDATE(created_at) ON public.accounts TO {ROLE};
GRANT UPDATE(title) ON public.billing_plans TO {ROLE};

GRANT SELECT,INSERT ON public.orders TO {ROLE};
GRANT UPDATE(state) ON public.orders TO {ROLE};
GRANT SELECT,INSERT ON public.order_terms,public.checkout_requests,
  public.order_referrals TO {ROLE};
GRANT SELECT,INSERT ON public.order_renewals TO {ROLE};
GRANT UPDATE(applied_at) ON public.order_renewals TO {ROLE};

GRANT SELECT,INSERT ON public.provider_captures,public.verified_payment_events,
  public.reconcile_outbox TO {ROLE};
GRANT SELECT,INSERT,UPDATE ON public.payment_delivery_receipts TO {ROLE};
GRANT SELECT,INSERT,UPDATE ON public.entitlement_credits TO {ROLE};
GRANT SELECT,INSERT,UPDATE ON public.entitlements TO {ROLE};

GRANT EXECUTE ON FUNCTION public.record_payment_delivery(text,text,text,text)
  TO {ROLE};
GRANT EXECUTE ON FUNCTION public.settle_verified_payment(
  uuid,text,text,text,text,bigint,text,bigint,bigint) TO {ROLE};
GRANT EXECUTE ON FUNCTION public.apply_verified_refund(
  uuid,text,text,text,text) TO {ROLE};
COMMIT;
"""
    sql_exec(query)
    # Reuse existing identity on subsequent runs; rotate explicitly, never
    # overwrite a previously deployed key or log it to GitHub Actions.
    if not ENV.exists():
        ENV.parent.mkdir(parents=True,exist_ok=True)
        fd,temp=tempfile.mkstemp(prefix='billing-db.env.',dir=str(ENV.parent))
        try:
            with os.fdopen(fd,'w') as f:
                f.write('WEB_BILLING_DATABASE_URL=postgresql://'
                    +ROLE+':'+password+'@127.0.0.1:55433/'+DB+'\n')
                f.flush();os.fsync(f.fileno())
            os.chmod(temp,0o600)
            os.replace(temp,ENV)
        finally:
            if os.path.exists(temp):os.unlink(temp)
    ENV.chmod(0o600)
    sql_exec(f"""
DO $verify$
BEGIN
IF NOT (
  has_table_privilege('{ROLE}','public.orders','INSERT')
  AND has_table_privilege('{ROLE}','public.billing_plans','SELECT')
  AND has_table_privilege('{ROLE}','public.entitlements','INSERT')
  AND has_function_privilege('{ROLE}',
    'public.settle_verified_payment(uuid,text,text,text,text,bigint,text,bigint,bigint)','EXECUTE')
  AND NOT has_table_privilege('{ROLE}','public.web_email_codes','SELECT')
  AND NOT has_table_privilege('{ROLE}','public.website_sessions','INSERT')
  AND NOT has_table_privilege('{ROLE}','public.accounts','INSERT')
) THEN RAISE EXCEPTION 'Website payment role privileges mismatch'; END IF;
END;
$verify$;
""")
    print('canonical_website_billing_role=ready')
    print('private_payment_db_config=ready_mode_600')
    print('public_checkout_untouched=true')
    print('VPN_and_existing_traffic_unmodified=true')

if __name__=='__main__':main()
