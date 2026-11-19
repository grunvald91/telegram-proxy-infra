#!/usr/bin/env python3
"""Live RU188 restricted AWG worker PostgreSQL login probe. READ ONLY.

Tests the *actual* configured password + isolated Node runtime and pg@8.16.3
against the canonical loopback DB, rather than relying on superuser SET ROLE.
The signed worker remains inactive and client release disabled. No customer
rows or database connection strings are logged. Never executes a write.
"""
from __future__ import annotations

import subprocess
import sys

import fi_awg_worker_isolated_systemd_stage as stage
import fi_awg_worker_isolated_runtime_preflight as runtime

CODE = r"""
import {createRequire} from 'node:module';
import {readFileSync,lstatSync,existsSync} from 'node:fs';
import {networkInterfaces} from 'node:os';

const fail = ()=>{throw Error('readonly probe blocked')};
const mark=(name)=>process.stderr.write('FI_AWG_DB_CHECKPOINT='+name+'\n');
mark('HOST');
const root='/root/mnebyvpn-controller';
const release='/opt/mnebyvpn-controller/awg-worker-releases/c73ddaa237543d91dc81fb09eb3f371389dc618d';
const envfile=root+'/config/awg-delivery.env';
const approval=root+'/approvals/awg-delivery.enable';
const addresses=Object.values(networkInterfaces()).flat().filter(Boolean);
if(process.getuid?.()!==0||!addresses.some(x=>x.address==='188.120.254.223')||
   existsSync(approval))fail();
const st=lstatSync(envfile);
if(!st.isFile()||st.isSymbolicLink()||st.uid!==0||(st.mode&0o077)!==0||
   st.size<1||st.size>8192)fail();
mark('ENV');
const env=readFileSync(envfile,'utf8');
const single=(key)=>[...env.matchAll(new RegExp('^'+key+'=(\\S+)$','gm'))];
if(single('MNEBYVPN_ENV').length!==1||
   single('MNEBYVPN_ENV')[0][1]!=='production'||
   single('MNEBYVPN_AWG_DELIVERY_WORKER').length!==1||
   single('MNEBYVPN_AWG_DELIVERY_WORKER')[0][1]!=='enabled')fail();
const urls=single('DATABASE_URL');
if(urls.length!==1 ||
   !/^postgresql:\/\/mnebyvpn_awg_delivery:[a-f0-9]{64}@127\.0\.0\.1:55433\/mnebyvpn_stage$/.test(urls[0][1]))fail();
mark('MODULE');
const require=createRequire(release+'/apps/service/src/awg-controller-delivery-worker.ts');
const {Pool}=require('pg');
const pool=new Pool({
  connectionString:urls[0][1],max:1,connectionTimeoutMillis:3500,
  idleTimeoutMillis:2000,statement_timeout:4500,
});
let client;
try{
  mark('CONNECT');
  client=await pool.connect();
  mark('TRANSACTION');
  await client.query('BEGIN READ ONLY');
  mark('ROLE');
  const identity=await client.query('SELECT current_user AS role,current_database() AS db');
  if(identity.rows.length!==1||
     identity.rows[0].role!=='mnebyvpn_awg_delivery'||
     identity.rows[0].db!=='mnebyvpn_stage')fail();
  mark('RELEASE');
  const flag=await client.query(
    "SELECT enabled FROM public.vpn_release_flags WHERE feature='vpn_awg_clients'");
  if(flag.rows.length!==1||flag.rows[0].enabled!==false)fail();
  mark('ENROLLED');
  const node=await client.query(
    "SELECT status FROM public.vpn_node_enrollment_inventory WHERE node_id='fi-test-01'");
  if(node.rows.length!==1||node.rows[0].status!=='enrolled')fail();
  mark('OUTBOX');
  const outbox=await client.query(
    "SELECT count(*)::int AS n FROM public.vpn_awg_command_outbox "+
    "WHERE state IN ('queued','claimed')");
  if(outbox.rows.length!==1||!Number.isSafeInteger(outbox.rows[0].n))fail();
  mark('GATEWAYS');
  const funcs=await client.query(
    "SELECT "+
    "has_function_privilege(current_user,'public.awg_worker_lock_entitlement(uuid)','EXECUTE') AS e,"+
    "has_function_privilege(current_user,'public.awg_worker_lock_node(text)','EXECUTE') AS n,"+
    "has_function_privilege(current_user,'public.awg_worker_lock_pool(text)','EXECUTE') AS p,"+
    "has_function_privilege(current_user,'public.awg_worker_lock_pool_node(text)','EXECUTE') AS j");
  if(funcs.rows.length!==1||Object.values(funcs.rows[0]).some(x=>x!==true))fail();
  mark('POOL');
  const poolState=await client.query(
    "SELECT state,verified_at FROM public.vpn_awg_node_pools WHERE node_id='fi-test-01'");
  if(poolState.rows.length>1)fail();
  // A missing or stale FI pool is a real **client release blocker**, but not
  // a failed DB login. Never repair or invent E2E country proof here.
  const health=poolState.rows[0];
  const fresh=!!health&&health.state==='verified'&&
    health.verified_at instanceof Date&&
    Date.now()-health.verified_at.getTime()<=3600000&&
    health.verified_at.getTime()<=Date.now()+30000;
  const proof=health?(fresh?'FRESH':'STALE'):'MISSING';
  mark('ROLLBACK');
  await client.query('ROLLBACK');
  client.release();
  client=undefined;
  console.log('FI_AWG_DB_CONNECTION=PASS');
  console.log('FI_AWG_DB_DEDICATED_ROLE=PASS');
  console.log('FI_AWG_DB_RELEASE_DISABLED=PASS');
  console.log('FI_AWG_DB_FI_ENROLLED=PASS');
  console.log('FI_AWG_DB_OUTBOX_READ=PASS');
  console.log('FI_AWG_DB_LOCK_GATEWAYS=PASS');
  console.log('FI_AWG_DB_NODE_PROOF='+proof);
  console.log('FI_AWG_DB_PROBE=READONLY_READY;PRODUCTION_NODE_PROOF_FRESH='+
    String(fresh)+';WORKER_STARTED=false;CUSTOMER_RELEASE=false');
}catch(error){
  // Only a five-character SQLSTATE may escape; credentials or SQL never do.
  const code=typeof error?.code==='string'&&/^[A-Z0-9]{5}$/.test(error.code)
    ?error.code:'NONE';
  process.stderr.write('FI_AWG_DB_CHECK_SQLSTATE='+code+'\n');
  if(client)await client.query('ROLLBACK').catch(()=>{});
  throw Error('readonly probe blocked');
}finally{if(client)client.release();await pool.end();}
"""


def main() -> int:
    # All trust and service-state gates are independently rechecked before
    # touching the protected worker environment or opening any DB socket.
    stage.dormant_and_disabled()
    stage.approved_base_unit()
    stage.exact_effective_unit()
    stage.source_verified()
    result = subprocess.run(
        [str(runtime.trusted_node_binary()), "--input-type=module", "-e", CODE],
        capture_output=True, text=True, timeout=18, check=False,
        stdin=subprocess.DEVNULL)
    if result.returncode or len(result.stdout) > 1024:
        import re
        steps=re.findall(
            r"^FI_AWG_DB_CHECKPOINT=(HOST|ENV|MODULE|CONNECT|TRANSACTION|ROLE|"
            r"RELEASE|ENROLLED|OUTBOX|GATEWAYS|POOL|ROLLBACK)$",
            result.stderr,re.MULTILINE)
        if steps:
            print("FI_AWG_DB_BLOCKED_AT="+steps[-1])
        code=re.search(r"^FI_AWG_DB_CHECK_SQLSTATE=([A-Z0-9]{5}|NONE)$",
                       result.stderr,re.MULTILINE)
        if code:
            print("FI_AWG_DB_SQLSTATE="+code.group(1))
        print("FI_AWG_DB_PROBE=BLOCKED;WORKER_STARTED=false;CUSTOMER_RELEASE=false")
        return 2
    lines = result.stdout.splitlines()
    required = [
        "FI_AWG_DB_CONNECTION=PASS", "FI_AWG_DB_DEDICATED_ROLE=PASS",
        "FI_AWG_DB_RELEASE_DISABLED=PASS", "FI_AWG_DB_FI_ENROLLED=PASS",
        "FI_AWG_DB_OUTBOX_READ=PASS", "FI_AWG_DB_LOCK_GATEWAYS=PASS",
    ]
    if (len(lines) != 8 or any(lines.count(item) != 1 for item in required) or
            lines[6] not in ("FI_AWG_DB_NODE_PROOF=FRESH",
                             "FI_AWG_DB_NODE_PROOF=STALE",
                             "FI_AWG_DB_NODE_PROOF=MISSING") or
            lines[7] != (
                "FI_AWG_DB_PROBE=READONLY_READY;PRODUCTION_NODE_PROOF_FRESH=" +
                ("true" if lines[6].endswith("FRESH") else "false") +
                ";WORKER_STARTED=false;CUSTOMER_RELEASE=false")):
        print("FI_AWG_DB_PROBE=BLOCKED;WORKER_STARTED=false;CUSTOMER_RELEASE=false")
        return 2
    for row in lines:
        print(row)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, TypeError, RuntimeError, KeyError,
            UnicodeError, subprocess.TimeoutExpired):
        print("FI_AWG_DB_PROBE=BLOCKED;WORKER_STARTED=false;CUSTOMER_RELEASE=false")
        raise SystemExit(2)
