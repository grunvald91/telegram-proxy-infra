#!/usr/bin/env node
/**
 * RU188 real signed AWG outbox -> SSH forced command -> FI217 actual apply ->
 * real FI Ed25519 APPLIED_V1 receipt -> DISPOSABLE PostgreSQL ACK -> revoke.
 *
 * This is NOT a client entitlement. The only peer has no corresponding
 * private key, the public feature flag is modified ONLY in a fresh disposable
 * localhost PG container, and the production AWG worker remains disabled.
 */
import assert from 'node:assert/strict';
import {createHash,createPublicKey,randomBytes,randomUUID,verify} from 'node:crypto';
import {readFileSync,existsSync} from 'node:fs';
import {networkInterfaces} from 'node:os';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';

const RELEASE='/opt/mnebyvpn-controller/awg-worker-releases/6743387075102698ab23ec06de364d0d8efd1dca';
const {trustedControllerKey}=await import(pathToFileURL(RELEASE+'/apps/service/src/awg-controller-delivery-worker.ts').href);
const {awgControllerPayload,stageAwgRevoke}=await import(
  pathToFileURL(RELEASE+'/packages/provisioning/src/awg-controller-grants.ts').href);
const {deliverNextAwgCommand}=await import(
  pathToFileURL(RELEASE+'/packages/provisioning/src/awg-trusted-ssh-delivery.ts').href);
const {Pool}=createRequire(RELEASE+'/apps/service/src/awg-controller-delivery-worker.ts')('pg');

function deny(){throw Error('FI_AWG_E2E_BLOCKED');}
const stage=process.argv[2]??'';
if(process.getuid?.()!==0||
  !/^\/run\/fi-awg-real-e2e\.[A-Za-z0-9]{8}$/.test(stage)||
  !Object.values(networkInterfaces()).flat().some(x=>x?.address==='188.120.254.223')||
  existsSync('/root/mnebyvpn-controller/approvals/awg-delivery.enable'))deny();
const url=readFileSync(stage+'/url','utf8').trim();
if(!/^postgresql:\/\/fi_awg_e2e:[a-f0-9]{48}@127\.0\.0\.1:55434\/mnebyvpn_test$/.test(url))deny();
const signed=JSON.parse(readFileSync(stage+'/signed.json','utf8'));
if(signed.version!==1||signed.nodeId!=='fi-test-01'||signed.grant.op!=='grant'||
   signed.revoke.op!=='revoke'||signed.grant.revision!==1||
   signed.revoke.revision!==2||
   signed.grant.entitlementId!==signed.revoke.entitlementId||
   signed.grant.peerPublicKey!==signed.revoke.peerPublicKey||
   signed.grant.clientIpv4!=='10.73.91.254'||
   signed.revoke.clientIpv4!=='10.73.91.254'||
   Date.parse(signed.grant.expiresAt)-Date.now()<40_000)deny();
const controller=trustedControllerKey(
  '/root/mnebyvpn-controller/controller-signing-key.pem',
  'e4c862bd0171e5be4ae64770a555029e090d3a8fcfa5ef2a82ffb0b798552844');
for(const cmd of [signed.grant,signed.revoke]){
  if(!verify(null,awgControllerPayload(cmd),createPublicKey(controller),
      Buffer.from(cmd.signature,'base64url')))deny();
}
const nodeSpki=readFileSync('/root/mnebyvpn-controller/fi-node-public.spki');
assert.equal(createHash('sha256').update(nodeSpki).digest('hex'),
  'c3689b687e8888d15e3ece8e45cf7d01672b9dadb77b1963a7871ffd8e967ed9');
const fingerprint=nodeSpki.toString('base64url');
const db=new Pool({connectionString:url,max:2,connectionTimeoutMillis:2500,
                   idleTimeoutMillis:2000});
const id=signed.grant.entitlementId;
const checksum=cmd=>createHash('sha256').update(awgControllerPayload(cmd)).digest('hex');
const gate="vpn_awg_clients";
try{
  const chk=await db.query('SELECT current_database() AS db,current_user AS role');
  if(chk.rows[0]?.db!=='mnebyvpn_test'||chk.rows[0]?.role!=='fi_awg_e2e')deny();
  const feature=await db.query('SELECT enabled FROM vpn_release_flags WHERE feature=$1',[gate]);
  if(feature.rows.length!==1||feature.rows[0].enabled!==false)deny();
  const account=randomUUID(),order=randomUUID();
  await db.query('INSERT INTO accounts(id) VALUES($1)',[account]);
  await db.query(
    "INSERT INTO orders(id,account_id,product,amount_minor,currency,state) "+
    "VALUES($1,$2,'vpn',0,'RUB','PAID')",[order,account]);
  await db.query(
    "INSERT INTO entitlements(id,account_id,source_order_id,product,state,"+
    "revision,starts_at,expires_at) VALUES($1,$2,$3,'vpn','ACTIVE',11,$4,$5)",
    [id,account,order,new Date(Date.now()-30_000),
     new Date(signed.grant.expiresAt)]);
  // The disposable fixture must follow the EXISTING enrollment guard.
  // It is NOT a change to the production inventory or real node approval.
  await db.query(
    "INSERT INTO vpn_node_enrollment_inventory(node_id,endpoint_host,"+
    "identity_public_spki) VALUES('fi-test-01','fi.mnebyvpn.site',$1)",
    [fingerprint]);
  await db.query(
    "UPDATE vpn_node_enrollment_inventory SET status='approved',"+
    "approved_at=clock_timestamp() WHERE node_id='fi-test-01'");
  // The isolated database uses a disposable consumed enrollment challenge
  // as a fixture. Real FI node proof is separately required for signed ACK.
  await db.query(
    "INSERT INTO vpn_node_enrollment_challenges(challenge_id,node_id,"+
    "nonce_sha256,issued_at,expires_at,consumed_at) "+
    "VALUES($1,'fi-test-01',$2,clock_timestamp()-interval '1 second',"+
    "clock_timestamp()+interval '2 minutes',clock_timestamp())",
    [randomUUID(),randomBytes(32).toString('hex')]);
  await db.query(
    "UPDATE vpn_node_enrollment_inventory SET status='enrolled',"+
    "enrolled_at=clock_timestamp() WHERE node_id='fi-test-01'");
  await db.query(
    "INSERT INTO vpn_awg_node_pools(node_id,endpoint_host,server_public_key,"+
    "subnet_cidr,state,external_e2e_proof_sha256,verified_at) "+
    "VALUES('fi-test-01','fi.mnebyvpn.site',$1,'10.73.91.0/24','verified',$2,clock_timestamp())",
    [randomBytes(32).toString('base64'),'f'.repeat(64)]);
  await db.query(
    "INSERT INTO vpn_awg_peer_allocations(node_id,entitlement_id,peer_public_key,"+
    "client_ipv4,revision,expires_at,state,last_signed_at,last_command_sha256) "+
    "VALUES('fi-test-01',$1,$2,'10.73.91.254'::inet,1,$3,'staged',$4,$5)",
    [id,signed.grant.peerPublicKey,new Date(signed.grant.expiresAt),
     new Date(signed.grant.issuedAt),checksum(signed.grant)]);
  await db.query("UPDATE vpn_release_flags SET enabled=true WHERE feature=$1",[gate]);
  // The grant was independently signed by the REAL RU188 controller key;
  // seed it in the isolated outbox to preserve FI's audited .254 canary IP.
  const stageGrant=new Date();
  await db.query(
    "INSERT INTO vpn_awg_command_outbox(node_id,entitlement_id,revision,"+
    "billing_revision,op,signed_command,command_sha256,issued_at,expires_delivery_at) "+
    "VALUES('fi-test-01',$1,1,11,'grant',$2::jsonb,$3,$4,$5)",
    [id,JSON.stringify(signed.grant),checksum(signed.grant),
     stageGrant,new Date(stageGrant.getTime()+40_000)]);
  const transport={
    sshIdentityFile:'/root/mnebyvpn-controller/awg-delivery-ssh',
    pinnedKnownHostsFile:'/root/mnebyvpn-controller/awg-delivery-known_hosts',
  };
  console.log('FI_AWG_E2E=SIGNED_GRANT_IN_DISPOSABLE_OUTBOX');
  const applied=await deliverNextAwgCommand(db,controller,transport,new Date());
  if(applied.status!=='acknowledged')deny();
  const grant=await db.query(
    "SELECT state,node_receipt_sha256 FROM vpn_awg_command_outbox "+
    "WHERE node_id='fi-test-01' AND entitlement_id=$1 AND revision=1",[id]);
  const peer=await db.query(
    "SELECT state,revision FROM vpn_awg_peer_allocations "+
    "WHERE node_id='fi-test-01' AND entitlement_id=$1",[id]);
  if(grant.rows[0]?.state!=='applied'||
     !/^[a-f0-9]{64}$/.test(grant.rows[0]?.node_receipt_sha256??'')||
     peer.rows[0]?.state!=='applied'||peer.rows[0]?.revision!==1)deny();
  console.log('FI_AWG_E2E=REAL_FI_SIGNED_GRANT_ACK_PERSISTED');
  // The existing reviewed controller API constructs a fresh CAS revocation
  // using the real signing key, then the same real SSH transport applies it.
  await db.query("UPDATE vpn_release_flags SET enabled=false WHERE feature=$1",[gate]);
  const revoke=await stageAwgRevoke(db,{
    nodeId:'fi-test-01',entitlementId:id,
    expectedAllocationRevision:1,expectedAllocationState:'applied',
  },controller,new Date());
  if(revoke.command.revision!==2||revoke.command.op!=='revoke')deny();
  const revoked=await deliverNextAwgCommand(db,controller,transport,new Date());
  if(revoked.status!=='acknowledged')deny();
  const done=await db.query(
    "SELECT o.revision,o.state,o.node_receipt_sha256 "+
    "FROM vpn_awg_command_outbox o WHERE o.node_id='fi-test-01' "+
    "AND o.entitlement_id=$1 ORDER BY o.revision",[id]);
  const current=await db.query(
    "SELECT state,revision,expires_at FROM vpn_awg_peer_allocations "+
    "WHERE node_id='fi-test-01' AND entitlement_id=$1",[id]);
  if(done.rows.length!==2||done.rows.some(x=>x.state!=='applied'||
      !/^[a-f0-9]{64}$/.test(x.node_receipt_sha256??''))||
      current.rows[0]?.revision!==2||current.rows[0]?.state!=='revoked'||
      current.rows[0]?.expires_at!==null)deny();
  console.log('FI_AWG_E2E=REAL_FI_SIGNED_REVOKE_ACK_PERSISTED');
  console.log('FI_AWG_E2E=GRANT_ACK_REVOKE_ACK;ACK_COUNT=2;REAL_FI_SSH=true;'+
    'REAL_FI_PEER=true;CUSTOMER_RELEASE=false;DATABASE=DISPOSABLE');
}finally{
  await db.end();
}
