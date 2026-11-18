import assert from 'node:assert/strict';
import {generateKeyPairSync,verify} from 'node:crypto';
import test from 'node:test';
import {signedAwgLease,awgLeasePayload} from '../awg-lease-signer.mjs';

const {privateKey,publicKey}=generateKeyPairSync('ed25519');
const base={
  nodeId:'fi-test-01',op:'grant',
  entitlementId:'11111111-2222-4333-8444-555555555555',
  revision:1,
  peerPublicKey:Buffer.from(Array.from({length:32},(_,i)=>i)).toString('base64'),
  clientIpv4:'10.73.91.2',
  expiresAt:'2026-11-18T04:30:00.000Z',
  issuedAt:'2026-11-18T04:00:00.000Z',
  nonce:'a'.repeat(64)
};
const now=Date.parse(base.issuedAt);

test('controller produces valid Ed25519 signature over canonical peer lease tuple',()=>{
  const signed=signedAwgLease(base,privateKey,now);
  assert(verify(null,awgLeasePayload(signed),publicKey,
    Buffer.from(signed.signature,'base64url')));
  assert.equal(JSON.parse(awgLeasePayload(signed))[0],'MNEBYVPN_AWG_LEASE_V1');
  assert.equal(Object.hasOwn(signed,'privateKey'),false);
});

test('revocation requires null expiry and an increased revision is caller responsibility',()=>{
  const signed=signedAwgLease({...base,op:'revoke',revision:2,expiresAt:null},
    privateKey,now);
  assert(verify(null,awgLeasePayload(signed),publicKey,
    Buffer.from(signed.signature,'base64url')));
  assert.throws(()=>signedAwgLease({...base,op:'revoke'},privateKey,now));
});

test('rejects grants outside configured AWG subnet, expired or invalid keys',()=>{
  for(const diff of [
    {clientIpv4:'10.73.91.1'}, {clientIpv4:'10.73.91.255'},
    {clientIpv4:'192.168.1.2'}, {clientIpv4:'10.73.91.02'},
    {expiresAt:base.issuedAt}, {expiresAt:null},
    {peerPublicKey:'bad'}, {revision:0}, {nodeId:'../fi'},
  ]){
    assert.throws(()=>signedAwgLease({...base,...diff},privateKey,now));
  }
});

test('signer cannot operate with public key only',()=>{
  assert.throws(()=>signedAwgLease(base,publicKey,now));
});

test('signed offline grants stay within seven days, no per-session network approval',()=>{
  const day=24*60*60*1000;
  const ok=signedAwgLease({...base,expiresAt:new Date(now+7*day).toISOString()},
    privateKey,now);
  assert(verify(null,awgLeasePayload(ok),publicKey,
    Buffer.from(ok.signature,'base64url')));
  assert.throws(()=>signedAwgLease({
    ...base,expiresAt:new Date(now+7*day+1).toISOString(),
  },privateKey,now));
});
