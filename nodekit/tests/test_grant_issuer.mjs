import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,verify} from 'node:crypto';
import {mkdtempSync,mkdirSync,writeFileSync,readdirSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {
  issueWebsiteGrant,readEd25519PublicKey,readEd25519PrivateKey,
  signNodeObservation,websiteReceiptMessage,
} from '../grant-issuer.mjs';
import {createNodeIdentity} from '../create-node-identity.mjs';

const now=new Date('2026-11-17T12:00:00.000Z');
const nonce='9'.repeat(64);
const entitlement={
  id:'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
  revision:6,state:'ACTIVE',product:'vpn',
  expiresAt:new Date(now.getTime()+86400_000).toISOString(),
};
const identity=generateKeyPairSync('ed25519');
const controller=generateKeyPairSync('ed25519');
const enrolledSpki=identity.publicKey.export({format:'der',type:'spki'}).toString('base64url');
const sampleNode={
  nodeId:'nl-node-02',
  state:'enabled',role:'combined',services:['vpn','dns','sni-proxy','tunnel'],
  countryCode:'NL',countryNameRu:'Нидерланды',
  endpointHost:'nl-node-02.nodes.example.net',endpointPort:2053,
  nodePublicSpki:enrolledSpki,
  exitCountryProofSha256:'a'.repeat(64),
  vpnE2eProofSha256:'b'.repeat(64),
  verifiedAt:now.toISOString(),
};
const profile='vless://12222222-3333-4333-8333-555555555555@'+
  sampleNode.endpointHost+':2053?encryption=none&security=reality'+
  '&type=tcp&flow=xtls-rprx-vision&sni=www.cloudflare.com&fp=chrome'+
  '&pbk='+('A'.repeat(43))+'&sid=ab12cd34ef56a789&spx=%2F';

function observed(){
  return signNodeObservation({
    nodeId:sampleNode.nodeId,
    entitlementId:entitlement.id,
    revision:entitlement.revision,
    expiresAt:entitlement.expiresAt,
    observedAt:now.toISOString(),
    profileUri:profile,
    nonce,nodeEnforcedExpiry:true,
  },identity.privateKey);
}

function issue(overrides={}){
  return issueWebsiteGrant({
    node:sampleNode,entitlement,observation:observed(),
    expectedNonce:nonce,controllerPrivateKey:controller.privateKey,
    now:now.getTime(),...overrides,
  });
}

test('node proof must match registered public key and controller challenge',()=>{
  const grant=issue();
  assert.equal(grant.node_id,'nl-node-02');
  assert.equal(grant.country_code,'NL');
  assert.equal(grant.country_name_ru,'Нидерланды');
  assert.equal(grant.entitlement_id,entitlement.id);
  assert.equal(grant.revision,entitlement.revision);
  assert.equal(grant.expires_at,entitlement.expiresAt);
  assert.ok(verify(null,websiteReceiptMessage(grant),controller.publicKey,
                   Buffer.from(grant.signature,'base64url')));
  const expectedBytes=Buffer.from(JSON.stringify([
    'MNEBYVPN_NODE_ACCESS_V1',
    grant.node_id,grant.country_code,grant.country_name_ru,
    grant.endpoint_host,grant.endpoint_port,grant.exit_country_proof_sha256,
    grant.vpn_e2e_proof_sha256,grant.entitlement_id,grant.revision,
    grant.expires_at,grant.observed_at,grant.profile_uri,
  ]));
  assert.deepEqual(websiteReceiptMessage(grant),expectedBytes);
});

test('forged, mismatched, stale, inactive and unapproved grants denied',()=>{
  const good=observed();
  const cases=[
    {observation:{...good,profileUri:profile.replace('security=reality','security=none')}},
    {observation:{...good,nonce:'0'.repeat(64)}},
    {expectedNonce:'0'.repeat(64)},
    {node:{...sampleNode,nodePublicSpki:
      generateKeyPairSync('ed25519').publicKey.export({format:'der',type:'spki'}).toString('base64url')}},
    {node:{...sampleNode,state:'testing'}},
    {node:{...sampleNode,state:'degraded'}},
    {node:{...sampleNode,role:'edge'}},
    {node:{...sampleNode,verifiedAt:new Date(now.getTime()-70*60_000).toISOString()}},
    {node:{...sampleNode,countryCode:'ZZ'}},
    {entitlement:{...entitlement,state:'EXPIRED'}},
    {entitlement:{...entitlement,revision:7}},
    {entitlement:{...entitlement,expiresAt:new Date(now.getTime()+2*86400_000).toISOString()}},
    {observation:{...good,observedAt:new Date(now.getTime()-16*60_000).toISOString()}},
    {observation:{...good,profileUri:profile+'&allowInsecure=true'}},
    {observation:{...good,signature:'0'.repeat(86)}},
  ];
  for(const changes of cases){
    assert.throws(()=>issue(changes),undefined,JSON.stringify(Object.keys(changes)));
  }
});

test('private key loader accepts Ed25519 DER only',()=>{
  const pkcs8=identity.privateKey.export({format:'der',type:'pkcs8'});
  assert.equal(readEd25519PrivateKey(pkcs8).asymmetricKeyType,'ed25519');
  assert.equal(readEd25519PublicKey(enrolledSpki).asymmetricKeyType,'ed25519');
  assert.throws(()=>readEd25519PrivateKey(Buffer.from('not a key')));
  assert.throws(()=>readEd25519PublicKey('not a public key'));
});

test('new VPS node identity is unique, private and immutable',()=>{
  const root=mkdtempSync(join(tmpdir(),'nodekit-identity-'));
  try{
    for(const node of ['de-node-01','nl-node-02']){
      const nodeRoot=join(root,node);
      mkdirSync(nodeRoot,{mode:0o700});
      writeFileSync(join(nodeRoot,'manifest.json'),JSON.stringify({
        node_id:node,state:'testing',registration_enabled:false,
      }),{mode:0o600});
    }
    const de=createNodeIdentity(root,'de-node-01',{requireRoot:false});
    const nl=createNodeIdentity(root,'nl-node-02',{requireRoot:false});
    assert.notEqual(de.identity_public_spki,nl.identity_public_spki);
    assert.equal(de.enabled,false);
    assert.equal(de.enrolled,false);
    assert.equal(JSON.stringify(de).includes('PRIVATE KEY'),false);
    assert.equal(readdirSync(join(root,'de-node-01','identity')).length,2);
    assert.equal(readFileSync(join(root,'de-node-01','identity','node-private.pk8')).length>0,true);
    assert.throws(()=>createNodeIdentity(root,'de-node-01',{requireRoot:false}));
    assert.throws(()=>createNodeIdentity(root,'../escape',{requireRoot:false}));
  }finally{
    rmSync(root,{recursive:true,force:true});
  }
});
