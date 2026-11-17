import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,verify} from 'node:crypto';
import {
  signedNodeAccessCommand,nodeAccessCommandPayload,NodekitAccessError,
  readControllerAccessPrivateKey,
} from '../controller-access.mjs';

test('controller signs canonical versioned Xray access command',()=>{
  const pair=generateKeyPairSync('ed25519');
  const privateKey=readControllerAccessPrivateKey(
    pair.privateKey.export({type:'pkcs8',format:'der'}));
  const now=Date.parse('2026-11-17T09:00:00.000Z');
  const command={
    nodeId:'nl-node-02',op:'apply',
    id:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    revision:4,enabled:true,
    expiresAt:new Date(now+3600000).toISOString(),
    issuedAt:new Date(now).toISOString(),
    nonce:'a'.repeat(64),
  };
  const signed=signedNodeAccessCommand(command,privateKey,now);
  assert.equal(verify(null,nodeAccessCommandPayload(signed),
    pair.publicKey,Buffer.from(signed.signature,'base64url')),true);
  assert.equal(nodeAccessCommandPayload(signed).toString(),
    JSON.stringify(['MNEBYVPN_NODEKIT_ACCESS_V1',
      command.nodeId,command.op,command.id,command.revision,
      command.enabled,command.expiresAt,command.issuedAt,command.nonce]));
  for(const mutation of [
    {...signed,id:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'},
    {...signed,revision:5},{...signed,enabled:false},
    {...signed,nodeId:'de-node-02'},
    {...signed,expiresAt:new Date(now+7200000).toISOString()},
  ]){
    assert.equal(verify(null,nodeAccessCommandPayload(mutation),
      pair.publicKey,Buffer.from(signed.signature,'base64url')),false);
  }
});
test('controller prevents stale / unbounded / malformed / unauthorized commands',()=>{
  const pair=generateKeyPairSync('ed25519');
  const now=Date.parse('2026-11-17T09:00:00.000Z');
  const base={
    nodeId:'nl-node-02',op:'apply',
    id:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',revision:1,
    enabled:true,expiresAt:new Date(now+3600000).toISOString(),
    issuedAt:new Date(now).toISOString(),nonce:'b'.repeat(64),
  };
  for(const mutation of [
    {...base,revision:0},{...base,enabled:'true'},
    {...base,expiresAt:new Date(now+101*86400000).toISOString()},
    {...base,issuedAt:new Date(now-100000).toISOString()},
    {...base,nonce:'123'}, {...base,op:'shell'},
    {...base,nodeId:'../prod'}, {...base,id:'0'.repeat(16)},
    {...base,enabled:false},
    {...base,op:'inspect',revision:1},
  ])assert.throws(()=>signedNodeAccessCommand(mutation,pair.privateKey,now),
    NodekitAccessError);
  assert.throws(()=>signedNodeAccessCommand(base,pair.publicKey,now),
    NodekitAccessError);
  const revoke=signedNodeAccessCommand(
    {...base,revision:2,enabled:false,expiresAt:null},pair.privateKey,now);
  assert.equal(revoke.enabled,false);
  const inspect=signedNodeAccessCommand({
    ...base,op:'inspect',revision:null,enabled:null,expiresAt:null,
  },pair.privateKey,now);
  assert.equal(inspect.revision,null);
});
