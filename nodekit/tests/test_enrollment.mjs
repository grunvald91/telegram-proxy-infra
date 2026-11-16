import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createPublicKey,sign,verify} from 'node:crypto';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createNodeIdentity} from '../create-node-identity.mjs';
import {
  createEnrollmentResponse,controllerChallengeBytes,enrollmentResponseBytes,
  signEnrollmentFile,
} from '../sign-enrollment.mjs';

test('controller-signed challenge produces per-VPS possession proof only',()=>{
  const dir=mkdtempSync(join(tmpdir(),'nodekit-enroll-'));
  const id='nl-amsterdam-02';
  const nodeDir=join(dir,id);
  const host='nl02.nodes.example.net';
  try{
    mkdirSync(nodeDir,{mode:0o700});
    writeFileSync(join(nodeDir,'manifest.json'),JSON.stringify({
      node_id:id,advertise_host:host,state:'testing',registration_enabled:false,
    }),{mode:0o600});
    const identity=createNodeIdentity(dir,id,{requireRoot:false});
    const ctl=generateKeyPairSync('ed25519');
    const ctlPub=ctl.publicKey.export({format:'der',type:'spki'});
    const challenge={
      nodeId:id,endpointHost:host,publicSpki:identity.identity_public_spki,
      challengeId:'11111111-2222-4333-8444-555555555555',
      nonce:'a'.repeat(43),
      expiresAt:new Date(Date.now()+120000).toISOString(),
      controllerSignature:'',
    };
    challenge.controllerSignature=sign(null,controllerChallengeBytes(challenge),
      ctl.privateKey).toString('base64url');
    const challengeFile=join(nodeDir,'enrollment-challenge.json');
    const ctlFile=join(nodeDir,'controller-public.spki');
    const responseFile=join(nodeDir,'enrollment-response.json');
    writeFileSync(challengeFile,JSON.stringify(challenge),{mode:0o600});
    writeFileSync(ctlFile,ctlPub,{mode:0o600});
    const output=signEnrollmentFile({
      stageRoot:dir,nodeId:id,challengeFile,
      controllerKeyFile:ctlFile,responseFile,
    });
    assert.equal(output.signed,true);
    const proof=JSON.parse(readFileSync(responseFile,'utf8'));
    assert.equal(proof.nodeId,id);
    assert.equal(proof.endpointHost,host);
    assert.equal(verify(null,enrollmentResponseBytes(proof),
      ctl.publicKey,Buffer.from(proof.signature,'base64url')),false);
    const nodePub=ctl.publicKey; // independent control identity
    assert.equal(nodePub.asymmetricKeyType,'ed25519');
    const actualNodePub=readFileSync(join(nodeDir,'identity','node-public.spki'));
    const publicKey=createPublicKey({
      key:actualNodePub,format:'der',type:'spki',
    });
    assert.equal(verify(null,enrollmentResponseBytes(proof),publicKey,
      Buffer.from(proof.signature,'base64url')),true);
    assert.throws(()=>signEnrollmentFile({
      stageRoot:dir,nodeId:id,challengeFile,
      controllerKeyFile:ctlFile,responseFile,
    }),/EEXIST/);
    const tampered={...challenge,endpointHost:'evil.example.net'};
    assert.throws(()=>createEnrollmentResponse(nodeDir,tampered,ctlPub),/staged node/);
    const falseSig={...challenge,nonce:'b'.repeat(43)};
    assert.throws(()=>createEnrollmentResponse(nodeDir,falseSig,ctlPub),/signature/);
    const old={...challenge,expiresAt:new Date(Date.now()-10).toISOString()};
    assert.throws(()=>createEnrollmentResponse(nodeDir,old,ctlPub),/Expired/);
    const stranger=generateKeyPairSync('ed25519').publicKey.export({format:'der',type:'spki'});
    assert.throws(()=>createEnrollmentResponse(nodeDir,challenge,stranger),/signature/);
  }finally{rmSync(dir,{recursive:true,force:true});}
});
