#!/usr/bin/env node
/**
 * Local possession proof for an operator-approved new Nodekit server.
 *
 * The controller challenge MUST be signed by a pinned enrollment authority.
 * This CLI NEVER enables services, changes routes, or publishes subscribers.
 * It writes a private response file (0600) instead of printing nonce/signature
 * into GitHub Actions or web logs.
 */
import {
  createHash,createPrivateKey,createPublicKey,sign,verify,
} from 'node:crypto';
import {
  existsSync,lstatSync,mkdirSync,readFileSync,writeFileSync,
} from 'node:fs';
import {resolve,join} from 'node:path';
import {fileURLToPath} from 'node:url';

const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const NONCE=/^[A-Za-z0-9_-]{43}$/;
const SIG=/^[A-Za-z0-9_-]{86}$/;
const NODE=/^[a-z0-9][a-z0-9-]{2,39}$/;

export class NodekitEnrollmentError extends Error {}
function ownedFile(path,uid,{minSize=1,maxSize=16384}={}){
  const st=lstatSync(path);
  if(!st.isFile()||st.isSymbolicLink()||st.uid!==uid||
     (st.mode&0o077)!==0||st.size<minSize||st.size>maxSize)
    throw new NodekitEnrollmentError('Enrollment file is not a protected regular file');
  return readFileSync(path);
}
function protectedDir(path,uid) {
  const st=lstatSync(path);
  if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==uid||
     (st.mode&0o077)!==0)
    throw new NodekitEnrollmentError('Enrollment directory is not protected');
}
export function controllerChallengeBytes(challenge){
  return Buffer.from(JSON.stringify([
    'MNEBYVPN_ENROLL_CHALLENGE_V1',
    challenge.nodeId,challenge.endpointHost,challenge.publicSpki,
    challenge.challengeId,challenge.nonce,challenge.expiresAt,
  ]),'utf8');
}
export function enrollmentResponseBytes(response){
  return Buffer.from(JSON.stringify([
    'MNEBYVPN_NODE_ENROLL_V1',response.nodeId,response.endpointHost,
    response.publicSpki,response.challengeId,response.nonce,
  ]),'utf8');
}
function readSpki(buffer){
  if(buffer.length!==44)throw new NodekitEnrollmentError('Not an Ed25519 public key');
  const key=createPublicKey({key:buffer,format:'der',type:'spki'});
  if(key.asymmetricKeyType!=='ed25519')
    throw new NodekitEnrollmentError('Expected Ed25519 public key');
  return key;
}
function host(value){
  return typeof value==='string'&&
    /^[a-z0-9][a-z0-9.-]{2,251}[a-z0-9]$/.test(value)&&
    value.includes('.')&&!value.includes('..')&&
    value.split('.').every(s=>s.length>0&&s.length<=63&&!s.startsWith('-')&&!s.endsWith('-'));
}
export function createEnrollmentResponse(
  nodeDir,challenge,controllerPublicDer,{uid=process.getuid(),now=Date.now()}={}
){
  protectedDir(nodeDir,uid);
  if(!challenge||typeof challenge!=='object'||Array.isArray(challenge)||
     Object.keys(challenge).sort().join(',')!==
       'challengeId,controllerSignature,endpointHost,expiresAt,nodeId,nonce,publicSpki'||
     !NODE.test(challenge.nodeId)||challenge.nodeId.endsWith('-')||
     !host(challenge.endpointHost)||!UUID.test(challenge.challengeId)||
     !NONCE.test(challenge.nonce)||!SIG.test(challenge.controllerSignature)||
     typeof challenge.publicSpki!=='string'||challenge.publicSpki.length!==59)
    throw new NodekitEnrollmentError('Malformed signed enrollment challenge');
  const expiry=new Date(challenge.expiresAt);
  if(!Number.isFinite(expiry.getTime())||
     expiry.toISOString()!==challenge.expiresAt||
     expiry.getTime()<=now||expiry.getTime()>now+300_000)
    throw new NodekitEnrollmentError('Expired or excessive enrollment challenge');
  const manifest=JSON.parse(ownedFile(join(nodeDir,'manifest.json'),uid).toString('utf8'));
  if(manifest.node_id!==challenge.nodeId||
     manifest.advertise_host!==challenge.endpointHost||
     manifest.state!=='testing'||manifest.registration_enabled!==false)
    throw new NodekitEnrollmentError('Enrollment challenge does not match staged node');
  const identityDir=join(nodeDir,'identity');
  protectedDir(identityDir,uid);
  const publicBytes=ownedFile(join(identityDir,'node-public.spki'),uid,{minSize:44,maxSize:44});
  readSpki(publicBytes);
  if(publicBytes.toString('base64url')!==challenge.publicSpki)
    throw new NodekitEnrollmentError('Challenge has unrecognized node identity');
  const controllerKey=readSpki(controllerPublicDer);
  const controllerSig=Buffer.from(challenge.controllerSignature,'base64url');
  if(controllerSig.length!==64||
     !verify(null,controllerChallengeBytes(challenge),controllerKey,controllerSig))
    throw new NodekitEnrollmentError('Invalid controller enrollment challenge signature');
  const nodePrivate=ownedFile(join(identityDir,'node-private.pk8'),uid,{minSize:40,maxSize:256});
  const key=createPrivateKey({key:nodePrivate,format:'der',type:'pkcs8'});
  if(key.asymmetricKeyType!=='ed25519')
    throw new NodekitEnrollmentError('Invalid node identity key');
  const response={
    challengeId:challenge.challengeId,nodeId:challenge.nodeId,
    endpointHost:challenge.endpointHost,publicSpki:challenge.publicSpki,
    nonce:challenge.nonce,
  };
  return {...response,signature:sign(null,enrollmentResponseBytes(response),key).toString('base64url')};
}
export function signEnrollmentFile({
  stageRoot,nodeId,challengeFile,controllerKeyFile,responseFile,
  uid=process.getuid(),now=Date.now(),
}){
  if(typeof nodeId!=='string'||!NODE.test(nodeId)||nodeId.endsWith('-'))
    throw new NodekitEnrollmentError('Invalid node ID');
  protectedDir(stageRoot,uid);
  const nodeDir=join(stageRoot,nodeId);
  const challenge=JSON.parse(ownedFile(challengeFile,uid,{maxSize:2048}).toString('utf8'));
  const controllerPublicDer=ownedFile(controllerKeyFile,uid,{minSize:44,maxSize:44});
  const response=createEnrollmentResponse(nodeDir,challenge,controllerPublicDer,{uid,now});
  // Refuse overwrites; the response contains a one-use enrollment bearer.
  writeFileSync(responseFile,JSON.stringify(response)+'\n',{flag:'wx',mode:0o600});
  return {signed:true,nodeId,response_sha256:createHash('sha256')
    .update(enrollmentResponseBytes(response)).digest('hex')};
}
function main(argv){
  if(process.getuid()!==0)
    throw new NodekitEnrollmentError('Enrollment identity must run as root');
  if(argv.length!==5)
    throw new NodekitEnrollmentError(
      'Usage: node sign-enrollment.mjs NODE_ID STAGE_ROOT CHALLENGE_FILE CONTROLLER_PUBLIC_DER RESPONSE_FILE');
  const [nodeId,stageRoot,challengeFile,controllerKeyFile,responseFile]=argv;
  const result=signEnrollmentFile({nodeId,stageRoot,challengeFile,controllerKeyFile,responseFile});
  process.stdout.write(JSON.stringify(result)+'\n');
}
if(process.argv[1]&&fileURLToPath(import.meta.url)===resolve(process.argv[1])){
  try{main(process.argv.slice(2));}
  catch(err){
    process.stderr.write('node_enrollment_error='+err.constructor.name+'\n');
    process.exitCode=2;
  }
}
