/**
 * Exact signed command ABI for NEW Nodekit Xray supervisor (UNIX socket only).
 *
 * The signing private key MUST remain exclusively in a trusted controller,
 * after independently checking live ACTIVE billing state, revision and expiry.
 * This pure helper does NOT query the DB and is NOT authorization by itself.
 */
import {randomBytes,sign,createPrivateKey} from 'node:crypto';

const NODE=/^[a-z0-9][a-z0-9-]{2,39}$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const UTC=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;

export class NodekitAccessError extends Error {}
export function nodeAccessCommandPayload(req){
  return Buffer.from(JSON.stringify([
    'MNEBYVPN_NODEKIT_ACCESS_V1',req.nodeId,req.op,req.id,
    req.revision,req.enabled,req.expiresAt,req.issuedAt,req.nonce,
  ]),'utf8');
}
export function signedNodeAccessCommand({
  nodeId,op,id,revision=null,enabled=null,expiresAt=null,
  issuedAt=new Date().toISOString(),nonce=randomBytes(32).toString('hex'),
},controllerKey,now=Date.now()){
  if(!NODE.test(nodeId??'')||nodeId.endsWith('-')||
     !UUID.test(id??'')||!['apply','inspect'].includes(op)||
     typeof issuedAt!=='string'||!UTC.test(issuedAt)||
     !Number.isFinite(Date.parse(issuedAt))||
     new Date(issuedAt).toISOString()!==issuedAt||
     Math.abs(Date.parse(issuedAt)-now)>45_000||
     !/^[a-f0-9]{64}$/.test(nonce??''))
    throw new NodekitAccessError('Invalid node access command');
  if(op==='inspect'){
    if(revision!==null||enabled!==null||expiresAt!==null)
      throw new NodekitAccessError('Inspect cannot change access');
  }else{
    if(!Number.isSafeInteger(revision)||revision<1||revision>1_000_000_000||
       typeof enabled!=='boolean')
      throw new NodekitAccessError('Invalid access revision or state');
    if(enabled){
      if(typeof expiresAt!=='string'||!UTC.test(expiresAt)||
         !Number.isFinite(Date.parse(expiresAt))||
         new Date(expiresAt).toISOString()!==expiresAt||
         Date.parse(expiresAt)<=now||Date.parse(expiresAt)>now+100*86_400_000)
        throw new NodekitAccessError('Invalid controller-issued expiry');
    }else if(expiresAt!==null)
      throw new NodekitAccessError('Revocation must have null expiry');
  }
  if(controllerKey?.asymmetricKeyType!=='ed25519'||
     controllerKey.type!=='private')
    throw new NodekitAccessError('Trusted Ed25519 signing key required');
  const req={nodeId,op,id,revision,enabled,expiresAt,issuedAt,nonce};
  return {...req,signature:sign(null,nodeAccessCommandPayload(req),
    controllerKey).toString('base64url')};
}

/** Read root-only PKCS8 DER *inside* controller process, never from web. */
export function readControllerAccessPrivateKey(pkcs8){
  if(!Buffer.isBuffer(pkcs8)||pkcs8.length<40||pkcs8.length>256)
    throw new NodekitAccessError('Invalid protected Ed25519 PKCS8');
  const key=createPrivateKey({key:pkcs8,format:'der',type:'pkcs8'});
  if(key.asymmetricKeyType!=='ed25519')
    throw new NodekitAccessError('Incorrect controller signing algorithm');
  return key;
}
