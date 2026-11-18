/** Signed AmneziaWG 3.1 peer lease ABI shared with Nodekit.
 * A private controller must check live VPN entitlement and monotonic revision
 * in PostgreSQL BEFORE calling this pure signer. Signing alone is not billing.
 * The controller private key must NEVER reach GitHub Actions or a node.
 */
import {randomBytes,sign} from 'node:crypto';

const NODE=/^[a-z0-9][a-z0-9-]{2,39}$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const KEY=/^[A-Za-z0-9+/]{43}=$/;
const TS=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const MAX_AGE=100*86400_000;
export class AwgLeaseError extends Error {}

export function awgLeasePayload(req){
  return Buffer.from(JSON.stringify([
    'MNEBYVPN_AWG_LEASE_V1',
    req.nodeId,req.op,req.entitlementId,req.revision,
    req.peerPublicKey,req.clientIpv4,req.expiresAt,
    req.issuedAt,req.nonce,
  ]),'utf8');
}
function validKey(value){
  if(typeof value!=='string'||!KEY.test(value))return false;
  const bytes=Buffer.from(value,'base64');
  return bytes.length===32&&bytes.toString('base64')===value;
}
function validIP(ip){
  if(typeof ip!=='string')return false;
  const m=/^10\.73\.91\.(\d{1,3})$/.exec(ip);
  return !!m&&Number(m[1])>=2&&Number(m[1])<=254&&
    String(Number(m[1]))===m[1];
}
function timestamp(value){
  if(typeof value!=='string'||!TS.test(value))return NaN;
  const t=Date.parse(value);
  return Number.isFinite(t)&&new Date(t).toISOString()===value?t:NaN;
}

export function signedAwgLease({
  nodeId,op,entitlementId,revision,peerPublicKey,clientIpv4,
  expiresAt=null,issuedAt=new Date().toISOString(),
  nonce=randomBytes(32).toString('hex'),
},privateKey,now=Date.now()){
  if(typeof nodeId!=='string'||!NODE.test(nodeId)||nodeId.endsWith('-')||
     !['grant','revoke'].includes(op)||typeof entitlementId!=='string'||
     !UUID.test(entitlementId)||!Number.isSafeInteger(revision)||
     revision<1||revision>1_000_000_000||!validKey(peerPublicKey)||
     !validIP(clientIpv4)||typeof nonce!=='string'||!/^[a-f0-9]{64}$/.test(nonce)||
     !Number.isFinite(now)||!Number.isFinite(timestamp(issuedAt))||
     Math.abs(timestamp(issuedAt)-now)>45_000)
    throw new AwgLeaseError('Invalid AWG lease command');
  if(op==='grant'){
    const end=timestamp(expiresAt);
    if(!Number.isFinite(end)||end<=now||end>now+MAX_AGE)
      throw new AwgLeaseError('Grant needs a finite future expiration');
  }else if(expiresAt!==null){
    throw new AwgLeaseError('Revocation never extends a lease');
  }
  if(privateKey?.type!=='private'||privateKey.asymmetricKeyType!=='ed25519')
    throw new AwgLeaseError('Trusted private Ed25519 controller key required');
  const record={nodeId,op,entitlementId,revision,peerPublicKey,clientIpv4,
    expiresAt,issuedAt,nonce};
  return {...record,signature:sign(null,awgLeasePayload(record),privateKey)
    .toString('base64url')};
}
