/**
 * Nodekit multi-country enrollment evidence and grant signer.
 * OFFLINE SECURITY LIBRARY, NOT A RUNNING CONTROLLER OR NODE PROVISIONER.
 *
 * Node private identity signs a controller-issued nonce and observed access.
 * Controller verifies actual canonical billing state and node E2E evidence
 * before countersigning the exact payload consumed by the Mnebyvpn website.
 *
 * Never give private signing material or arbitrary shell access to an LLM.
 */
import {createPrivateKey,createPublicKey,sign,verify} from 'node:crypto';
import {isIP} from 'node:net';

const HEX=/^[a-f0-9]{64}$/;
const NODE=/^[a-z0-9][a-z0-9-]{2,39}$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SPKI=/^[A-Za-z0-9_-]{59}$/;
const FQDN=/^[a-z0-9](?:[a-z0-9.-]{1,251})[a-z0-9]$/;
const VLESS_KEYS=new Set([
  'encryption','security','type','flow','sni','fp','pbk','sid','spx',
]);
const MAX_GRANT_AGE=15*60_000;
const MAX_NODE_HEALTH_AGE=60*60_000;

export class NodekitTrustError extends Error {}

export function readEd25519PublicKey(base64url) {
  if(typeof base64url!=='string'||!SPKI.test(base64url))
    throw new NodekitTrustError('Unrecognized enrolled node public key');
  const raw=Buffer.from(base64url,'base64url');
  if(raw.length!==44)throw new NodekitTrustError('Incorrect enrolled node public key');
  const key=createPublicKey({key:raw,format:'der',type:'spki'});
  if(key.asymmetricKeyType!=='ed25519')
    throw new NodekitTrustError('Node enrollment is not Ed25519');
  return key;
}
export function readEd25519PrivateKey(pkcs8Der) {
  if(!Buffer.isBuffer(pkcs8Der)||pkcs8Der.length>256||pkcs8Der.length<40)
    throw new NodekitTrustError('Private key requires an explicit protected PKCS8 file');
  const key=createPrivateKey({key:pkcs8Der,format:'der',type:'pkcs8'});
  if(key.asymmetricKeyType!=='ed25519')
    throw new NodekitTrustError('Wrong signing algorithm');
  return key;
}

function requireDate(input) {
  if(typeof input!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(input))
    throw new NodekitTrustError('Non-canonical timestamp');
  const date=new Date(input);
  if(!Number.isFinite(date.getTime())||date.toISOString()!==input)
    throw new NodekitTrustError('Invalid timestamp');
  return date.getTime();
}
const hostname=value=>typeof value==='string'&&FQDN.test(value)&&
  value.includes('.')&&!value.includes('..')&&
  !isIP(value)&&value!=='cdn.servgo.ru'&&
  !value.endsWith('.local')&&!value.endsWith('.internal')&&
  !value.includes('localhost');

function validateVlessUri(profile,expectedHost,expectedPort) {
  if(typeof profile!=='string'||profile.length>2048||/[\x00-\x20]/.test(profile))
    throw new NodekitTrustError('Malformed VPN profile');
  let url;
  try{url=new URL(profile);}catch{throw new NodekitTrustError('Invalid profile URI');}
  if(url.protocol!=='vless:'||url.hostname!==expectedHost||
     url.port!==String(expectedPort)||!UUID.test(url.username)||
     !!url.password||!!url.hash||(url.pathname!==''&&url.pathname!=='/'))
    throw new NodekitTrustError('Unexpected VLESS destination or credentials');
  const q=url.searchParams;
  if(q.size!==VLESS_KEYS.size||[...q.keys()].some(k=>!VLESS_KEYS.has(k))||
     q.get('encryption')!=='none'||q.get('security')!=='reality'||
     q.get('type')!=='tcp'||q.get('flow')!=='xtls-rprx-vision'||
     !hostname(q.get('sni'))||
     (q.get('fp')!=='chrome'&&q.get('fp')!=='firefox')||
     !/^[A-Za-z0-9_-]{43}$/.test(q.get('pbk')??'')||
     !/^[a-f0-9]{16}$/.test(q.get('sid')??'')||
     q.get('spx')!=='/')
    throw new NodekitTrustError('Unsafe VLESS parameters');
}

function nodeAttestationMessage(observation) {
  return Buffer.from(JSON.stringify([
    'MNEBYVPN_NODE_OBSERVATION_V1',
    observation.nodeId,observation.entitlementId,observation.revision,
    observation.expiresAt,observation.observedAt,observation.profileUri,
    observation.nonce,observation.nodeEnforcedExpiry,
  ]),'utf8');
}
export function signNodeObservation(observation,nodePrivateKey) {
  // Only call after on-node agent has actually checked running Xray state and
  // independently enforced the exact expiry. The function itself cannot prove
  // that the caller inspected the data-plane.
  if(observation?.nodeEnforcedExpiry!==true||!HEX.test(observation?.nonce??''))
    throw new NodekitTrustError('Missing expiry enforcement or controller nonce');
  const msg=nodeAttestationMessage(observation);
  return {...observation,signature:sign(null,msg,nodePrivateKey).toString('base64url')};
}

function verifyNodeObservation(observation, enrolledPublicKey) {
  if(!observation||typeof observation!=='object'||Array.isArray(observation)||
     !/^[A-Za-z0-9_-]{86}$/.test(observation.signature??'')||
     observation.nodeEnforcedExpiry!==true)return false;
  try{
    return verify(null,nodeAttestationMessage(observation),enrolledPublicKey,
                  Buffer.from(observation.signature,'base64url'));
  }catch{return false;}
}

/** This exact tuple is verified by multi-node-subscriptions.ts in Mnebyvpn. */
export function websiteReceiptMessage(row) {
  return Buffer.from(JSON.stringify([
    'MNEBYVPN_NODE_ACCESS_V1',
    row.node_id,row.country_code,row.country_name_ru,row.endpoint_host,row.endpoint_port,
    row.exit_country_proof_sha256,row.vpn_e2e_proof_sha256,
    row.entitlement_id,row.revision,row.expires_at,
    row.observed_at,row.profile_uri,
  ]),'utf8');
}

/**
 * Issuance must run inside the trusted control-plane after DB authorization,
 * verified external E2E, country evidence and an atomic one-time nonce lease.
 * No network, SQL or service mutation occurs in this function.
 */
export function issueWebsiteGrant({node,entitlement,observation,expectedNonce,
                                    controllerPrivateKey,now=Date.now()}) {
  if(typeof now!=='number'||!Number.isFinite(now)||
     !node||!entitlement||!observation||
     !NODE.test(node.nodeId)||node.nodeId.endsWith('-')||
     node.state!=='enabled'||node.role==='edge'||!node.services?.includes('vpn')||
     !/^[A-Z]{2}$/.test(node.countryCode)||node.countryCode==='ZZ'||
     !/^[А-Яа-яЁёA-Za-z ()-]{2,70}$/.test(node.countryNameRu)||
     !hostname(node.endpointHost)||!Number.isInteger(node.endpointPort)||
     node.endpointPort<1||node.endpointPort>65535||
     !HEX.test(node.exitCountryProofSha256??'')||
     !HEX.test(node.vpnE2eProofSha256??'')||
     !UUID.test(entitlement.id??'')||
     !Number.isSafeInteger(entitlement.revision)||entitlement.revision<1||
     entitlement.state!=='ACTIVE'||entitlement.product!=='vpn'||
     !HEX.test(expectedNonce??''))
    throw new NodekitTrustError('Node or entitlement is not approved');
  const eExpires=requireDate(entitlement.expiresAt);
  const verified=requireDate(node.verifiedAt);
  const oExpires=requireDate(observation.expiresAt);
  const observed=requireDate(observation.observedAt);
  if(eExpires<=now||verified>now+120_000||now-verified>MAX_NODE_HEALTH_AGE||
     observed>now+120_000||now-observed>MAX_GRANT_AGE||
     Math.abs(eExpires-oExpires)>1000)
    throw new NodekitTrustError('Stale or inconsistent node access evidence');
  if(observation.nodeId!==node.nodeId||
     observation.entitlementId!==entitlement.id||
     observation.revision!==entitlement.revision||
     observation.nonce!==expectedNonce||observation.nodeEnforcedExpiry!==true)
    throw new NodekitTrustError('Node attestation does not match the approved grant');
  validateVlessUri(observation.profileUri,node.endpointHost,node.endpointPort);
  const nodeKey=readEd25519PublicKey(node.nodePublicSpki);
  if(!verifyNodeObservation(observation,nodeKey))
    throw new NodekitTrustError('Invalid node-side access signature');
  if(controllerPrivateKey.asymmetricKeyType!=='ed25519')
    throw new NodekitTrustError('Controller signing algorithm not allowed');
  const receipt={
    node_id:node.nodeId,country_code:node.countryCode,
    country_name_ru:node.countryNameRu,endpoint_host:node.endpointHost,
    endpoint_port:node.endpointPort,
    exit_country_proof_sha256:node.exitCountryProofSha256,
    vpn_e2e_proof_sha256:node.vpnE2eProofSha256,
    entitlement_id:entitlement.id,revision:entitlement.revision,
    expires_at:entitlement.expiresAt,observed_at:observation.observedAt,
    profile_uri:observation.profileUri,
  };
  return {
    ...receipt,
    signature:sign(null,websiteReceiptMessage(receipt),controllerPrivateKey)
      .toString('base64url'),
  };
}
