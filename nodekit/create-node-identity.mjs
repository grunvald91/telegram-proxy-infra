#!/usr/bin/env node
/**
 * Generate a UNIQUE Ed25519 identity after Nodekit stage on a new VPS.
 * Does not create an Xray/WireGuard/TLS credential and does not enroll node.
 *
 * root-only in production; no key material is ever printed, uploaded to
 * GitHub Actions or stored in the public repository.
 */
import {
  existsSync,lstatSync,mkdirSync,readFileSync,writeFileSync,
} from 'node:fs';
import {join} from 'node:path';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const NODE=/^[a-z0-9][a-z0-9-]{2,39}$/;
export class IdentityError extends Error {}

function secureDir(path,requireRoot) {
  const st=lstatSync(path);
  if(!st.isDirectory()||st.isSymbolicLink()||
     st.mode&0o077||requireRoot&&st.uid!==0)
    throw new IdentityError('Untrusted nodekit state directory');
}

export function createNodeIdentity(stageRoot,nodeId,{requireRoot=true}={}) {
  if(typeof nodeId!=='string'||!NODE.test(nodeId)||nodeId.endsWith('-'))
    throw new IdentityError('Invalid node ID');
  if(typeof stageRoot!=='string'||!stageRoot.startsWith('/')||
     stageRoot==='/'||stageRoot.includes('/../'))
    throw new IdentityError('Invalid stage directory');
  if(requireRoot&&process.getuid()!==0)
    throw new IdentityError('Run only as root on the new VPS');
  secureDir(stageRoot,requireRoot);
  const nodeDir=join(stageRoot,nodeId);
  secureDir(nodeDir,requireRoot);
  const manifestPath=join(nodeDir,'manifest.json');
  if(lstatSync(manifestPath).isSymbolicLink())
    throw new IdentityError('Invalid node manifest');
  const manifest=JSON.parse(readFileSync(manifestPath,'utf8'));
  if(manifest.node_id!==nodeId||manifest.state!=='testing'||
     manifest.registration_enabled!==false)
    throw new IdentityError('Node must be staged and not yet enrolled');
  const identityDir=join(nodeDir,'identity');
  if(existsSync(identityDir))throw new IdentityError('Never overwrite an existing node identity');
  mkdirSync(identityDir,{mode:0o700});
  const {publicKey,privateKey}=generateKeyPairSync('ed25519');
  const publicSpki=publicKey.export({format:'der',type:'spki'});
  const privatePk8=privateKey.export({format:'der',type:'pkcs8'});
  const privateFile=join(identityDir,'node-private.pk8');
  const publicFile=join(identityDir,'node-public.spki');
  writeFileSync(privateFile,privatePk8,{flag:'wx',mode:0o600});
  writeFileSync(publicFile,publicSpki,{flag:'wx',mode:0o600});
  return {
    node_id:nodeId,
    identity_public_spki:publicSpki.toString('base64url'),
    identity_public_sha256:createHash('sha256').update(publicSpki).digest('hex'),
    private_key_location:'root-only nodekit identity file',
    enabled:false,
    enrolled:false,
  };
}

function main(args) {
  if(args.length!==2)throw new IdentityError(
    'Usage: node create-node-identity.mjs NODE_ID /var/lib/mnebyvpn-nodekit');
  const result=createNodeIdentity(args[1],args[0]);
  process.stdout.write(JSON.stringify(result)+'\n');
}
if(process.argv[1]&&fileURLToPath(import.meta.url)===process.argv[1]){
  try{main(process.argv.slice(2));}
  catch(error){
    process.stderr.write('node_identity_error='+error.constructor.name+'\n');
    process.exitCode=2;
  }
}
