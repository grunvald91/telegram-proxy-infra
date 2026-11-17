/** Controller-side pinned-SSH delivery of a signed Nodekit command.
 * The trusted controller MUST authorize each ACTIVE entitlement separately.
 * SSH identity, signed commands and responses must never be logged.
 */
import {spawn} from 'node:child_process';
import {lstatSync} from 'node:fs';
import {BlockList,isIP} from 'node:net';
import {resolve} from 'node:path';

const NODE=/^[a-z0-9][a-z0-9-]{2,39}$/;
const HOST=/^[A-Za-z0-9][A-Za-z0-9.-]{0,251}[A-Za-z0-9]$/;
const NONCE=/^[a-f0-9]{64}$/;
const SIG=/^[A-Za-z0-9_-]{86}$/;
const MAX_REPLY=8192;
const bans=new BlockList();
for(const [network,bits] of [
  ['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],
  ['169.254.0.0',16],['172.16.0.0',12],['192.0.0.0',24],
  ['192.0.2.0',24],['192.168.0.0',16],['198.18.0.0',15],
  ['198.51.100.0',24],['203.0.113.0',24],['224.0.0.0',4],
  ['240.0.0.0',4],
]) bans.addSubnet(network,bits,'ipv4');
for(const address of ['89.125.90.101','188.120.254.223'])
  bans.addAddress(address,'ipv4');

export class NodekitTransportError extends Error {}

function privateFile(value){
  if(typeof value!=='string'||!value.startsWith('/')||
     value.includes('\n')||value.includes('\r'))
    throw new NodekitTransportError('Expected absolute protected key path');
  const file=resolve(value);
  const st=lstatSync(file);
  if(!st.isFile()||st.isSymbolicLink()||st.uid!==process.getuid()||
     (st.mode&0o077)!==0)
    throw new NodekitTransportError('SSH trust file owner or permissions unsafe');
  return file;
}
export function checkedSshTarget(host,ip,nodeId){
  if(typeof host!=='string'||host.length>253||!HOST.test(host)||
     host.includes('..')||host.split('.').some(label=>
       label.length<1||label.length>63||
       label.startsWith('-')||label.endsWith('-'))||
     typeof nodeId!=='string'||!NODE.test(nodeId)||nodeId.endsWith('-')||
     isIP(ip)!==4||bans.check(ip,'ipv4'))
    throw new NodekitTransportError('Untrusted new-VPS SSH target');
  return {host,ip,nodeId};
}

/** Uses SSH identity pinning AND node-side Ed25519 verification. */
export async function deliverSignedNodeAccess({
  host,ip,nodeId,identityFile,knownHostsFile,command,
  sshBin='ssh',spawnProcess=spawn,timeoutMs=12_000,
}){
  checkedSshTarget(host,ip,nodeId);
  if(typeof command!=='object'||!command||Array.isArray(command)||
     Object.keys(command).sort().join(',')!==
      'enabled,expiresAt,id,issuedAt,nodeId,nonce,op,revision,signature'||
     command.nodeId!==nodeId||!NONCE.test(command.nonce??'')||
     !SIG.test(command.signature??'')||
     !['apply','inspect'].includes(command.op))
    throw new NodekitTransportError('Invalid signed controller envelope');
  if(!Number.isInteger(timeoutMs)||timeoutMs<1000||timeoutMs>30000)
    throw new NodekitTransportError('Unsafe SSH timeout');
  const key=privateFile(identityFile),known=privateFile(knownHostsFile);
  const commandLine=[
    // Ignore ~/.ssh/config and make any unrestricted root key fail closed.
    // Success is only possible if authorized_keys has a forced command
    // pointing at forward_command.py for this exact node ID.
    '-F','/dev/null','-T','-i',key,
    '-o','BatchMode=yes','-o','IdentitiesOnly=yes',
    '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+known,
    '-o','GlobalKnownHostsFile=/dev/null','-o','UpdateHostKeys=no',
    '-o','HostName='+ip,'-o','HostKeyAlias='+host,
    '-o','ForwardAgent=no','-o','ClearAllForwardings=yes',
    '-o','PermitLocalCommand=no','-o','ProxyCommand=none',
    '-o','ConnectTimeout=8','-o','LogLevel=ERROR',
    'root@'+host,'false',
  ];
  const payload=Buffer.from(JSON.stringify(command)+'\n');
  if(payload.length>4096)
    throw new NodekitTransportError('Signed envelope exceeds Nodekit cap');
  return await new Promise((resolvePromise,reject)=>{
    let done=false,output='',errorOutputLength=0;
    const child=spawnProcess(sshBin,commandLine,{stdio:['pipe','pipe','pipe']});
    const timeout=setTimeout(()=>{
      child.kill('SIGKILL');
      finish(new NodekitTransportError('Nodekit SSH timeout'));
    },timeoutMs);
    const finish=(err,value)=>{
      if(done)return;
      done=true;
      clearTimeout(timeout);
      if(err)reject(err);else resolvePromise(value);
    };
    child.stdout.on('data',chunk=>{
      output+=chunk.toString('utf8');
      if(Buffer.byteLength(output)>MAX_REPLY) {
        child.kill('SIGKILL');
        finish(new NodekitTransportError('Oversized supervisor reply'));
      }
    });
    child.stderr.on('data',chunk=>{
      // Never report or log remote stderr. It may contain access material.
      errorOutputLength+=chunk.length;
      if(errorOutputLength>MAX_REPLY)child.kill('SIGKILL');
    });
    child.on('error',()=>finish(new NodekitTransportError('SSH delivery failed')));
    child.on('close',code=>{
      if(code!==0)return finish(new NodekitTransportError('SSH delivery rejected'));
      try{
        if(!output.endsWith('\n')||output.trim().includes('\n'))
          throw new NodekitTransportError('Malformed supervisor reply');
        const parsed=JSON.parse(output);
        if(parsed?.ok!==true||!parsed.result||
           typeof parsed.result!=='object'||Array.isArray(parsed.result))
          throw new NodekitTransportError('Node rejected signed command');
        const answer=parsed.result;
        if(command.op==='apply'){
          // A signed transport ACK is not proof an access change happened.
          // In particular, status=stale MUST NOT be reported as applied.
          if(answer.status!=='applied'||answer.revision!==command.revision)
            throw new NodekitTransportError('Node did not apply requested revision');
        }else if(
          !Number.isSafeInteger(answer.revision)||answer.revision<0||
          typeof answer.enabled!=='boolean'||(
            answer.enabled&&(
              typeof answer.credential!=='string'||
              !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(
                answer.credential)||
              typeof answer.expiresAt!=='string'||
              !Number.isFinite(Date.parse(answer.expiresAt))
            )
          )
        ){
          throw new NodekitTransportError('Malformed node inspection');
        }
        finish(null,answer);
      }catch{
        finish(new NodekitTransportError('Invalid supervisor acknowledgement'));
      }
    });
    child.stdin.on('error',()=>{});
    child.stdin.end(payload);
  });
}
