/** Native RU188 FI DNS private runtime; existing Node and pg, no public API.
 * Each mode uses its own login and a single inherited function-only role.
 * Publisher writes a root-only signed outbox; transport is separately gated.
 */
import {createHash,createPrivateKey,createPublicKey,randomBytes} from 'node:crypto';
import {openSync,closeSync,readSync,fstatSync,lstatSync,constants} from 'node:fs';
import {open,rename,unlink} from 'node:fs/promises';
import {dirname} from 'node:path';
import {createRequire} from 'node:module';
import {setTimeout as pause} from 'node:timers/promises';
import {startFiMeterLoopbackServer} from './fi-dns-meter-loopback.ts';
import {handleFiMeterRequest} from './fi-dns-meter-rpc.ts';
import {publishFiDnsSnapshotOnce} from './fi-dns-snapshot-publisher.ts';

const ROOT='/root/mnebyvpn-controller';
const RUNTIME='/opt/mnebyvpn-controller/current';
const STATE='/var/lib/mnebyvpn-fi-dns-controller';
const NODE_PIN='c3689b687e8888d15e3ece8e45cf7d01672b9dadb77b1963a7871ffd8e967ed9';
const CONTROLLER_PIN='e4c862bd0171e5be4ae64770a555029e090d3a8fcfa5ef2a82ffb0b798552844';
const PORT=18856;
const require=createRequire(import.meta.url);
function protectedBytes(path,max){
 for(let parent=dirname(path);;parent=dirname(parent)){
  const s=lstatSync(parent);
  if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==0||(s.mode&0o022))throw Error('Unsafe controller directory');
  if(parent==='/')break;
 }
 const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const s=fstatSync(fd);
  if(!s.isFile()||s.uid!==0||(s.mode&0o077)||s.size<1||s.size>max)throw Error('Unsafe controller file');
  const raw=Buffer.alloc(s.size+1);
  if(readSync(fd,raw,0,raw.length,0)!==s.size)throw Error('Controller file changed');
  return raw.subarray(0,s.size);
 }finally{closeSync(fd);}
}
function sha(raw){return createHash('sha256').update(raw).digest('hex');}
function loadTrust(){
 const raw=protectedBytes(ROOT+'/controller-signing-key.pem',8192);
 let key;
 try{key=createPrivateKey(raw);}finally{raw.fill(0);}
 if(key.asymmetricKeyType!=='ed25519'||sha(createPublicKey(key).export({format:'der',type:'spki'}))!==CONTROLLER_PIN)throw Error('Controller signing pin mismatch');
 const node=protectedBytes(ROOT+'/fi-node-public.spki',44);
 if(node.length!==44||sha(node)!==NODE_PIN)throw Error('Node signing pin mismatch');
 return {key,node:{spki:node.toString('base64url'),sha256:NODE_PIN}};
}
async function atomicSnapshot(snapshot){
 const body=Buffer.from(JSON.stringify(snapshot));
 if(body.length>700000)throw Error('Oversized snapshot');
 const tmp=STATE+'/.snapshot-'+randomBytes(12).toString('hex');
 let file;
 try{
  file=await open(tmp,'wx',0o600);
  await file.writeFile(body);await file.sync();await file.close();file=null;
  await rename(tmp,STATE+'/snapshot.json');
  const dir=await open(STATE,constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);
  try{await dir.sync();}finally{await dir.close();}
 }finally{if(file)await file.close();await unlink(tmp).catch(()=>{});}
}
async function main(){
 const mode=process.argv[2];
 if(process.getuid?.()!==0||!['meter','publisher'].includes(mode)||process.argv.length!==3)throw Error('Invalid controller invocation');
 const role='mnebyvpn_fi_dns_'+mode+'_runtime';
 const url=process.env.DATABASE_URL??'';
 if(!new RegExp('^postgresql://'+role+':[a-f0-9]{64}@127\\.0\\.0\\.1:55433/mnebyvpn_stage$').test(url))throw Error('Unapproved scoped database URL');
 const {key,node}=loadTrust();
 const {Pool}=require(RUNTIME+'/node_modules/pg');
 const pool=new Pool({connectionString:url,max:mode==='meter'?8:1,connectionTimeoutMillis:1200,statement_timeout:1500,query_timeout:1900,idleTimeoutMillis:10000});
 pool.on('error',()=>process.stderr.write('FI_DNS_DB_IDLE_ERROR\n'));
 const abort=new AbortController();
 const stop=()=>abort.abort();
 process.once('SIGTERM',stop);process.once('SIGINT',stop);
 let server;
 try{
  const identity=await pool.query('SELECT current_user AS role,current_database() AS db');
  if(identity.rows.length!==1||identity.rows[0].role!==role||identity.rows[0].db!=='mnebyvpn_stage')throw Error('Wrong database login');
  if(mode==='meter'){
   server=await startFiMeterLoopbackServer(PORT,input=>handleFiMeterRequest(input,node,key,pool));
   process.stdout.write('FI_DNS_METER_LOOPBACK_READY\n');
   if(!abort.signal.aborted)await new Promise(resolve=>abort.signal.addEventListener('abort',resolve,{once:true}));
  }else{
   while(!abort.signal.aborted){
    await publishFiDnsSnapshotOnce(pool,key,atomicSnapshot);
    process.stdout.write('FI_DNS_SIGNED_OUTBOX_READY\n');
    try{await pause(25000,undefined,{signal:abort.signal});}catch{if(!abort.signal.aborted)throw Error('Publisher sleep failed');}
   }
  }
 }finally{
  if(server)await new Promise(resolve=>server.close(resolve));
  await pool.end();
 }
}
main().catch(()=>{process.stderr.write('FI_DNS_CONTROLLER_WORKER_STOPPED\n');process.exitCode=1;});
