// One-off synthetic runtime canary. Logs only safe PASS/FAIL codes.
// Creates an ephemeral random user in direct-ozon, then DISABLES it.
// Never prints the username, MTProxy secret, API envelope, or customer details.
import {randomBytes} from 'node:crypto';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const importFromRuntime=(path)=>import(pathToFileURL(resolve(process.cwd(),path)).href);
const username='dns_'+randomBytes(12).toString('hex');
const secret=randomBytes(16).toString('hex');
const expires=new Date(Date.now()+5*60_000);
let createdByCanary=false,admin=null,passed=false,revokePassed=false;
try{
  const {TelemtAdminClient}=await importFromRuntime('packages/web/src/telegram-proxy-provisioning.ts');
  const {createTelemtUnixTransport,OWNER_TELEMT_SSH_SOCKET}=
    await importFromRuntime('packages/web/src/telegram-proxy-unix-transport.ts');
  admin=new TelemtAdminClient('http://127.0.0.1:9096/',
    process.env.DNS_MT_PROXY_TELEMT_AUTH,
    createTelemtUnixTransport(OWNER_TELEMT_SSH_SOCKET));
  const previous=await admin.get(username);
  if(previous!==null)throw Error('canary username collision');
  // Strictly random 5-minute account; never share credentials or links.
  createdByCanary=true;
  passed=await admin.ensure(username,secret,expires,false);
  console.log('owner_telemt_synthetic_create='+ (passed?'verified':'failed'));
}catch(e){
  console.log('owner_telemt_synthetic_create=failed');
  process.exitCode=1;
}finally{
  if(createdByCanary&&admin!==null){
    try{
      const disabled=await admin.disable(username);
      const after=await admin.get(username);
      revokePassed=disabled&&(after===null||after.enabled===false);
    }catch{revokePassed=false;}
    console.log('owner_telemt_synthetic_revoke='+(revokePassed?'verified':'FAILED'));
    if(!revokePassed)process.exitCode=1;
  }else{
    console.log('owner_telemt_synthetic_revoke=not_applicable');
    process.exitCode=1;
  }
}
if(!passed||!revokePassed)process.exitCode=1;
