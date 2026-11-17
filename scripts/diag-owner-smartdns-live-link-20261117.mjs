/**
 * Run only inside the owner-only Telegram bot container. Uses its authenticated
 * DB connection and encrypted owner label in memory. Never prints secrets.
 * The test performs bounded DNS queries through the actual public DoT path.
 */
import {createRequire} from 'node:module';
import {lookup} from 'node:dns/promises';
import {connect as connectTls} from 'node:tls';
import {randomBytes} from 'node:crypto';
import {ownerDnsKey,decryptOwnerDnsLabel} from
  '/srv/mnebyvpn/apps/service/src/owner-dns-links.ts';
const require=createRequire('/srv/mnebyvpn/apps/service/src/telegram-cabinet-server.ts');
const {Pool}=require('pg');
const db=new Pool({connectionString:process.env.DATABASE_URL,max:1,
  connectionTimeoutMillis:3000,query_timeout:3500});
function fail(name){throw Error(name);}
function qname(host){
  const labels=host.split('.');
  return Buffer.concat([...labels.map(x=>Buffer.concat([Buffer.from([x.length]),Buffer.from(x,'ascii')])),Buffer.from([0])]);
}
function query(name,type){
  const header=Buffer.alloc(12);header.writeUInt16BE(randomBytes(2).readUInt16BE(0),0);
  header.writeUInt16BE(0x0100,2);header.writeUInt16BE(1,4);
  const rest=Buffer.alloc(4);rest.writeUInt16BE(type,0);rest.writeUInt16BE(1,2);
  return Buffer.concat([header,qname(name),rest]);
}
function stripName(buf,start){
  let pos=start;
  for(let i=0;i<127;i++){
    if(pos>=buf.length)fail('TRUNCATED_DNS_NAME');
    const len=buf[pos++];
    if((len&0xc0)===0xc0)return pos+1;
    if(len===0)return pos;
    if(len>63||pos+len>buf.length)fail('INVALID_DNS_NAME');
    pos+=len;
  }
  fail('DNS_NAME_LOOP');
}
function parseAnswer(data,q){
  if(data.length<12||data.readUInt16BE(0)!==q.readUInt16BE(0))fail('DNS_ID_MISMATCH');
  const code=data.readUInt16BE(2)&15, count=data.readUInt16BE(6);
  let pos=stripName(data,12)+4;
  const addresses=[];
  for(let i=0;i<count;i++){
    pos=stripName(data,pos);
    if(pos+10>data.length)fail('DNS_RR_SHORT');
    const type=data.readUInt16BE(pos),size=data.readUInt16BE(pos+8);
    pos+=10;
    if(pos+size>data.length)fail('DNS_RDATA_SHORT');
    if(type===1&&size===4)addresses.push([...data.subarray(pos,pos+4)].join('.'));
    pos+=size;
  }
  return {code,addresses};
}
async function dnsOverTls(host,name,type){
  const q=query(name,type);
  const sock=connectTls({host:'89.125.90.101',port:853,servername:host,
    rejectUnauthorized:true,minVersion:'TLSv1.2'});
  sock.setTimeout(12000);
  try{
    await new Promise((resolve,reject)=>{
      sock.once('secureConnect',resolve);
      sock.once('error',()=>reject(Error('TLS_CONNECTION_ERROR')));
      sock.once('timeout',()=>reject(Error('TLS_CONNECTION_TIMEOUT')));
    });
    if(!sock.authorized)fail('TLS_UNVERIFIED');
    console.log('ACTUAL_LABEL_DOT_TLS_VERIFIED=true');
    const answer=await new Promise((resolve,reject)=>{
      let chunks=Buffer.alloc(0),done=false;
      const finish=(err,value)=>{
        if(done)return;done=true;
        if(err)reject(err);else resolve(value);
      };
      sock.on('error',()=>finish(Error('DNS_TLS_STREAM_ERROR')));
      sock.on('timeout',()=>finish(Error('DNS_TLS_STREAM_TIMEOUT')));
      sock.on('close',()=>finish(Error('DNS_TLS_STREAM_CLOSED')));
      sock.on('data',part=>{
        chunks=Buffer.concat([chunks,part]);
        if(chunks.length>=2){
          const n=chunks.readUInt16BE(0);
          if(n<12||n>16384){finish(Error('DNS_SIZE_INVALID'));return;}
          if(chunks.length>=n+2)finish(null,chunks.subarray(2,n+2));
        }
      });
      const packet=Buffer.alloc(2+q.length);
      packet.writeUInt16BE(q.length,0);q.copy(packet,2);
      sock.write(packet);
    });
    return parseAnswer(answer,q);
  }finally{sock.destroy();}
}
try{
  const key=ownerDnsKey(process.env.MNEBYDNS_OWNER_LINK_KEY);
  if(!key)fail('OWNER_LINK_KEY_UNAVAILABLE');
  const r=await db.query(
    "SELECT id,owner_telegram_id,token_ciphertext FROM owner_dns_links "+
    "WHERE video_route='smart_dns' AND revoked_at IS NULL "+
    "AND (permanent OR expires_at>clock_timestamp()) "+
    "ORDER BY created_at DESC LIMIT 2");
  console.log('ACTIVE_OWNER_LINKS_TO_PROBE='+r.rows.length);
  if(r.rows.length!==1)fail('AMBIGUOUS_NEW_OWNER_LINK');
  const row=r.rows[0],owner=Number(row.owner_telegram_id);
  if(!Number.isSafeInteger(owner))fail('INVALID_OWNER_ID');
  const label=decryptOwnerDnsLabel(row.token_ciphertext,row.id,owner,key);
  const hostname=label+'.dns.mnebyvpn.site';
  const answer=await lookup(hostname,{family:4});
  console.log('ACTUAL_LABEL_PUBLIC_BOOTSTRAP_OK='+String(answer.address==='89.125.90.101'));
  if(answer.address!=='89.125.90.101')fail('ACTUAL_LABEL_PUBLIC_A_MISMATCH');
  const tests=[
    ['example.org',1,'ORDINARY_A'],
    ['connectivitycheck.gstatic.com',1,'ANDROID_CONNECTIVITY_A'],
    ['youtubei.googleapis.com',1,'YOUTUBE_API_A'],
    ['i.ytimg.com',1,'YOUTUBE_THUMB_A'],
    ['s.ytimg.com',1,'YOUTUBE_ASSETS_A'],
    ['yt3.ggpht.com',1,'YOUTUBE_AVATAR_A'],
    ['m.youtube.com',1,'YOUTUBE_MOBILE_A'],
    ['www.youtube.com',1,'YOUTUBE_WEB_A'],
    ['rr1---sn-gxuo03g-ig3s.googlevideo.com',1,'GOOGLEVIDEO_A'],
    ['rr1---sn-gxuo03g-ig3s.googlevideo.com',28,'GOOGLEVIDEO_AAAA'],
  ];
  for(const [domain,type,kind] of tests){
    try{
      const result=await dnsOverTls(hostname,domain,type);
      const mapped=kind==='GOOGLEVIDEO_A';
      console.log('ACTUAL_LABEL_DNS='+kind+' RCODE='+result.code+
        ' A_COUNT='+result.addresses.length+
        ' DE89_INCLUDED='+String(result.addresses.includes('89.125.90.101')));
      if(result.code!==0 || (mapped&&!result.addresses.includes('89.125.90.101')) ||
        (!mapped&&kind.endsWith('_A')&&!result.addresses.length))
        fail('ACTUAL_LABEL_DNS_'+kind+'_FAILED');
    }catch(err){
      console.log('ACTUAL_LABEL_DNS='+kind+' ERROR='+err?.message?.slice(0,90));
      throw err;
    }
  }
  console.log('ACTUAL_PERSONAL_OWNER_DOT_E2E=PASS');
}catch(err){
  console.log('ACTUAL_PERSONAL_OWNER_DOT_E2E=FAIL_'+String(err?.message??'UNKNOWN').slice(0,90));
  process.exitCode=2;
}finally{await db.end();}
