import {Pool} from 'pg';
import {connect} from 'node:tls';
import {publicEncrypt,constants,randomBytes,randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {ownerDnsLinksAction,ownerDnsKey} from './apps/service/src/owner-dns-links.ts';
import {dnsAdminOwner} from './apps/service/src/dns-admin.ts';
const db=new Pool({connectionString:process.env.DATABASE_URL,connectionTimeoutMillis:3000,statement_timeout:2500});
const owner=dnsAdminOwner(),key=ownerDnsKey(process.env.MNEBYDNS_OWNER_LINK_KEY);
if(!owner||!key)throw Error('Owner configuration unavailable');
const page=await ownerDnsLinksAction(db,owner,owner,key,'dnslinks:permanent','release-20261116');
const hostname=page.text.match(/\b[a-z0-9]{12}\.dns\.mnebyvpn\.site\b/)?.[0];
if(!hostname)throw Error('Permanent link not issued');
function query(host,address,port,domain,expectDenied=false){
  return new Promise((resolve,reject)=>{
    const q=Buffer.alloc(12);q.writeUInt16BE(1234);q.writeUInt16BE(256,2);q.writeUInt16BE(1,4);
    const body=Buffer.concat([q,...domain.split('.').map(x=>Buffer.concat([Buffer.from([x.length]),Buffer.from(x)])),Buffer.from([0,0,1,0,1])]);
    const frame=Buffer.alloc(body.length+2);frame.writeUInt16BE(body.length);body.copy(frame,2);
    let data=Buffer.alloc(0),done=false;
    const tls=connect({host:address,port,servername:host,rejectUnauthorized:true},()=>tls.write(frame));
    const end=(error)=>{if(done)return;done=true;clearTimeout(timer);tls.destroy();error?reject(error):resolve(true)};
    const timer=setTimeout(()=>end(Error('DNS probe timeout')),12000);
    tls.on('error',()=>end(expectDenied?null:Error('TLS or DNS failure')));
    tls.on('close',()=>end(expectDenied?null:Error('DNS response closed')));
    tls.on('data',b=>{
      data=Buffer.concat([data,b]);if(data.length<2||data.length<2+data.readUInt16BE(0))return;
      const rcode=data[5]&15;
      if(expectDenied){end(rcode===2?null:Error('Expired/unknown link accepted'));return;}
      end(data.readUInt16BE(2)===1234&&rcode===0&&data.readUInt16BE(8)>0?null:Error('Bad DNS reply'));
    });
  });
}
try{
  const port=Number(process.env.OWNER_TEST_PORT);
  const local=process.env.OWNER_TEST_PUBLIC==='yes'?'10.66.77.2':'127.0.0.1';
  for(const domain of ['example.org','www.youtube.com','rr1---sn-gxuo03g-ig3s.googlevideo.com'])await query(hostname,local,port,domain);
  await query(randomBytes(8).toString('hex').slice(0,12)+'.dns.mnebyvpn.site',local,port,'example.org',true);
  // Each probe intentionally expires its fixture. A later probe must not
  // reuse that idempotency key and mistake the old expiry for issuance failure.
  const probeId='probe-'+randomUUID();
  const temporary=await ownerDnsLinksAction(db,owner,owner,key,'dnslinks:new:1h',probeId);
  const expired=temporary.text.match(/\b[a-z0-9]{12}\.dns\.mnebyvpn\.site\b/)?.[0];
  if(!expired)throw Error('Temporary link not issued');
  await db.query(`UPDATE owner_dns_links SET expires_at=clock_timestamp()-interval '1 second' WHERE owner_telegram_id=$1 AND request_key=$2 AND NOT permanent`,[String(owner),'new:'+probeId]);
  await query(expired,local,port,'example.org',true);
  if(process.env.OWNER_TEST_PUBLIC==='yes'){
    for(const address of ['89.125.90.101','188.120.254.223']){
      await query(hostname,address,853,'example.org');await query(hostname,address,853,'www.youtube.com');
    }
  }
  const cipher=publicEncrypt({key:readFileSync('/response.pub'),padding:constants.RSA_PKCS1_OAEP_PADDING,oaepHash:'sha256'},Buffer.from(hostname));
  console.log(JSON.stringify({ok:true,publicVerified:process.env.OWNER_TEST_PUBLIC==='yes',ciphertext:cipher.toString('base64'),utc:new Date().toISOString()}));
}finally{await db.end();}
