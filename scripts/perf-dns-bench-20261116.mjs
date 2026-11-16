import {Pool} from 'pg';
import {connect} from 'node:tls';
import {performance} from 'node:perf_hooks';
import {dnsAdminOwner} from './apps/service/src/dns-admin.ts';
import {ownerDnsKey,ownerDnsLinksAction} from './apps/service/src/owner-dns-links.ts';
const db=new Pool({connectionString:process.env.DATABASE_URL,connectionTimeoutMillis:2500,statement_timeout:2500});
const owner=dnsAdminOwner(),key=ownerDnsKey(process.env.MNEBYDNS_OWNER_LINK_KEY);
const page=await ownerDnsLinksAction(db,owner,owner,key,'dnslinks:permanent','perf-bench-20261116');
const hostname=page.text.match(/\b[a-z0-9]{12}\.dns\.mnebyvpn\.site\b/)?.[0];
await db.end();if(!hostname)throw Error('Owner DNS unavailable');
const targets=[['personal-private','10.66.77.2',8856,hostname],['personal-DE','89.125.90.101',853,hostname],['personal-RU','188.120.254.223',853,hostname],['mapped-upstream','10.66.77.1',1853,'dns.mnebyvpn.site'],['direct-upstream','1.1.1.1',853,'one.one.one.one']];
const summary=values=>{
  const a=values.toSorted((a,b)=>a-b);return {n:a.length,p50_ms:a.length?+a[Math.floor(a.length/2)].toFixed(2):null,p95_ms:a.length?+a[Math.min(a.length-1,Math.ceil(a.length*.95)-1)].toFixed(2):null,max_ms:a.length?+a.at(-1).toFixed(2):null};
};
function request(domain,id){const h=Buffer.alloc(12);h.writeUInt16BE(id);h.writeUInt16BE(256,2);h.writeUInt16BE(1,4);const b=Buffer.concat([h,...domain.split('.').map(s=>Buffer.concat([Buffer.from([s.length]),Buffer.from(s)])),Buffer.from([0,0,1,0,1])]);const frame=Buffer.alloc(b.length+2);frame.writeUInt16BE(b.length);b.copy(frame,2);return frame;}
const results=[];
for(const [tag,address,port,name] of targets){
  const row={tag,ordinary:[],premium:[],errors:[]};let socket;
  try{
    const t=performance.now();socket=connect({host:address,port,servername:name,rejectUnauthorized:true});
    await new Promise((resolve,reject)=>{const timer=setTimeout(()=>{socket.destroy();reject(Error('TLS timeout'));},6500);socket.once('secureConnect',()=>{clearTimeout(timer);resolve()});socket.once('error',()=>{clearTimeout(timer);reject(Error('TLS failure'))});});
    row.connect_tls_ms=+(performance.now()-t).toFixed(2);
    for(const [type,domain] of [['ordinary','example.org'],['premium','www.youtube.com']])for(let i=0;i<10;i++){
      const id=2000+i,start=performance.now();
      await new Promise((resolve,reject)=>{
        let b=Buffer.alloc(0),done=false;
        const end=(error)=>{if(done)return;done=true;clearTimeout(timer);socket.off('data',data);socket.off('close',close);socket.off('error',errorHandler);error?reject(error):resolve();};
        const close=()=>end(Error('DNS closed')),errorHandler=()=>end(Error('DNS error'));
        const data=part=>{b=Buffer.concat([b,part]);if(b.length>16386){end(Error('DNS oversized'));return;}if(b.length>=2&&b.length>=b.readUInt16BE(0)+2)end(b.readUInt16BE(2)===id&&(b[5]&15)===0?null:Error('DNS response rejected'));};
        const timer=setTimeout(()=>end(Error('DNS timeout')),9000);socket.on('data',data);socket.once('close',close);socket.once('error',errorHandler);socket.write(request(domain,id));
      });
      row[type].push(performance.now()-start);
    }
  }catch(e){row.errors.push(e.message);}finally{socket?.destroy();}
  results.push({tag:row.tag,connect_tls_ms:row.connect_tls_ms,ordinary:summary(row.ordinary),premium:summary(row.premium),errors:row.errors});
}
console.log(JSON.stringify({utc:new Date().toISOString(),results}));
