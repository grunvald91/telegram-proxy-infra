// Run inside the existing production bot container; never send Telegram requests.
// All data is scoped to one uncommitted transaction and is always rolled back.
import {Client} from 'pg';
import {randomUUID,randomInt,createHash} from 'node:crypto';
import {personalDnsTelegramMenu,personalDnsTelegramAction} from './apps/service/src/personal-dot-telegram-view.ts';
import {sendPersonalDnsMobileconfig} from './packages/dns-policy/src/personal-dot-profile.ts';
const db=new Client({connectionString:process.env.DATABASE_URL,connectionTimeoutMillis:5000,statement_timeout:8000});
const a=randomUUID(),o=randomUUID(),e=randomUUID();
let stage='connect';
function check(ok){if(!ok)throw Error('contract failed');}
function pass(name){console.log('FI_BOT_TEST_'+name+'=PASS');}
function buttons(m){return m.reply_markup.inline_keyboard.flat();}
function action(m,callback){return buttons(m).some(b=>b.callback_data===callback);}
function hostname(m,suffix){
 const v=buttons(m).find(b=>b.copy_text)?.copy_text.text;
 check(typeof v==='string'&&new RegExp('^[a-z0-9]{12}\\.'+suffix+'\\.mnebyvpn\\.site$').test(v));
 return v;
}
let opened=false;
try{
 await db.connect();
 check(process.env.MNEBYDNS_REGIONAL_DOT_ENABLED==='yes');
 await db.query('BEGIN');opened=true;
 await db.query("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='8s'; SET LOCAL idle_in_transaction_session_timeout='45s'");
 stage='fixture';
 const actor=randomInt(1000000000000,1000100000000),other=actor+1;
 const absent=await db.query('SELECT NOT EXISTS(SELECT 1 FROM accounts WHERE telegram_user_id IN ($1,$2)) AS ok',[actor,other]);
 check(absent.rows[0].ok);
 await db.query('INSERT INTO accounts(id,telegram_user_id) VALUES($1,$2)',[a,actor]);
 await db.query("INSERT INTO orders(id,account_id,product,provider,amount_minor,currency,state) VALUES($1,$2,'smart_dns','fi_dns_bot_release_canary',0,'RUB','PAID')",[o,a]);
 await db.query("INSERT INTO entitlements(id,account_id,source_order_id,product,state,revision,starts_at,expires_at,dns_query_quota_per_30d) VALUES($1,$2,$3,'smart_dns','ACTIVE',1,clock_timestamp()-interval '1 minute',clock_timestamp()+interval '10 minutes',1000000)",[e,a,o]);
 const menu=()=>personalDnsTelegramMenu(db,actor,[],[],true);
 const deliver=async(host)=>sendPersonalDnsMobileconfig(actor,host,'123456:abcdefghijklmnopqrstuvwxyz12345',async(url,opts)=>{
   // Local capture only. No outbound fetch and no real Telegram token.
   const form=opts.body;
   check(form.get('chat_id')===String(actor));
   const file=form.get('document'),xml=await file.text();
   check(file.name.endsWith('.mobileconfig')&&xml.includes('<key>ServerName</key><string>'+host+'</string>'));
   return new Response(JSON.stringify({ok:true,result:{chat:{id:actor}}}),{status:200});
 });
 stage='de';
 check(action(await menu(),'dns:issue'));
 const de=hostname(await personalDnsTelegramAction(db,actor,'dns:issue',deliver,true),'dns');
 check(action(await menu(),'dns:fi:execute:0'));
 pass('DE_AND_FI_MENU');
 stage='ownership';
 check(!action(await personalDnsTelegramMenu(db,other,[],[],true),'dns:fi:execute:0'));
 const unauthorized=await personalDnsTelegramAction(db,other,'dns:fi:execute:0',undefined,true);
 check(!buttons(unauthorized).some(b=>b.copy_text));
 pass('OWNER_ISOLATION');
 stage='issue';
 const issued=await personalDnsTelegramAction(db,actor,'dns:fi:execute:0',deliver,true);
 const fi=hostname(issued,'fi');
 check(issued.text.includes('Финляндия')&&issued.text.includes('отправлен отдельным документом'));
 check(action(await menu(),'dns:fi:confirm:1'));
 const before=await db.query('SELECT token_sha256 FROM personal_dns_credentials WHERE entitlement_id=$1',[e]);
 check(before.rows[0].token_sha256===createHash('sha256').update(de.split('.')[0]).digest('hex'));
 pass('FI_LINK_AND_MOBILECONFIG');
 stage='rotation';
 const replay=await personalDnsTelegramAction(db,actor,'dns:fi:execute:0',undefined,true);
 check(!buttons(replay).some(b=>b.copy_text));
 const confirm=await personalDnsTelegramAction(db,actor,'dns:fi:confirm:1',undefined,true);
 check(action(confirm,'dns:fi:execute:1'));
 const rotated=hostname(await personalDnsTelegramAction(db,actor,'dns:fi:execute:1',deliver,true),'fi');
 check(fi!==rotated&&action(await menu(),'dns:fi:confirm:2'));
 const after=await db.query('SELECT token_sha256 FROM personal_dns_credentials WHERE entitlement_id=$1',[e]);
 check(after.rows[0].token_sha256===before.rows[0].token_sha256);
 pass('FI_ROTATION_DE_UNCHANGED');
 stage='rollback';
 await db.query('ROLLBACK');opened=false;
 check((await db.query('SELECT NOT EXISTS(SELECT 1 FROM accounts WHERE id=$1) AS ok',[a])).rows[0].ok);
 pass('ROLLBACK');
 console.log('FI_BOT_LIVE_CONTRACT=PASS');
}catch{
 console.log('FI_BOT_LIVE_CONTRACT=BLOCKED:'+stage);process.exitCode=2;
}finally{
 if(opened){try{await db.query('ROLLBACK');pass('ROLLBACK');}catch{process.exitCode=3;}}
 await db.end().catch(()=>{process.exitCode=3;});
}
