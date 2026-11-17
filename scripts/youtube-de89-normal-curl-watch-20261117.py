#!/usr/bin/env python3
"""Sparse normal-TLS watcher: match TLS Random, kernel receipt and emitted ACKs."""
import concurrent.futures,hashlib,importlib.util,json,os,pathlib,re,signal,struct,subprocess,time
ROOT=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('obs',ROOT/'observer.py');obs=importlib.util.module_from_spec(spec);spec.loader.exec_module(obs)
def emit(k,v):print(k+'='+json.dumps(v,sort_keys=True),flush=True)
seen={};by_peer={};futures=[];pool=concurrent.futures.ThreadPoolExecutor(max_workers=2)
private=ROOT/'bindings.private.jsonl'
def measure(entry):
    time.sleep(2)
    p=subprocess.run(['ss','-Htin','state','established','(','sport','=',':443','and','dst',entry['address'],'and','dport','=',':'+str(entry['port']),')'],capture_output=True,text=True,timeout=5)
    got=re.search(r'bytes_received:(\d+)',p.stdout);sent=re.search(r'bytes_sent:(\d+)',p.stdout)
    a=list(entry['acks'])
    emit('NORMAL_TLS_KERNEL_RECEIPT',{'probe':entry['probe'],'domain':entry['domain'],'expected_tls_record':entry['expected'],'first_payload_bytes':entry['prefix'],'socket_found':bool(p.stdout.strip()),'kernel_received_bytes':int(got[1]) if got else None,'kernel_sent_bytes':int(sent[1]) if sent else 0,'ss_exit':p.returncode,'emitted_pure_ack_count':len(a),'largest_emitted_ack_bytes':max(a,default=None)})
filt='ip and tcp and ((dst host 89.125.90.101 and dst port 443 and tcp[((tcp[12] & 0xf0) >> 2)] = 0x16) or (src host 89.125.90.101 and src port 443 and (tcp[13] & 0x17) = 0x10 and (ip[2:2] - ((ip[0] & 0xf) << 2) - ((tcp[12] & 0xf0) >> 2)) = 0))'
p=subprocess.Popen(['timeout','1800','tcpdump','-i','eth0','-n','-U','-B','32768','-s','8192','-w','-',filt],stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
try:
    endian,link=obs.read_header(p.stdout);(ROOT/'READY').write_text('ARMED\n');emit('NORMAL_CURL_WATCH_READY',True)
    while True:
        h=obs.read_exact(p.stdout,16)
        if h is None:break
        _,_,cap,_=struct.unpack(endian+'IIII',h)
        if cap>8192:raise RuntimeError('BAD_PREFIX_SIZE')
        frame=obs.read_exact(p.stdout,cap)
        if frame is None:raise RuntimeError('SHORT_PCAP')
        q=obs.decode(frame,link)
        if not q:continue
        src,sp,dst,dp,seq,flags,window,plen,ack,_,_,body=q
        if src=='89.125.90.101' and sp==443:
            entry=by_peer.get((dst,dp))
            if entry and len(entry['acks'])<128:
                n=(ack-entry['base'])&0xffffffff
                if n<(1<<31):entry['acks'].append(n)
            continue
        if len(body)<43 or body[0]!=22 or body[5]!=1 or len(seen)>=512:continue
        name=obs.tls_sni(body)
        if name not in ['youtubei.googleapis.com','rr1---sn-gxuo03g-ig3s.googlevideo.com']:continue
        token=hashlib.sha256(body[11:43]).hexdigest()[:16]
        if token in seen:continue
        entry={'probe':token,'domain':name,'address':src,'port':sp,'expected':5+int.from_bytes(body[3:5],'big'),'prefix':len(body),'base':seq,'acks':[],'observed_at':time.time()}
        seen[token]=entry;by_peer[(src,sp)]=entry
        with private.open('a') as f:f.write(json.dumps({k:v for k,v in entry.items() if k!='acks'})+'\n')
        os.chmod(private,0o600)
        futures.append(pool.submit(measure,entry))
finally:
    if p.poll() is None:p.send_signal(signal.SIGINT)
    _,stats=p.communicate(timeout=10);pool.shutdown(wait=True)
    for f in futures:f.result()
    drops=re.search(rb'(\d+) packets dropped by kernel',stats)
    emit('NORMAL_CURL_WATCH_FINISHED',{'flow_count':len(seen),'kernel_capture_drops':int(drops[1]) if drops else None})
