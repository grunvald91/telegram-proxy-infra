#!/usr/bin/env python3
"""Thirty-minute sparse watcher for tagged owner-requested client probes only."""
import concurrent.futures,importlib.util,json,pathlib,re,signal,struct,subprocess,time
ROOT=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('obs',ROOT/'observer.py');obs=importlib.util.module_from_spec(spec);spec.loader.exec_module(obs)
def emit(k,v):print(k+'='+json.dumps(v,sort_keys=True),flush=True)
def measure(addr,port,token,expected,prefix):
    time.sleep(2)
    p=subprocess.run(['ss','-Htin','state','established','(','sport','=',':443','and','dst',addr,'and','dport','=',':'+str(port),')'],capture_output=True,text=True,timeout=5)
    got=re.search(r'bytes_received:(\d+)',p.stdout);sent=re.search(r'bytes_sent:(\d+)',p.stdout)
    emit('TAGGED_KERNEL_RECEIPT',{'probe':token,'expected_tls_record':expected,'observed_first_payload_bytes':prefix,'socket_found':bool(p.stdout.strip()),'kernel_received_bytes':int(got[1]) if got else None,'kernel_sent_bytes':int(sent[1]) if sent else 0,'ss_exit':p.returncode})
pool=concurrent.futures.ThreadPoolExecutor(max_workers=2);seen=set();futures=[]
filt='ip and tcp and dst host 89.125.90.101 and dst port 443 and tcp[((tcp[12] & 0xf0) >> 2)] = 0x16'
p=subprocess.Popen(['timeout','1800','tcpdump','-i','eth0','-n','-U','-B','32768','-s','8192','-w','-',filt],stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
try:
    endian,link=obs.read_header(p.stdout)
    (ROOT/'READY').write_text('ARMED\n');emit('TAGGED_WATCH_READY',True)
    while True:
        h=obs.read_exact(p.stdout,16)
        if h is None:break
        _,_,cap,_=struct.unpack(endian+'IIII',h)
        if cap>8192:raise RuntimeError('BAD_PREFIX_SIZE')
        frame=obs.read_exact(p.stdout,cap)
        if frame is None:raise RuntimeError('SHORT_PCAP')
        pkt=obs.decode(frame,link)
        if not pkt or len(seen)>=16:continue
        body=pkt[-1]
        match=re.search(rb'mnebydns-check-([0-9a-f]{16})',body)
        if not match or len(body)<9 or body[5]!=1:continue
        token=match[1].decode()
        if token in seen:continue
        seen.add(token)
        futures.append(pool.submit(measure,pkt[0],pkt[1],token,5+int.from_bytes(body[3:5],'big'),len(body)))
finally:
    if p.poll() is None:p.send_signal(signal.SIGINT)
    _,stats=p.communicate(timeout=10);pool.shutdown(wait=True)
    for f in futures:f.result()
    drops=re.search(rb'(\d+) packets dropped by kernel',stats)
    emit('TAGGED_WATCH_FINISHED',{'probe_count':len(seen),'kernel_capture_drops':int(drops[1]) if drops else None})
