#!/usr/bin/env python3
"""Read-only correlation of observed media hello with kernel TCP_INFO counters."""
import concurrent.futures, hashlib, hmac, importlib.util, json, os, pathlib, re, subprocess, time
root=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('obs',root/'observer.py');obs=importlib.util.module_from_spec(spec);spec.loader.exec_module(obs)
obs.CAPTURE_SECONDS=75
raw_decode=obs.decode;salt=os.urandom(32);seen=set();futures=[]
pool=concurrent.futures.ThreadPoolExecutor(max_workers=2)
def probe(ip,port,expected,ident):
    time.sleep(2)
    args=['ss','-Htin','state','established','(','sport','=',':443','and','dst',ip,'and','dport','=',':'+str(port),')']
    p=subprocess.run(args,capture_output=True,text=True,timeout=5)
    received=re.search(r'bytes_received:(\d+)',p.stdout);sent=re.search(r'bytes_sent:(\d+)',p.stdout)
    result={'flow':ident,'host_family':'googlevideo.com','tls_record_expected':expected,'ss_exit':p.returncode,
            'kernel_socket_found':bool(p.stdout.strip()),'kernel_received_bytes':int(received[1]) if received else None,
            'kernel_sent_bytes':int(sent[1]) if sent else 0,'seconds_after_observed_prefix':2}
    print('KERNEL_MEDIA_RECEIPT='+json.dumps(result,sort_keys=True),flush=True)
def decode(frame,network):
    pkt=raw_decode(frame,network)
    if pkt and len(seen)<3:
        src,sp,dst,dp,*_=pkt;body=pkt[-1]
        if dst=='89.125.90.101' and dp==443 and len(body)>=9 and (src,sp) not in seen:
            name=obs.tls_sni(body)
            if name and name.endswith('.googlevideo.com'):
                seen.add((src,sp));ident=hmac.new(salt,repr((src,sp)).encode(),hashlib.sha256).hexdigest()[:10]
                futures.append(pool.submit(probe,src,sp,5+int.from_bytes(body[3:5],'big'),ident))
    return pkt
raw=subprocess.run(['nft','-j','list','ruleset'],capture_output=True,text=True,check=True,timeout=5).stdout
for marker in ['mnebydns_youtube_window4_test','mnebydns_youtube_synsplit_test']:
    if marker in raw:raise RuntimeError('EXPERIMENTAL_RULE_REMAINS')
print('ORDINARY_TCP_RULES_RESTORED=true',flush=True)
obs.decode=decode
try:obs.run()
finally:
    pool.shutdown(wait=True)
    for f in futures:f.result()
    print('KERNEL_MEDIA_RECEIPT_PROBE_COUNT='+str(len(seen)),flush=True)
