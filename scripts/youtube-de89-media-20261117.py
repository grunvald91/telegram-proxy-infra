#!/usr/bin/env python3
"""Obtain a test-video URL through DE89, then read a bounded media range via SmartDNS."""
import json, os, pathlib, subprocess, sys, time, urllib.parse
def emit(k,v):print(k+'='+json.dumps(v,sort_keys=True),flush=True)
start=time.monotonic()
cmd=[sys.executable,'-m','yt_dlp','--proxy','socks5://127.0.0.1:10889','--js-runtimes','node',
     '--socket-timeout','10','--extractor-retries','0','--retries','0','--no-playlist',
     '--skip-download','--no-warnings','--no-progress','--dump-single-json','https://www.youtube.com/watch?v=BaW_jenozKc']
try:p=subprocess.run(cmd,capture_output=True,text=True,timeout=100)
except subprocess.TimeoutExpired:
    emit('MEDIA_EXTRACTION',{'success':False,'reason':'timeout','media_transfer_tested':False});raise SystemExit(0)
if p.returncode:
    err=p.stderr.lower()
    reason='login_or_bot_challenge' if ('sign in' in err or 'bot' in err) else 'extractor_failed'
    emit('MEDIA_EXTRACTION',{'success':False,'reason':reason,'media_transfer_tested':False,'elapsed_ms':round((time.monotonic()-start)*1000)})
    raise SystemExit(0)
info=json.loads(p.stdout)
formats=[f for f in info.get('formats',[]) if '.googlevideo.com' in (urllib.parse.urlsplit(f.get('url','')).hostname or '') and f.get('protocol') in ('http','https')]
if not formats:
    emit('MEDIA_EXTRACTION',{'success':True,'usable_direct_media_formats':0,'media_transfer_tested':False});raise SystemExit(0)
f=next((f for f in formats if f.get('vcodec') not in (None,'none')),formats[0])
url=f['url'];u=urllib.parse.urlsplit(url);host=u.hostname
query=urllib.parse.parse_qs(u.query)
emit('MEDIA_EXTRACTION',{'success':True,'usable_direct_media_formats':len(formats),'url_bound_to_DE89':query.get('ip')==['89.125.90.101'],'urls_logged':False})
# Range is appended without rewriting signed parameters.
url+=('&' if '?' in url else '?')+'range=0-65535'
base=pathlib.Path(os.environ['RUNNER_TEMP'])
for label,route in [('DE89_SOCKS_ORIGIN',['--proxy','socks5h://127.0.0.1:10889']),('DE89_SMARTDNS',['--noproxy','*','--resolve',host+':443:89.125.90.101'])]:
    body=base/(label+'.body');headers=base/(label+'.headers')
    args=['curl','--silent','--show-error','-4','--http1.1','--connect-timeout','8','--max-time','20',
          '--max-filesize','131072','--range','0-65535','--output',str(body),'--dump-header',str(headers),
          '--write-out','%{json}',*route,'--config','-']
    config='url = '+json.dumps(url)+'\n'
    try:
        r=subprocess.run(args,input=config,capture_output=True,text=True,timeout=23)
        result=json.loads(r.stdout) if r.stdout else {}
        content_type=result.get('content_type','')
        emit('MEDIA_RANGE',{'route':label,'curl_exit':r.returncode,'http_status':result.get('http_code'),
             'received_bytes':body.stat().st_size if body.exists() else 0,
             'content_type':content_type,'certificate_verify_result':result.get('ssl_verify_result'),
             'total_seconds':result.get('time_total'),'media_mime':content_type.startswith(('video/','audio/'))})
    except subprocess.TimeoutExpired:emit('MEDIA_RANGE',{'route':label,'error':'timeout'})
    finally:
        body.unlink(missing_ok=True);headers.unlink(missing_ok=True)
