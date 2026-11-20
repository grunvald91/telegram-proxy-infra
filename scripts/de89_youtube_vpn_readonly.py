#!/usr/bin/env python3
"""Read-only DE89 end-to-end media and active VLESS check; never log UUID or video URL."""
import json, os, pathlib, socket, subprocess, sys, tempfile, time, uuid
from urllib.parse import urlsplit

url = sys.stdin.readline().strip()
p = urlsplit(url)
if p.scheme != "https" or not (p.hostname or "").endswith(".googlevideo.com"):
    url = ""
print("DE89_SIGNED_VIDEO_PRESENT=" + str(bool(url)).lower(), flush=True)

def curl(label, target, port=None, partial=False):
    cmd = ["curl", "-4", "-sS", "-L", "--connect-timeout", "7", "--max-time", "20",
           "-o", "/dev/null", "-w", "%{http_code} %{size_download}"]
    cmd += ["--noproxy", "", "--proxy", "socks5h://127.0.0.1:" + str(port)] if port else ["--noproxy", "*"]
    if partial: cmd += ["-r", "0-262143"]
    cmd.append(target)
    env = {k:v for k,v in os.environ.items() if not k.lower().endswith("_proxy")}
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=23, env=env)
        fields = r.stdout.split()
        code = fields[0] if fields else "000"
        size = int(float(fields[1])) if len(fields)>1 else 0
        ok = r.returncode == 0 and code in ("200","206") and (not partial or size>=1024)
        print("DE89_"+label+"=http:"+code+",bytes:"+str(size)+",rc:"+str(r.returncode)+",ok:"+str(ok).lower(),flush=True)
    except Exception as ex:
        print("DE89_"+label+"=error:"+type(ex).__name__,flush=True)

watch = "https://www.youtube.com/watch?v=jNQXAC9IVRw"
image = "https://i.ytimg.com/vi/jNQXAC9IVRw/hqdefault.jpg"
curl("DIRECT_WATCH",watch)
curl("DIRECT_IMAGE",image)
if url: curl("DIRECT_VIDEO_BYTES",url,partial=True)

cfg = pathlib.Path("/etc/mnebyvpn/xray-canary.json")
xray = pathlib.Path("/opt/xray/xray")
client_id = None
if cfg.is_file():
    try:
        data=json.loads(cfg.read_text())
        for inbound in data.get("inbounds",[]):
            if inbound.get("protocol")=="vless" and str(inbound.get("port"))=="18943":
                for client in inbound.get("settings",{}).get("clients",[]):
                    try: client_id=str(uuid.UUID(client.get("id",""))); break
                    except (ValueError,TypeError,AttributeError): pass
                if client_id: break
    except (ValueError,OSError,TypeError): pass
print("DE89_REAL_VLESS_ID_AVAILABLE="+str(bool(client_id)).lower(),flush=True)
if not client_id or not xray.is_file():
    print("DE89_VLESS_CHECK=blocked",flush=True)
    sys.exit(0)

with tempfile.TemporaryDirectory(prefix="de89-yt-",dir="/run") as tmp:
    with socket.socket() as s:
        s.bind(("127.0.0.1",0))
        port=s.getsockname()[1]
    data={"log":{"loglevel":"error"},
      "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"socks","settings":{"auth":"noauth","udp":False}}],
      "outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"89.125.90.101","port":8443,
        "users":[{"id":client_id,"encryption":"none"}]}]},
        "streamSettings":{"network":"ws","security":"tls",
        "tlsSettings":{"serverName":"cdn.servgo.ru","allowInsecure":False},
        "wsSettings":{"path":"/mnebyvpn-vpn/ws","headers":{"Host":"cdn.servgo.ru"}}}}]}
    path=pathlib.Path(tmp)/"client.json"
    path.write_text(json.dumps(data)); os.chmod(path,0o600)
    proc=subprocess.Popen([str(xray),"run","-config",str(path)],
          stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        ready=False
        for _ in range(30):
            if proc.poll() is not None: break
            try:
                with socket.create_connection(("127.0.0.1",port),timeout=0.3):
                    ready=True;break
            except OSError: time.sleep(0.2)
        print("DE89_EPHEMERAL_VLESS_SOCKS_READY="+str(ready).lower(),flush=True)
        if ready:
            curl("VLESS_EXAMPLE","https://example.com/",port)
            curl("VLESS_WATCH",watch,port)
            curl("VLESS_IMAGE",image,port)
            if url: curl("VLESS_VIDEO_BYTES",url,port,partial=True)
    finally:
        proc.terminate()
        try:proc.wait(timeout=3)
        except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=3)
print("DE89_VIDEO_READONLY_PROBE_COMPLETE=true",flush=True)
