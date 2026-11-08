#!/usr/bin/env python3
"""Read-only authenticated WS/REALITY probes from Russian control-plane host.
Does not provision, revoke, or modify any Xray node or existing service.
Never prints or logs subscriber UUID, Reality metadata or bearer URL.
"""
import datetime as dt
import hashlib
import hmac
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

HASH="65159196f6dc7ce18685dd61f958679927889b3a8db907ce80c6b57ce6154a4e"
HOST="89.125.90.101"
KEY_PATH=pathlib.Path("/opt/mnebyvpn/bot/provisioner.key")
PSQL=["docker","exec","mnebyvpn-stage-postgres","psql","-AtX","-v","ON_ERROR_STOP=1",
      "-U","mnebyvpn_stage","-d","mnebyvpn_stage"]
TARGET="https://www.cloudflare.com/cdn-cgi/trace"
NAMES=("ws","reality_chrome","reality_firefox")
PORTS=(29083,29084,29085)

def owner():
    query=("SELECT e.id::text||'|'||e.revision::text FROM vpn_subscription_links l "
        "JOIN entitlements e ON e.id=l.entitlement_id JOIN provisioning_state p ON "
        "p.entitlement_id=e.id AND p.adapter='vpn' WHERE l.token_sha256='"+HASH+
        "' AND l.revoked_at IS NULL AND e.product='vpn' AND e.state='ACTIVE' "
        "AND e.expires_at>clock_timestamp()+interval '1 hour' AND p.applied_revision=e.revision")
    rows=subprocess.run(PSQL+["-c",query],check=True,capture_output=True,text=True,timeout=15).stdout.strip().splitlines()
    if len(rows)!=1 or rows[0].count("|")!=1:raise RuntimeError("Owner profile not uniquely active")
    identity,rev=rows[0].split("|")
    key=bytes.fromhex(KEY_PATH.read_text().strip())
    raw=json.dumps({"op":"inspect","id":identity,"ts":int(time.time())},
        separators=(",",":")).encode()
    req=urllib.request.Request("http://10.66.77.1:18944/v1/provision",raw,
        headers={"Content-Type":"application/json",
            "X-Mnebyvpn-Signature":hmac.new(key,raw,hashlib.sha256).hexdigest()},
        method="POST")
    with urllib.request.urlopen(req,timeout=9) as res:info=json.load(res)
    if info.get("enabled") is not True or info.get("revision")!=int(rev) or not info.get("reality"):
        raise RuntimeError("REALITY not signed and announced to current owner")
    expires=dt.datetime.fromisoformat(info["expiresAt"].replace("Z","+00:00"))
    if expires<=dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1):
        raise RuntimeError("Node expiry not safely beyond probe")
    return info

def config(info):
    cred=info["credential"]
    meta=info["reality"]
    ws={"tag":"ws","protocol":"vless",
        "settings":{"vnext":[{"address":HOST,"port":8443,
            "users":[{"id":cred,"encryption":"none"}]}]},
        "streamSettings":{"network":"ws","security":"tls",
            "tlsSettings":{"serverName":"cdn.servgo.ru","allowInsecure":False},
            "wsSettings":{"path":"/mnebyvpn-vpn/ws","headers":{"Host":"cdn.servgo.ru"}}}}
    outbounds=[ws]
    for fp in ("chrome","firefox"):
        outbounds.append({"tag":"reality_"+fp,"protocol":"vless",
            "settings":{"vnext":[{"address":HOST,"port":2053,
                "users":[{"id":cred,"encryption":"none","flow":"xtls-rprx-vision"}]}]},
            "streamSettings":{"network":"tcp","security":"reality",
                "realitySettings":{"serverName":"www.cloudflare.com","fingerprint":fp,
                    "password":meta["publicKey"],"shortId":meta["shortId"],
                    "spiderX":"/"}}})
    inbounds=[{"tag":"socks_"+tag,"listen":"127.0.0.1","port":port,
                "protocol":"socks","settings":{"auth":"noauth","udp":False}}
                for tag,port in zip(NAMES,PORTS)]
    routing={"rules":[{"type":"field","inboundTag":["socks_"+tag],
                         "outboundTag":tag} for tag in NAMES]}
    return {"log":{"loglevel":"warning"},"inbounds":inbounds,
            "outbounds":outbounds,"routing":routing}

def check_local_ports():
    for port in PORTS:
        s=socket.socket()
        try:s.bind(("127.0.0.1",port))
        finally:s.close()

def call(port):
    result=subprocess.run(["curl","--noproxy","","--proxy","socks5h://127.0.0.1:"+str(port),
        "--connect-timeout","4","--max-time","7","-fsS","-o","/dev/null",
        "-w","%{http_code} %{time_total}",TARGET],
        capture_output=True,text=True,timeout=9)
    pieces=result.stdout.split()
    return result.returncode, pieces[0] if pieces else "", round(float(pieces[1]),3) if len(pieces)>1 else None

def main():
    if len(sys.argv)!=2:raise RuntimeError("Xray binary path required")
    binary=pathlib.Path(sys.argv[1])
    if not binary.is_file():raise RuntimeError("Xray binary missing")
    route=subprocess.run(["ip","-4","route","get",HOST],capture_output=True,text=True,check=True,timeout=5).stdout
    route_dev=route.split(" dev ",1)[1].split()[0] if " dev " in route else "unknown"
    print("russia_probe_route_device="+route_dev,flush=True)
    if route_dev.startswith(("wg","tun")):raise RuntimeError("Russian probe routed over a VPN; invalid ISP evidence")
    check_local_ports()
    info=owner()
    with tempfile.TemporaryDirectory(prefix="mnebyvpn-reality-russia-",dir="/root") as folder:
        target=pathlib.Path(folder)/"client.json"
        target.write_text(json.dumps(config(info)))
        target.chmod(0o600)
        binary.chmod(0o700)
        subprocess.run([str(binary),"run","-test","-config",str(target)],
                       check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
        process=subprocess.Popen([str(binary),"run","-config",str(target)],
                                 stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            time.sleep(2)
            if process.poll() is not None:raise RuntimeError("Temporary test client exited")
            stats={name:[] for name in NAMES}
            for n in range(12):
                for name,port in zip(NAMES,PORTS):
                    ret,http,elapsed=call(port)
                    stats[name].append((ret,http,elapsed))
                if n<11:time.sleep(5)
            for name in NAMES:
                rows=stats[name]
                good=[x[2] for x in rows if x[0]==0 and x[1]=="200"]
                print("ru_probe_"+name+"_ok="+str(len(good))+"_of_"+str(len(rows)),flush=True)
                if good:print("ru_probe_"+name+"_avg_https_seconds="+str(round(sum(good)/len(good),3)),flush=True)
                if len(good)!=len(rows):
                    fail=[str(i+1) for i,x in enumerate(rows) if x[0]!=0 or x[1]!="200"]
                    print("ru_probe_"+name+"_failed_sample_indices="+",".join(fail),flush=True)
            print("ru_probe_elapsed_complete=true",flush=True)
        finally:
            process.terminate()
            try:process.wait(timeout=4)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=4)

if __name__=="__main__":
    try:main()
    except Exception as ex:
        print("ru_probe_failed="+type(ex).__name__,file=sys.stderr)
        sys.exit(2)
