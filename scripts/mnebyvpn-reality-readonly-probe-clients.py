#!/usr/bin/env python3
"""Build temporary local Xray clients from read-only existing owner node INSPECT."""
import json
import pathlib
import sys
import uuid

dest=pathlib.Path(sys.argv[1])
info=json.loads(pathlib.Path(sys.argv[2]).read_text())
identity=str(uuid.UUID(info['credential']))
pbk=info['publicKey'];sid=info['shortId']
assert len(pbk)==43 and len(sid)==16
dest.mkdir(parents=True,exist_ok=True)

def make(mode,port):
    is_ws=mode.startswith("ws_")
    is_ip=mode.endswith("_ip")
    hostname="89.125.90.101" if is_ip else "cdn.servgo.ru"
    if is_ws:
        stream={"network":"ws","security":"tls","tlsSettings":{
            "serverName":"cdn.servgo.ru","allowInsecure":False},
            "wsSettings":{"path":"/mnebyvpn-vpn/ws","headers":{"Host":"cdn.servgo.ru"}}}
        user={"id":identity,"encryption":"none"}
        remote_port=8443
    else:
        stream={"network":"tcp","security":"reality","realitySettings":{
            "serverName":"www.cloudflare.com","fingerprint":"firefox" if mode=="reality_firefox" else "chrome",
            "password":pbk,"shortId":sid,"spiderX":"/"}}
        user={"id":identity,"encryption":"none","flow":"xtls-rprx-vision"}
        remote_port=2053
    obj={"log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"socks",
                    "settings":{"auth":"noauth","udp":False}}],
        "outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":hostname,
                      "port":remote_port,"users":[user]}]},"streamSettings":stream}]}
    p=dest/(mode+".json")
    p.write_text(json.dumps(obj))
    p.chmod(0o600)
for mode,port in [("ws_domain",19083),("ws_ip",19084),
                  ("reality_domain",19085),("reality_ip",19086),
                  ("reality_firefox",19087)]:
    make(mode,port)
print("operator_xray_client_configs=5_generated",flush=True)
