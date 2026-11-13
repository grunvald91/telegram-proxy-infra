#!/usr/bin/env python3
"""Read-only TLS HTTP and TCP control checks from one GitHub runner."""
import socket
import ssl
import sys

phase=sys.argv[1]
assert phase in ("before","during","after")
def check(host,port,server_name=None,redirect=False):
    try:
        with socket.create_connection((host,port),timeout=4) as s:
            if not server_name:return "connected"
            with ssl.create_default_context().wrap_socket(s,server_hostname=server_name) as tls:
                tls.settimeout(5)
                tls.sendall(("GET / HTTP/1.1\r\nHost: "+server_name+
                             "\r\nConnection: close\r\n\r\n").encode())
                status=tls.recv(256).split(b"\r\n",1)[0]
                if b" 200 " in status:return "HTTP200"
                if redirect and any(x in status for x in (b" 301 ",b" 308 ")):return "HTTP3XX"
                return "unexpected_http"
    except Exception as exc:return type(exc).__name__
for name,host,port,sni,redirect in (
    ("ru443","188.120.254.223",443,"mnebyvpn.site",False),
    ("www443","188.120.254.223",443,"www.mnebyvpn.site",True),
    ("ru8443","188.120.254.223",8443,None,False),
    ("de8443","89.125.90.101",8443,None,False)):
    print(phase.upper()+"_"+name+"="+check(host,port,sni,redirect),flush=True)
