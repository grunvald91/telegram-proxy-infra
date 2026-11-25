#!/usr/bin/env python3
"""Real pinned CoreDNS + Nginx startup regression with synthetic 618/75 catalog."""
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
from fi_shared_routes import render_core,render_nginx,FI

def exact_read(sock,n):
    data=b""
    while len(data)<n:
        part=sock.recv(n-len(data))
        assert part,"unexpected EOF"
        data+=part
    return data

def question(name,kind,ctx):
    q=struct.pack("!HHHHHH",1234,256,1,0,0,0)+b"".join(bytes([len(s)])+s.encode() for s in name.split("."))+b"\0"+struct.pack("!HH",kind,1)
    with socket.create_connection(("127.0.0.1",18855),timeout=3) as raw:
        with ctx.wrap_socket(raw,server_hostname="test.example.net") as tls:
            tls.sendall(struct.pack("!H",len(q))+q)
            r=exact_read(tls,struct.unpack("!H",exact_read(tls,2))[0])
    ident,flags,qd,an,_,_=struct.unpack("!HHHHHH",r[:12])
    assert ident==1234 and flags&0x8000 and not flags&15 and qd==1
    assert r[12:len(q)]==q[12:]
    if kind==1:
        assert an==1 and r[-4:]==socket.inet_aton(FI)
    else:assert an==0

def main(binary):
    p={"exact":["service"+str(i)+".long-domain-name.example.net" for i in range(618)],
       "families":["family"+str(i)+".long-domain-name.example.net" for i in range(75)]}
    with tempfile.TemporaryDirectory() as tmp:
        d=Path(tmp)
        cert=d/"cert.pem";key=d/"key.pem"
        subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","1","-subj","/CN=test.example.net","-addext","subjectAltName=DNS:test.example.net","-keyout",str(key),"-out",str(cert)],check=True,capture_output=True)
        base="tls://.:8853 {\n  bind 127.0.0.1\n  tls "+str(cert)+" "+str(key)+"\n  errors\n  cache 20\n  forward . tls://1.1.1.1 tls://1.0.0.1 {\n    tls_servername cloudflare-dns.com\n  }\n}\n"
        (d/"Corefile").write_text(render_core(p,base))
        (d/"nginx.conf").write_text(render_nginx(p).replace("/run/mnebyvpn-fi-route-canary.pid",str(d/"nginx.pid")))
        subprocess.run(["nginx","-t","-c",str(d/"nginx.conf"),"-p",tmp],check=True)
        children=[]
        try:
            children.append(subprocess.Popen([binary,"-conf",str(d/"Corefile")]))
            children.append(subprocess.Popen(["nginx","-c",str(d/"nginx.conf"),"-p",tmp,"-g","daemon off;"]))
            for _ in range(30):
                assert all(c.poll() is None for c in children),"real service startup failed"
                try:
                    with socket.create_connection(("127.0.0.1",18855),timeout=.3),socket.create_connection(("127.0.0.1",14443),timeout=.3):pass
                    break
                except OSError:time.sleep(.2)
            else:raise RuntimeError("real service startup timed out")
            ctx=ssl.create_default_context(cafile=str(cert))
            for name in (p["exact"][0],p["exact"][309],p["exact"][-1],p["families"][-1],"a.b."+p["families"][0]):
                for kind in (1,28,5,64,65):question(name,kind,ctx)
            # Unlisted SNI must not cause any upstream connection. An empty
            # backend closes the TLS stream; no external network required.
            with socket.create_connection(("127.0.0.1",14443),timeout=3) as raw:
                try:
                    with ctx.wrap_socket(raw,server_hostname="not-routed.example.org"):raise AssertionError("unknown SNI accepted")
                except ssl.SSLError:pass
            assert all(c.poll() is None for c in children)
            print("FI_ROUTE_REAL_BINARIES_618_75_STARTUP_AND_25_DNS_ANSWERS=PASS")
        finally:
            for c in reversed(children):
                if c.poll() is None:
                    c.terminate()
                    try:c.wait(5)
                    except subprocess.TimeoutExpired:c.kill();c.wait(5)

if __name__=="__main__":main(sys.argv[1])
