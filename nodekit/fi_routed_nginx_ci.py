#!/usr/bin/env python3
"""Exercise exact nonroot systemd service settings with a local TLS origin."""
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time

def run(*args):
    return subprocess.run(args,check=True,capture_output=True,text=True).stdout

def main():
    unit="mnebyvpn-fi-sni-fixture.service"
    path=Path("/run/systemd/system")/unit
    assert not path.exists()
    src=Path(__file__).resolve().parent/"systemd/fi-routed/mnebyvpn-fi-sni-routed-v2.service"
    with tempfile.TemporaryDirectory(prefix="fi-sni-fixture-",dir="/run") as d:
        root=Path(d)
        marker=root/"enable";marker.touch()
        config=root/"nginx.conf"
        cert=root/"cert";key=root/"key"
        run("openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","1","-subj","/CN=fixture.example.net","-addext","subjectAltName=DNS:fixture.example.net","-keyout",str(key),"-out",str(cert))
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cert,key)
        origin=socket.socket();origin.bind(("127.0.0.1",0));origin.listen(2)
        dns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);dns.bind(("127.0.0.1",0))
        origin_port=origin.getsockname()[1];dns_port=dns.getsockname()[1]
        def serve_dns():
            try:
                while True:
                    q,peer=dns.recvfrom(4096)
                    # Nginx resolver asks for a single A question.
                    off=12
                    while q[off]:off+=1+q[off]
                    off+=5
                    question=q[12:off]
                    answer=b"\xc0\x0c"+struct.pack("!HHIH",1,1,30,4)+socket.inet_aton("127.0.0.1")
                    dns.sendto(q[:2]+struct.pack("!HHHHH",0x8180,1,1,0,0)+question+answer,peer)
            except OSError:pass
        def serve_origin():
            try:
                raw,_=origin.accept()
                with raw,ctx.wrap_socket(raw,server_side=True) as tls:
                    tls.sendall(b"OK")
            except OSError:pass
        threading.Thread(target=serve_dns,daemon=True).start()
        threading.Thread(target=serve_origin,daemon=True).start()
        config.write_text(f"""load_module /usr/lib/nginx/modules/ngx_stream_module.so;
worker_processes 1;
error_log stderr warn;
pid /run/mnebyvpn-fi-route-fixture/nginx.pid;
events {{ worker_connections 128; }}
stream {{
 map $ssl_preread_server_name $target {{
   default "";
   fixture.example.net fixture.example.net:{origin_port};
 }}
 resolver 127.0.0.1:{dns_port} ipv6=off valid=30s;
 server {{
   listen 127.0.0.1:14443;
   ssl_preread on;
   proxy_pass $target;
 }}
}}
""")
        text=src.read_text().replace("/var/lib/mnebyvpn-nodekit/fi-test-01/dns-auth/routed-dataplane.enable",str(marker)).replace("/var/lib/mnebyvpn-nodekit/fi-test-01/dns-auth/RoutedNginxV2.conf",str(config)).replace("RuntimeDirectory=mnebyvpn-fi-route","RuntimeDirectory=mnebyvpn-fi-route-fixture").replace("/run/mnebyvpn-fi-route/","/run/mnebyvpn-fi-route-fixture/").replace("User=mnebyvpn-fi-sni","User=mnebyvpn-fi-fixture")
        path.write_text(text)
        try:
            run("systemctl","daemon-reload")
            run("systemctl","start",unit)
            for _ in range(30):
                try:
                    raw=socket.create_connection(("127.0.0.1",14443),timeout=.5)
                    raw.close();break
                except OSError:time.sleep(.2)
            else:raise RuntimeError("fixture_listener_missing")
            pid=int(run("systemctl","show",unit,"-p","MainPID","--value").strip())
            status=dict(line.split(":",1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
            assert all(int(x)>0 for x in status["Uid"].split())
            assert int(status["CapEff"].strip(),16)==0
            client=ssl.create_default_context(cafile=str(cert))
            with socket.create_connection(("127.0.0.1",14443),timeout=6) as raw:
                with client.wrap_socket(raw,server_hostname="fixture.example.net") as tls:
                    assert tls.recv(2)==b"OK"
            with socket.create_connection(("127.0.0.1",14443),timeout=5) as raw:
                try:
                    with client.wrap_socket(raw,server_hostname="unknown.example.net"):raise AssertionError("unknown SNI accepted")
                except (ssl.SSLEOFError,ConnectionResetError):pass
            print("FI_NGINX_SYSTEMD_UNPRIVILEGED_TLS_PROXY=PASS")
        except BaseException:
            print(subprocess.run(["journalctl","-u",unit,"--no-pager","-n","30"],capture_output=True,text=True).stdout)
            raise
        finally:
            subprocess.run(["systemctl","stop",unit],capture_output=True)
            path.unlink(missing_ok=True)
            run("systemctl","daemon-reload")
            origin.close();dns.close()

if __name__=="__main__":main()
