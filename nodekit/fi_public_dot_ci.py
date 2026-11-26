#!/usr/bin/env python3
"""Real systemd socket activation test against a local TLS-only fixture."""
import os
from pathlib import Path
import socket
import ssl
import subprocess
import threading
import tempfile
import time

def run(*args):
    return subprocess.run(args,check=True,capture_output=True,text=True,timeout=20).stdout

def main():
    root=Path(__file__).resolve().parent
    units=root/"systemd/fi-public-dot"
    base="mnebyvpn-fi-public-dot-fixture"
    paths=[Path("/run/systemd/system")/(base+s) for s in (".socket",".service")]
    assert not any(p.exists() for p in paths)
    with tempfile.TemporaryDirectory(prefix="fi-dot-fixture-",dir="/run") as d:
        d=Path(d);marker=d/"enable";marker.touch()
        cert=d/"cert";key=d/"key"
        run("openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","1","-subj","/CN=fixture.example.net","-addext","subjectAltName=DNS:fixture.example.net","-keyout",str(key),"-out",str(cert))
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cert,key)
        backend=socket.socket();backend.bind(("127.0.0.1",0));backend.listen(8)
        port=backend.getsockname()[1]
        def origin():
            for _ in range(2):
                raw,_=backend.accept()
                with raw,ctx.wrap_socket(raw,server_side=True) as tls:
                    assert tls.recv(4)==b"test"
                    tls.unwrap().close()
        t=threading.Thread(target=origin,daemon=True);t.start()
        relay=d/"relay.py"
        relay.write_text((root/"fi_public_dot_relay.py").read_text().replace('PUBLIC_IP="217.11.167.91"','PUBLIC_IP="127.0.0.1"').replace("PUBLIC_PORT=853","PUBLIC_PORT=18530").replace('BACKEND=("127.0.0.1",18854)',f'BACKEND=("127.0.0.1",{port})'))
        for suffix,path in zip((".socket",".service"),paths):
            text=(units/("mnebyvpn-fi-public-dot"+suffix)).read_text().replace("mnebyvpn-fi-public-dot",base).replace("217.11.167.91:853","127.0.0.1:18530").replace("/var/lib/mnebyvpn-nodekit/fi-test-01/dns-auth/public-dot.enable",str(marker)).replace("/var/lib/mnebyvpn-nodekit/fi-test-01/dns-auth/PublicDotRelay.py",str(relay))
            text="\n".join(line for line in text.splitlines() if not line.startswith("BindsTo="))
            for dependency in ("mnebyvpn-fi-dns-country.service", "mnebyvpn-fi-sni-routed-v3.service", "mnebyvpn-fi-sni-egress-guard.service"):
                text = text.replace(" " + dependency, "")
            path.write_text(text+"\n")
        try:
            run("systemctl","daemon-reload")
            run("systemctl","start",base+".socket")
            client=ssl.create_default_context(cafile=str(cert))
            for _ in range(2):
                with socket.create_connection(("127.0.0.1",18530),timeout=5) as raw:
                    with client.wrap_socket(raw,server_hostname="fixture.example.net") as tls:
                        tls.sendall(b"test")
                        assert tls.recv(2)==b""
                        try:tls.unwrap().close()
                        except OSError:pass
            pid=int(run("systemctl","show",base+".service","-p","MainPID","--value").strip())
            assert pid>1
            status=dict(line.split(":",1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
            assert all(int(x)>0 for x in status["Uid"].split()) and int(status["CapEff"].strip(),16)==0
            print("FI_PUBLIC_DOT_SOCKET_ACTIVATION_TLS_TEST=PASS")
        except BaseException:
            print(subprocess.run(["journalctl","-u",base+".service","--no-pager","-n","30"],capture_output=True,text=True).stdout)
            raise
        finally:
            subprocess.run(["systemctl","stop",base+".socket",base+".service"],capture_output=True,timeout=15)
            for p in paths:p.unlink(missing_ok=True)
            run("systemctl","daemon-reload")
            backend.close()

if __name__=="__main__":main()
