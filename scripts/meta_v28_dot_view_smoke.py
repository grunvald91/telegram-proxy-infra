#!/usr/bin/env python3
"""Isolated real DNS-over-TLS source-view smoke on the running DE CoreDNS binary.

Only loopback TCP/15534 and temporary self-signed test certificate. Tests both
source addresses through TLS and actual DNS wire framing. Never reads private
production TLS keys, touches port 853, or edits running service configurations.
"""
from __future__ import annotations
import ipaddress
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import time

HOST="pilot.example.com"
PORT=15534
EXPECTED={"127.0.0.1":"188.120.254.223", "127.0.0.2":"89.125.90.101"}


def question():
    labels=b"".join(bytes([len(s)])+s.encode("ascii") for s in HOST.split("."))+b"\0"
    return struct.pack("!HHHHHH",0x44AC,0x0100,1,0,0,0)+labels+struct.pack("!HH",1,1)


def recv_exact(tls,n):
    buf=bytearray()
    while len(buf)<n:
        data=tls.recv(n-len(buf))
        if not data:raise AssertionError("DoT response prematurely closed")
        buf.extend(data)
    return bytes(buf)


def answer(peer,cert):
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as raw:
        raw.settimeout(2)
        raw.bind((peer,0))
        raw.connect(("127.0.0.1",PORT))
        ctx=ssl.create_default_context(cafile=str(cert))
        with ctx.wrap_socket(raw,server_hostname="localhost") as tls:
            if tls.version() not in ("TLSv1.2","TLSv1.3"):
                raise AssertionError("unexpected DoT TLS version")
            payload=question()
            tls.sendall(struct.pack("!H",len(payload))+payload)
            size=struct.unpack("!H",recv_exact(tls,2))[0]
            result=recv_exact(tls,size)
    if result[:2]!=b"\x44\xac" or len(result)<28 or (result[3]&15):
        raise AssertionError("invalid or negative DoT DNS response")
    if struct.unpack_from("!H",result,6)[0]!=1:
        raise AssertionError("DoT expected exactly one A answer")
    return str(ipaddress.IPv4Address(result[-4:]))


def corefile(cert,key):
    # Same-zone/port view ordering follows official CoreDNS view semantics.
    # The two blocks share the same loopback TLS listener, not port 853.
    block=f"""tls://.:{PORT} {{
    bind 127.0.0.1
    tls {cert} {key}
"""
    view="""    view pilot {
        expr client_ip() == '127.0.0.1'
    }
"""
    template='''    template IN A . {
        match ^pilot[.]example[.]com[.]$
        answer "{{ .Name }} 5 IN A %s"
    }
'''
    return (block+view+template%EXPECTED["127.0.0.1"]+"}\n"
            +block+template%EXPECTED["127.0.0.2"]+"}\n")


def run():
    service=subprocess.run(["systemctl","show","-P","MainPID","mnebydns-dot.service"],
                           capture_output=True,text=True,timeout=5,check=True)
    pid=int(service.stdout.strip())
    if pid<=0:raise RuntimeError("real CoreDNS service not running")
    binary="/proc/"+str(pid)+"/exe"
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1",PORT))
    with tempfile.TemporaryDirectory(prefix="mneby-v28-dot-view-") as directory:
        d=Path(directory)
        cert=d/"cert.pem";key=d/"key.pem";config=d/"Corefile"
        subprocess.run(["openssl","req","-x509","-newkey","rsa:2048",
                        "-nodes","-days","1","-subj","/CN=localhost",
                        "-addext","subjectAltName=DNS:localhost",
                        "-keyout",str(key),"-out",str(cert)],
                       check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
        config.write_text(corefile(cert,key),encoding="utf-8")
        config.chmod(0o600)
        child=subprocess.Popen([binary,"-conf",str(config)],cwd=directory,
                               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            end=time.monotonic()+7
            while time.monotonic()<end:
                if child.poll() is not None:
                    raise RuntimeError("isolated TLS CoreDNS view server failed to start")
                try:
                    selected=answer("127.0.0.1",cert)
                    default=answer("127.0.0.2",cert)
                    break
                except (OSError,ssl.SSLError,AssertionError):
                    time.sleep(.1)
            else:raise RuntimeError("isolate DoT CoreDNS view not answering")
            if selected!=EXPECTED["127.0.0.1"] or default!=EXPECTED["127.0.0.2"]:
                raise AssertionError("DoT source client view leaked or failed")
            print("meta_v28_dot_tls_validated=true",flush=True)
            print("meta_v28_dot_selected_source_to_RU188=PASS",flush=True)
            print("meta_v28_dot_unselected_source_to_DE89=PASS",flush=True)
            print("meta_v28_dot_isolated_port_15534=true",flush=True)
        finally:
            child.terminate()
            try:child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill();child.wait(timeout=3)
    print("meta_v28_dot_child_stopped=true",flush=True)
    print("meta_v28_public_port853_config_untouched=true",flush=True)
    print("meta_v28_real_phone_ip_preservation=NOT_TESTED",flush=True)


if __name__=="__main__":
    run()
