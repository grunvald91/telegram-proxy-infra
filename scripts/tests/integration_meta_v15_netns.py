#!/usr/bin/env python3
"""Root-only lab in an isolated network namespace; no VPS/Internet/credentials.

Real Linux TLS client -> veth -> NAT -> WindowProxy -> TLS server. The client
performs an ordinary SSL handshake; it contains no splitting implementation.
Only aggregated PCAP metadata is retained in memory.
"""
from pathlib import Path
import hashlib
import os
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from meta_v15_receive_window import WindowProxy,nft_rules,WINDOW
from mnebydns_iglite_sni_observer import Analyzer,parse_pcap

EDGE="198.18.0.1";PEER="198.18.0.2";CONTROL="198.18.0.3"
HOST="i.instagram.com"
PAYLOAD=b"synthetic-window-release-check\n"*8192


def run(args,**kw):
    return subprocess.run(args,check=True,timeout=30,capture_output=True,**kw)


def client(cert,source,fragmented=False):
    context=ssl.create_default_context(cafile=cert)
    with socket.create_connection((EDGE,443),timeout=20,source_address=(source,0)) as plain:
        if fragmented:
            # Keep OpenSSL's exact handshake bytes/transcript, but frame the
            # initial ClientHello over two valid TLS records. TCP writes are
            # ordinary sendall; only the server forces tiny TCP segments.
            incoming=ssl.MemoryBIO();outgoing=ssl.MemoryBIO()
            tls=context.wrap_bio(incoming,outgoing,server_side=False,server_hostname=HOST)
            first=True
            def flush():
                nonlocal first
                data=outgoing.read()
                if not data:return
                if first:
                    first=False
                    size=int.from_bytes(data[3:5],"big")
                    payload=data[5:5+size];cut=30
                    data=(data[:3]+cut.to_bytes(2,"big")+payload[:cut]+
                          data[:3]+(size-cut).to_bytes(2,"big")+payload[cut:]+data[5+size:])
                plain.sendall(data)
            while True:
                try:tls.do_handshake()
                except ssl.SSLWantReadError:
                    flush()
                    data=plain.recv(65536)
                    if not data:raise AssertionError("fragmented TLS handshake EOF")
                    incoming.write(data)
                else:
                    flush();break
            assert tls.getpeercert()
            tls.write(PAYLOAD);flush();result=b""
            while len(result)<32:
                try:
                    piece=tls.read(32-len(result))
                    if not piece:raise AssertionError("fragmented TLS clean EOF")
                    result+=piece
                except ssl.SSLWantReadError:
                    flush();data=plain.recv(65536)
                    if not data:raise AssertionError("fragmented TLS response EOF")
                    incoming.write(data)
            assert result==hashlib.sha256(PAYLOAD).digest()
            return
        with context.wrap_socket(plain,server_hostname=HOST) as tls:
            if not tls.getpeercert():raise AssertionError("certificate verification missing")
            tls.sendall(PAYLOAD)
            result=b""
            while len(result)<32:
                piece=tls.recv(32-len(result))
                if not piece:raise AssertionError("TLS echo truncated")
                result+=piece
            assert result==hashlib.sha256(PAYLOAD).digest()


class LabAnalyzer(Analyzer):
    def __init__(self):
        super().__init__([HOST])
        self.small=0;self.large=0;self.synack_scales=[];self.windows=[]
        self.control_windows=[]
        self.control_synack_windows=[]

    def ethernet(self,frame,timestamp=None):
        if len(frame)<54 or frame[12:14]!=b"\x08\x00":return
        at=14;ihl=(frame[at]&15)*4;tcp=at+ihl
        if frame[at+9]!=6 or len(frame)<tcp+20:return
        source=socket.inet_ntoa(frame[at+12:at+16])
        dest=socket.inet_ntoa(frame[at+16:at+20])
        sport,dport=struct.unpack_from("!HH",frame,tcp)
        flags=frame[tcp+13];head=(frame[tcp+12]>>4)*4
        size=int.from_bytes(frame[at+2:at+4],"big")-ihl-head
        if source==PEER and dport==443:
            if size>0:
                if size<=WINDOW:self.small+=1
                else:self.large+=1
            super().ethernet(frame,timestamp)
        if source==EDGE and sport==443:
            window=int.from_bytes(frame[tcp+14:tcp+16],"big")
            if dest==CONTROL:
                self.control_windows.append(window)
                if flags&0x12==0x12:self.control_synack_windows.append(window)
            if dest!=PEER:return
            self.windows.append(window)
            if flags&0x12==0x12:
                options=frame[tcp+20:tcp+head];pos=0;scale=None
                while pos<len(options):
                    kind=options[pos]
                    if kind==0:break
                    if kind==1:pos+=1;continue
                    if pos+2>len(options):raise ValueError("bad option")
                    length=options[pos+1]
                    if length<2 or pos+length>len(options):raise ValueError("bad length")
                    if kind==3 and length==3:scale=options[pos+2]
                    pos+=length
                self.synack_scales.append(scale)


def inner():
    if os.geteuid()!=0:raise RuntimeError("isolated root lab required")
    namespace="mnebycli"+str(os.getpid())
    capture=None;proxy=None;listener=None;thread=None;capture_thread=None
    capture_errors=[];server_errors=[]
    run(["ip","link","set","lo","up"])
    run(["ip","netns","add",namespace])
    try:
        run(["ip","link","add","v15srv","type","veth","peer","name","v15cli"])
        # EDGE is deliberately secondary. A plain REDIRECT would choose the
        # primary interface address and miss the EDGE-bound proxy listener.
        run(["ip","addr","add","198.18.0.4/29","dev","v15srv"])
        run(["ip","addr","add",EDGE+"/29","dev","v15srv"])
        run(["ip","link","set","v15srv","up"])
        run(["ip","link","set","v15cli","netns",namespace])
        for addr in (PEER,CONTROL):
            run(["ip","-n",namespace,"addr","add",addr+"/29","dev","v15cli"])
        run(["ip","-n",namespace,"link","set","v15cli","up"])
        run(["ip","-n",namespace,"link","set","lo","up"])
        run(["ethtool","-K","v15srv","gro","off","gso","off","tso","off"])
        run(["ip","netns","exec",namespace,"ethtool","-K","v15cli",
             "gro","off","gso","off","tso","off"])
        global_scaling=Path("/proc/sys/net/ipv4/tcp_window_scaling").read_bytes()
        with tempfile.TemporaryDirectory(prefix="meta-v15-lab-") as td:
            cert=str(Path(td)/"cert.pem");key=str(Path(td)/"key.pem")
            run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","1",
                 "-subj","/CN="+HOST,"-addext","subjectAltName=DNS:"+HOST,
                 "-keyout",key,"-out",cert])
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
            listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            listener.bind(("0.0.0.0",443));listener.listen(4);listener.settimeout(30)
            def server():
                try:
                    for _ in range(3):
                        plain,_=listener.accept();plain.settimeout(20)
                        with context.wrap_socket(plain,server_side=True) as tls:
                            digest=hashlib.sha256();count=0
                            while count<len(PAYLOAD):
                                chunk=tls.recv(min(65536,len(PAYLOAD)-count))
                                if not chunk:raise AssertionError("missing client bytes")
                                digest.update(chunk);count+=len(chunk)
                            assert digest.digest()==hashlib.sha256(PAYLOAD).digest()
                            tls.sendall(digest.digest())
                except BaseException as exc:server_errors.append(type(exc).__name__+":"+str(exc))
            thread=threading.Thread(target=server,daemon=True);thread.start()
            proxy=WindowProxy(EDGE,PEER);proxy.start()
            rules=nft_rules(EDGE,PEER,interface="v15srv")
            run(["nft","--check","-f","-"],input=rules.encode())
            run(["nft","-f","-"],input=rules.encode())
            # Mimic the existing mark exemption after reverse NAT. This
            # counter MUST remain zero for the dedicated proxy's replies.
            audit=("add table inet v15audit\n"
                "add chain inet v15audit post { type filter hook postrouting priority 101; policy accept; }\n"
                f"add rule inet v15audit post ip saddr {EDGE} ip daddr {PEER} "
                "tcp sport 443 meta mark & 0x40000000 == 0 counter\n")
            run(["nft","-f","-"],input=audit.encode())
            analyzer=LabAnalyzer();ready=threading.Event()
            capture=subprocess.Popen(["tcpdump","-i","v15srv","-n","-U","-s","1500",
                "-w","-","tcp port 443"],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
            def consume():
                try:parse_pcap(capture.stdout,analyzer,ready)
                except BaseException as exc:capture_errors.append(type(exc).__name__)
            capture_thread=threading.Thread(target=consume,daemon=True);capture_thread.start()
            if not ready.wait(5) or capture.poll() is not None:
                raise AssertionError("capture not ready")
            for source in (CONTROL,PEER):
                run(["ip","netns","exec",namespace,sys.executable,str(Path(__file__).resolve()),
                     "client",cert,source])
            run(["ip","netns","exec",namespace,sys.executable,str(Path(__file__).resolve()),
                 "client",cert,PEER,"fragmented"])
            thread.join(timeout=5)
            if thread.is_alive() or server_errors:raise AssertionError(server_errors)
            time.sleep(.2)
            capture.send_signal(signal.SIGINT);capture_thread.join(timeout=5)
            assert capture.wait(timeout=3)==0
            assert not capture_errors and not capture_thread.is_alive(),capture_errors
            assert analyzer.stats["target_clienthello"]==2,dict(analyzer.stats)
            assert analyzer.stats["sni_split"]==2,dict(analyzer.stats)
            assert analyzer.stats["sni_boundary_indeterminate"]==0,dict(analyzer.stats)
            assert analyzer.small>=2 and analyzer.large>=1
            assert analyzer.synack_scales and set(analyzer.synack_scales)=={0}
            assert WINDOW in analyzer.windows and max(analyzer.windows)>WINDOW
            # Native flow control and RST/teardown can legitimately contain
            # window zero. Compare the initial control handshake, which is
            # the point where the experimental tiny window is negotiated.
            assert analyzer.control_synack_windows and min(analyzer.control_synack_windows)>WINDOW
            import json
            audit=json.loads(run(["nft","-j","list","table","inet","v15audit"]).stdout)
            counters=[e["counter"]["packets"] for item in audit["nftables"]
                      for e in item.get("rule",{}).get("expr",[]) if "counter" in e]
            assert counters==[0],counters
            assert proxy.stats["failed"]==0,dict(proxy.stats)
            assert proxy.stats["window_released"]==2,dict(proxy.stats)
            assert proxy.stats["target_sni"]==2,dict(proxy.stats)
            assert Path("/proc/sys/net/ipv4/tcp_window_scaling").read_bytes()==global_scaling
            print("meta_v15_lab_real_tls_verified=true")
            print("meta_v15_lab_sni_split="+str(analyzer.stats["sni_split"]))
            print("meta_v15_lab_small_segments="+str(analyzer.small))
            print("meta_v15_lab_post_release_large_segments="+str(analyzer.large))
            print("meta_v15_lab_receive_scale_zero=true")
            print("meta_v15_lab_nonpeer_window_unchanged=true")
            print("meta_v15_lab_control_native_zero_packets="+str(analyzer.control_windows.count(0)))
            print("meta_v15_lab_queue210_exemption_mark_verified=true")
            print("meta_v15_lab_global_scaling_unchanged=true")
            print("meta_v15_lab_secondary_edge_ip_verified=true")
            print("meta_v15_lab_tls_record_fragmentation_verified=true")
            print("meta_v15_lab_android_tspu=NOT_TESTED")
    finally:
        if capture is not None:
            if capture.poll() is None:capture.kill()
            capture.wait(timeout=3)
            if capture_thread is not None:capture_thread.join(timeout=3)
            capture.stdout.close()
        if proxy is not None:proxy.close()
        if listener is not None:listener.close()
        run(["ip","netns","delete",namespace])


if __name__=="__main__":
    if sys.argv[1:2]==["client"]:client(sys.argv[2],sys.argv[3],len(sys.argv)>4)
    elif sys.argv[1:]==["--inner"]:inner()
    else:
        # A fresh server network namespace prevents all host firewall changes.
        subprocess.run(["unshare","--net","--mount-proc",sys.executable,
                        str(Path(__file__).resolve()),"--inner"],check=True,timeout=90)
