#!/usr/bin/env python3
"""Experimental receiver-driven ClientHello segmentation, Linux IPv4 only.

No TLS termination and no payload rewriting. A dedicated listening socket
negotiates receive scale=0. Peer-scoped nft rules advertise an 8-byte receive
window until a complete SNI is read; SO_MARK then releases the tiny window.
This MUST be measured on the client-facing interface, not inferred from recv().
"""
from __future__ import annotations

import argparse
from collections import Counter
import ipaddress
import re
import select
import signal
import socket
import struct
import threading
import time

from mnebydns_iglite_sni_observer import LIMIT, locate_partial_sni, clienthello_view

BYPASS = 0x40000000
RELEASED = 0x20000000
WINDOW = 8
CLAMP = 65535
MAX_CLIENTS = 64
MAX_LIFETIME = 1500
SO_ORIGINAL_DST = 80
HOSTS = frozenset(("iglite-z.instagram.com", "i.instagram.com",
    "i-fallback.instagram.com", "test-gateway.instagram.com",
    "graph.instagram.com", "z-m-gateway.facebook.com", "graph.facebook.com",
    "www.instagram.com", "www.facebook.com", "static.xx.fbcdn.net",
    "scontent.xx.fbcdn.net"))


def ipv4(value):
    return str(ipaddress.IPv4Address(value))


def nft_rules(edge, peer, *, port=18443, interface="eth0", table="mneby_meta_v15"):
    edge=ipv4(edge)
    shared=peer=="all"
    if shared and (edge!="188.120.254.223" or interface!="ens3"):
        raise ValueError("shared ingress is supported only on reviewed RU ens3")
    peer=None if shared else ipv4(peer)
    source="" if shared else f"ip saddr {peer} "
    destination="" if shared else f"ip daddr {peer} "
    if edge == peer or not 1024 < port < 65536 or port == 443:
        raise ValueError("invalid canary endpoint")
    if not re.fullmatch(r"[a-zA-Z0-9_]{1,40}", table):
        raise ValueError("invalid table")
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", interface):
        raise ValueError("invalid interface")
    # IMPORTANT: the RU telegram_nfqws OUTPUT/predefrag rule applies notrack to
    # packets marked BYPASS.  A mark inherited from the TCP listener therefore
    # prevents conntrack from reversing 443 -> 18443 DNAT for SYN-ACK replies.
    # Only mark these reply packets at postrouting priority 100: after conntrack
    # has already run, but before telegram_nfqws NFQUEUE at priority 101.
    ct_source="" if shared else f"ct original ip saddr {peer} "
    return (f"add table inet {table}\n"
        f"add chain inet {table} pre {{ type nat hook prerouting priority -101; policy accept; }}\n"
        f'add rule inet {table} pre iifname "{interface}" {source}ip daddr {edge} '
        f'tcp dport 443 counter dnat ip to {edge}:{port}\n'
        f"add chain inet {table} out {{ type filter hook output priority -149; policy accept; }}\n"
        f"add rule inet {table} out ip saddr {edge} {destination}tcp sport {port} "
        f"meta mark & {RELEASED:#x} == 0 tcp flags & ack == ack tcp window > {WINDOW} "
        f"counter tcp window set {WINDOW}\n"
        f"add chain inet {table} post {{ type filter hook postrouting priority 100; policy accept; }}\n"
        f'add rule inet {table} post oifname "{interface}" ip saddr {edge} {destination}'
        f'ct direction reply ct status dnat {ct_source}ct original ip daddr {edge} '
        f'ct original proto-dst 443 ct reply proto-src {port} '
        f'counter meta mark set meta mark | {BYPASS:#x}\n')


def verify_queue_exemption(ruleset):
    """Prove the archived queue210 exclusion expression exactly, not by substring."""
    targets = []
    for item in ruleset.get("nftables", []):
        rule = item.get("rule", {})
        if any(e.get("queue", {}).get("num") == 210 for e in rule.get("expr", [])):
            targets.append(rule)
    if len(targets) != 1:
        raise ValueError("unique queue210 rule required")
    match = {"op": "==", "left": {"&": [{"meta": {"key": "mark"}}, BYPASS]}, "right": 0}
    expressions=targets[0]["expr"]
    queue_index=next(i for i,e in enumerate(expressions) if e.get("queue",{}).get("num")==210)
    if not any(e.get("match") == match for e in expressions[:queue_index]):
        raise ValueError("queue210 bypass-bit equality not verified")
    return True


def receive_scale(conn):
    info = conn.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 256)
    if len(info) < 7:
        raise RuntimeError("TCP_INFO scale unavailable")
    # Linux uapi tcp_info uses __u8 snd_wscale:4, rcv_wscale:4 on little endian.
    import sys
    if sys.byteorder != "little":
        raise RuntimeError("TCP_INFO bitfield unsupported on this architecture")
    return info[6] >> 4


def original_destination(conn):
    data = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    return socket.inet_ntoa(data[4:8]), struct.unpack("!H", data[2:4])[0]


def read_prefix(conn, *, timeout=12):
    deadline = time.monotonic() + timeout
    data = bytearray()
    while len(data) < LIMIT:
        conn.settimeout(max(.001, deadline-time.monotonic()))
        if time.monotonic() >= deadline:
            raise TimeoutError("ClientHello prefix deadline")
        part = conn.recv(min(4096, LIMIT-len(data)))
        if not part:
            raise ConnectionError("EOF before ClientHello prefix")
        data.extend(part)
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
        if len(data) < 5:
            continue
        if data[0] != 22 or data[1] != 3:
            return bytes(data), None
        _,complete,_=clienthello_view(data)
        host = locate_partial_sni(data)
        if host is not None:
            return bytes(data), host
        if complete:
            # Non-target/unsupported TLS is passed through with normal window.
            return bytes(data), None
    raise ValueError("ClientHello prefix limit")


def relay(left, right, stop, *, idle=60):
    """Bounded buffers, partial-write handling, and bidirectional half-close."""
    peers={left:right,right:left}
    pending={left:bytearray(),right:bytearray()}
    eof=set();closed_write=set()
    for sock in peers:sock.setblocking(False)
    activity=time.monotonic()
    while not stop.is_set() and time.monotonic()-activity < idle:
        for source,destination in peers.items():
            if source in eof and not pending[destination] and destination not in closed_write:
                destination.shutdown(socket.SHUT_WR)
                closed_write.add(destination)
        if len(eof)==2 and not any(pending.values()):return
        readers=[s for s in peers if s not in eof and len(pending[peers[s]])<65536]
        writers=[s for s in peers if pending[s]]
        ready_read,ready_write,_=select.select(readers,writers,[],.25)
        for source in ready_read:
            destination=peers[source]
            try:chunk=source.recv(65536-len(pending[destination]))
            except BlockingIOError:continue
            if chunk:
                pending[destination].extend(chunk)
                activity=time.monotonic()
            else:eof.add(source)
        for destination in ready_write:
            try:sent=destination.send(pending[destination])
            except BlockingIOError:continue
            if sent==0:raise ConnectionError("relay write EOF")
            del pending[destination][:sent]
            activity=time.monotonic()


class WindowProxy:
    def __init__(self, edge, peer, *, port=18443, backend=("127.0.0.1",443),
                 non_meta_backend=None):
        self.edge=ipv4(edge)
        self.peer=None if peer=="all" else ipv4(peer)
        if self.peer is None and non_meta_backend is None:
            raise ValueError("shared receiver requires the reviewed RU fallback")
        self.port, self.backend = port, backend
        self.non_meta_backend = non_meta_backend
        if non_meta_backend is not None and (
                self.edge != "188.120.254.223" or
                backend != ("10.66.77.1", 443) or
                non_meta_backend != ("188.120.254.223", 443)):
            raise ValueError("RU non-Meta fallback must use existing public RU443 service")
        self.stop = threading.Event()
        self.stats = Counter()
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(MAX_CLIENTS)
        self.sockets = set()
        self.listener = None
        self.thread = None

    def count(self, key):
        with self.lock:
            self.stats[key] += 1

    def destination_for(self, host):
        """Only allowlisted Meta hostnames leave RU over the private tunnel."""
        if self.non_meta_backend is not None and host not in HOSTS:
            return self.non_meta_backend
        return self.backend

    def start(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            listener.setsockopt(socket.IPPROTO_TCP,socket.TCP_WINDOW_CLAMP,CLAMP)
            # Do not mark the listener: BYPASS on SYN-ACK would trigger the
            # existing OUTPUT notrack rule before reverse DNAT can take place.
            # The peer-scoped postrouting rule marks replies only after conntrack.
            listener.bind((self.edge,self.port))
            listener.listen(64)
            listener.settimeout(.25)
        except BaseException:
            listener.close()
            raise
        self.listener = listener
        self.thread = threading.Thread(target=self.accept,daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stop.is_set():
            try:
                conn, address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if not self.stop.is_set():
                    self.count("accept_failed")
                    self.stop.set()
                break
            if (self.peer is not None and address[0]!=self.peer) or not self.slots.acquire(blocking=False):
                conn.close()
                continue
            with self.lock:
                if self.stop.is_set():
                    conn.close()
                    self.slots.release()
                    continue
                self.sockets.add(conn)
            try:threading.Thread(target=self.handle,args=(conn,),daemon=True).start()
            except RuntimeError:
                conn.close()
                with self.lock:self.sockets.discard(conn)
                self.slots.release()
                self.count("accept_failed")
                self.stop.set()

    def handle(self, conn):
        backend = None
        try:
            if original_destination(conn) != (self.edge,443):
                raise ValueError("direct listener access forbidden")
            if receive_scale(conn) != 0:
                raise RuntimeError("receive scale must be zero")
            self.count("scale_zero")
            prefix, host = read_prefix(conn)
            self.count("target_sni" if host in HOSTS else "other_protocol")
            # Linux still believes its original advertised window. Because
            # scale zero was negotiated by the kernel itself, restoring the
            # unmodified window needs no translation or changed TCP options.
            # RELEASED alone prevents the small-window clamp without
            # triggering the unrelated pre-conntrack BYPASS/notrack rule.
            conn.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,RELEASED)
            conn.setsockopt(socket.IPPROTO_TCP,socket.TCP_QUICKACK,1)
            self.count("window_released")
            # The RU shared :443 ingress also handles non-Meta connections.
            # These must stay on RU's existing HTTPS service, not leak into
            # the fixed private Meta WireGuard origin router.
            destination = self.destination_for(host)
            if self.non_meta_backend is not None:
                self.count("meta_via_wg" if host in HOSTS else "non_meta_via_ru")
            backend = socket.create_connection(destination,timeout=5)
            with self.lock:
                if self.stop.is_set():raise ConnectionError("proxy stopping")
                self.sockets.add(backend)
            backend.sendall(prefix)
            relay(conn,backend,self.stop)
        except (OSError,ValueError,RuntimeError):
            self.count("failed")
        finally:
            for sock in (conn,backend):
                if sock is not None:
                    try:sock.close()
                    except OSError:pass
                    with self.lock:self.sockets.discard(sock)
            self.slots.release()

    def close(self):
        self.stop.set()
        if self.listener is not None:
            self.listener.close()
        if self.thread is not None:
            self.thread.join(timeout=2)
        with self.lock:
            sockets = list(self.sockets)
        for conn in sockets:
            try:conn.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            conn.close()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--edge",default="89.125.90.101")
    parser.add_argument("--peer",required=True)
    parser.add_argument("--port",type=int,default=18443)
    parser.add_argument("--max-lifetime",type=int,choices=(1500,2700),default=1500)
    parser.add_argument("--backend-address",choices=("127.0.0.1","10.66.77.1"),default="127.0.0.1")
    parser.add_argument("--non-meta-backend-address",choices=("188.120.254.223",))
    parser.add_argument("--evidence-file")
    args=parser.parse_args()
    if args.peer!="all" and (not ipaddress.IPv4Address(args.peer).is_global or args.peer==args.edge):
        raise SystemExit("distinct public test-phone IPv4 required")
    # Only local Nginx or the fixed private WireGuard peer may receive raw TLS.
    # Never derive a backend from untrusted SNI or arbitrary client input.
    fallback = ((args.non_meta_backend_address,443)
                if args.non_meta_backend_address else None)
    proxy=WindowProxy(args.edge,args.peer,port=args.port,
                      backend=(args.backend_address,443),
                      non_meta_backend=fallback)
    def stop(signum, frame):proxy.stop.set()
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,stop)
    evidence=None
    try:
        if args.evidence_file:
            if (args.edge!="188.120.254.223" or
                    args.evidence_file!="/var/lib/mneby-meta-v26-ru/evidence.json"):
                raise ValueError("packet evidence must use the owned RU state")
            from meta_v31_sni_evidence import CaptureEvidence
            evidence=CaptureEvidence(args.peer,args.evidence_file)
            evidence.start()
        proxy.start()
        print("meta_v15_listener_ready=true",flush=True)
        until=time.monotonic()+args.max_lifetime
        while not proxy.stop.wait(min(2,max(0,until-time.monotonic()))):
            if evidence is not None:
                if not evidence.healthy():raise RuntimeError("RU ingress capture failed")
                with proxy.lock:stats=dict(proxy.stats)
                evidence.publish(stats)
            if time.monotonic()>=until:break
        if proxy.stats["accept_failed"]:
            raise RuntimeError("proxy accept loop failed")
    finally:
        proxy.close()
        if evidence is not None:
            evidence.stop()
            evidence.publish(proxy.stats)
        for key,value in sorted(proxy.stats.items()):
            print("meta_v15_proxy_"+key+"="+str(value),flush=True)


if __name__=="__main__":main()
