#!/usr/bin/env python3
"""Offline/namespace-only TCP443 isolated-namespace capture probe for nftables SYN-ACK Window=4.

Modes: listener, client, verify. All addresses are documentation-only
RFC 5737 addresses, usable only inside test namespaces; no DNS or Internet.
"""
from __future__ import annotations

import argparse
import os
import socket
import ssl
import struct
import time
from pathlib import Path

def checksum(data: bytes) -> int:
    if len(data) % 2: data += b"\x00"
    total=sum(struct.unpack("!%dH" % (len(data)//2), data))
    while total >> 16: total=(total&0xffff)+(total>>16)
    return (~total)&0xffff


SERVER = "192.0.2.1"
CLIENT = "192.0.2.2"
PORT = 443
QUEUE = 211


def listener(ready: str, count: int):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((SERVER, PORT))
        server.listen(12)
        server.settimeout(12)
        Path(ready).write_text("ready\n")
        for _ in range(count):
            conn, address = server.accept()
            if address[0] != CLIENT:
                raise RuntimeError("Namespace listener received a foreign client")
            with conn:
                conn.settimeout(3)
                block = bytearray()
                expected = None
                while len(block) < 16384:
                    chunk = conn.recv(16384 - len(block))
                    if not chunk:
                        break
                    block.extend(chunk)
                    if expected is None and len(block)>=5:
                        expected=5+int.from_bytes(block[3:5],'big')
                    if expected is not None and len(block)>=expected:
                        break
                if expected is None or len(block)<expected or b"i.instagram.com" not in block:
                    raise AssertionError("Expected complete TLS ClientHello with SNI")
                conn.sendall(b"OK")
                print(f"listener_received_tls_clienthello_bytes={len(block)}", flush=True)


def client():
    # Generate a real OpenSSL TLS 1.3 ClientHello without contacting Meta.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    connection = context.wrap_bio(incoming, outgoing, server_hostname="i.instagram.com")
    try:
        connection.do_handshake()
    except ssl.SSLWantReadError:
        pass
    hello = outgoing.read()
    assert len(hello) > 100 and b"i.instagram.com" in hello
    with socket.create_connection((SERVER, PORT), timeout=8) as sock:
        sock.settimeout(8)
        sock.sendall(hello)
        if sock.recv(2)!=b"OK":
            raise RuntimeError("listener did not receive complete ClientHello")
    print(f"client_sent_tls_clienthello_bytes={len(hello)}", flush=True)



def capture(interface: str, dest: str, ready: str):
    """Unbuffered raw Ethernet PCAP, independent of libpcap/tcpdump filters."""
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)) as sock:
        sock.bind((interface, 0))
        sock.settimeout(.2)
        with open(dest, "wb", buffering=0) as out:
            out.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            Path(ready).write_text("ready\n")
            deadline=time.monotonic()+12.0
            seen=0
            while time.monotonic()<deadline:
                try: frame=sock.recv(65535)
                except socket.timeout: continue
                if len(frame)<14 or frame[12:14]!=b"\x08\x00": continue
                timestamp=time.time()
                seconds=int(timestamp)
                microseconds=int((timestamp-seconds)*1000000)
                out.write(struct.pack("<IIII",seconds,microseconds,len(frame),len(frame)))
                out.write(frame)
                seen+=1
            print("netns_raw_capture_ipv4_packets="+str(seen),flush=True)


def pcap_packets(file: str):
    raw = Path(file).read_bytes()
    if len(raw) < 24:
        raise ValueError("No pcap global header")
    magic = raw[:4]
    if magic == bytes.fromhex("d4c3b2a1"):
        endian = "<"
    elif magic == bytes.fromhex("a1b2c3d4"):
        endian = ">"
    else:
        raise ValueError("Expected classic pcap file")
    linktype = struct.unpack_from(endian + "I", raw, 20)[0]
    if linktype != 1:
        raise ValueError(f"Expected Ethernet capture, got linktype {linktype}")
    pos = 24
    while pos + 16 <= len(raw):
        _sec, _usec, length, _origlen = struct.unpack_from(endian + "IIII", raw, pos)
        pos += 16
        frame = raw[pos:pos+length]
        if len(frame) != length:
            raise ValueError("Truncated pcap packet")
        pos += length
        if len(frame) < 54 or frame[12:14] != b"\x08\x00":
            continue
        ipv4 = frame[14:]
        ihl = (ipv4[0] & 15) * 4
        if ipv4[0] >> 4 != 4 or ihl < 20 or len(ipv4) < ihl + 20 or ipv4[9] != 6:
            continue
        total = struct.unpack_from("!H", ipv4, 2)[0]
        if total > len(ipv4):
            raise ValueError("Truncated IPv4 payload")
        tcp = ipv4[ihl:total]
        sport, dport = struct.unpack_from("!HH", tcp, 0)
        hlen = (tcp[12] >> 4) * 4
        if hlen < 20 or len(tcp) < hlen:
            continue
        yield {
            "src": socket.inet_ntoa(ipv4[12:16]),
            "dst": socket.inet_ntoa(ipv4[16:20]),
            "sport": sport, "dport": dport,
            "flags": tcp[13], "window": struct.unpack_from("!H", tcp, 14)[0],
            "payload_size": len(tcp) - hlen,
            "timestamp": _sec + _usec / 1_000_000.0,
            "valid_checksum": checksum(ipv4[12:20] +
                                       struct.pack("!BBH", 0, 6, len(tcp)) + tcp) == 0,
        }


def verify(file: str, mode: str):
    packets = list(pcap_packets(file))
    synacks = [p for p in packets
               if p["src"] == SERVER and p["dst"] == CLIENT
               and p["sport"] == PORT and p["flags"] & 0x12 == 0x12]
    if len(synacks) != 1:
        print("debug_pcap_packet_count="+str(len(packets)),flush=True)
        print("debug_pcap_first_packets="+repr([(p["src"],p["dst"],p["sport"],p["dport"],p["flags"],p["payload_size"]) for p in packets[:15]]),flush=True)
        raise AssertionError(f"Need exactly 1 SYN-ACK, saw {len(synacks)}")
    synack = synacks[0]
    if not synack["valid_checksum"]:
        raise AssertionError("Bad on-wire TCP checksum on SYN-ACK")
    if mode in ("clamped","clamped_acks"):
        if synack["window"] != 4:
            raise AssertionError(f"Expected win 4, got {synack['window']}")
    elif mode == "clamped_no_ws":
        if synack["window"] != 20:
            raise AssertionError(f"Expected win 20, got {synack['window']}")
    elif synack["window"] == 4:
        raise AssertionError("Reference SYN-ACK unexpectedly had win 4")
    payload = [p["payload_size"] for p in packets
               if p["src"] == CLIENT and p["dst"] == SERVER
               and p["dport"] == PORT and p["payload_size"] > 0]
    if not payload:
        raise AssertionError("No client payload in capture")
    if mode in ("clamped","clamped_acks") and payload[0] != 4:
        raise AssertionError(f"Expected first 4-byte TCP data segment; got {payload[0]}")
    if mode == "clamped_no_ws" and payload[0] != 20:
        raise AssertionError(f"Expected first 20-byte TCP data segment; got {payload[0]}")
    acks = [p["window"] for p in packets
            if p["src"] == SERVER and p["dst"] == CLIENT
            and p["sport"] == PORT and p["flags"] & 0x10
            and not p["flags"] & 0x02 and p["payload_size"] == 0]
    timed = [p["timestamp"] for p in packets
             if p["src"] == CLIENT and p["dst"] == SERVER
             and p["dport"] == PORT and p["payload_size"] > 0]
    interval_ms = round((timed[-1] - timed[0]) * 1000, 2) if len(timed) >= 2 else 0
    print(f"mode={mode} synack_window={synack['window']} "
          f"synack_checksum_valid={synack['valid_checksum']} "
          f"client_tcp_data_segments={payload} "
          f"data_span_ms={interval_ms} server_ack_windows={acks[:24]}", flush=True)


    # Reassemble actual isolated TCP segments and test SNI boundary.
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from mnebydns_iglite_sni_observer import Analyzer, parse_pcap
    analyzer=Analyzer(["i.instagram.com"])
    with open(file,"rb") as source:
        parse_pcap(source,analyzer)
    print("netns_actual_sni_split="+str(analyzer.stats["sni_split"]),flush=True)
    print("netns_actual_sni_unsplit="+str(analyzer.stats["sni_unsplit"]),flush=True)
    print("netns_actual_target_hello="+str(analyzer.stats["target_clienthello"]),flush=True)
    if analyzer.stats["target_clienthello"]!=1:
        raise AssertionError("Expected one complete TLS ClientHello for i.instagram.com")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=("listener", "client", "capture", "verify"))
    p.add_argument("--ready")
    p.add_argument("--count", type=int, default=3)
    p.add_argument("--interface")
    p.add_argument("--pcap")
    p.add_argument("--variant", choices=("reference", "clamped", "clamped_acks", "clamped_no_ws", "failbypass"))
    args = p.parse_args()
    if args.mode == "listener":
        if not args.ready:
            p.error("--ready required")
        listener(args.ready, args.count)
    elif args.mode == "client":
        client()
    elif args.mode == "capture":
        if not args.interface or not args.pcap or not args.ready:
            p.error("--interface --pcap --ready required")
        capture(args.interface,args.pcap,args.ready)
    else:
        if not args.pcap or not args.variant:
            p.error("--pcap and --variant required")
        verify(args.pcap, args.variant)


if __name__ == "__main__":
    main()
