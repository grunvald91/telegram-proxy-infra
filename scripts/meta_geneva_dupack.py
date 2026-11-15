#!/usr/bin/env python3
"""Pure-stdlib Geneva server-side duplicate-ACK (bad TCP checksum) injector.

Listens on an isolated NFQUEUE (default 211) for server-side SYN+ACK replies,
immediately accepts the genuine SYN+ACK, and transmits duplicate ACK packet(s)
with a valid IPv4 header and intentionally corrupted TCP checksum via a raw
socket marked BYPASS (notrack + excluded from NFQUEUE 210/211).
"""
from __future__ import annotations

import ipaddress
import os
import re
import select
import socket
import struct
import threading

BYPASS = 0x40000000
GENEVA_QUEUE = 211
SUPPORTED_EXPERIMENT_MODES = ("window", "geneva")
SUPPORTED_GENEVA_VARIANTS = ("ack-exact", "ack-desync")
SUPPORTED_GENEVA_REPEATS = (1, 2, 3)
DEFAULT_GENEVA_VARIANT = "ack-exact"
DEFAULT_GENEVA_REPEATS = 2

# Linux netlink / nfnetlink_queue constants (<linux/netfilter/nfnetlink_queue.h>)
NETLINK_NETFILTER = 12
NLMSG_ERROR = 2
NLM_F_REQUEST = 1
NLM_F_ACK = 4

NFNL_SUBSYS_QUEUE = 3
NFQNL_MSG_PACKET = 0
NFQNL_MSG_VERDICT = 1
NFQNL_MSG_CONFIG = 2

NFQA_PACKET_HDR = 1
NFQA_VERDICT_HDR = 2
NFQA_PAYLOAD = 10

NFQNL_CFG_CMD_BIND = 1
NFQNL_CFG_CMD_UNBIND = 2
NFQA_CFG_CMD = 1
NFQA_CFG_PARAMS = 2
NFQA_CFG_FLAGS = 5
NFQA_CFG_MASK = 4
NFQA_CFG_F_FAIL_OPEN = 1 << 0
NFQNL_COPY_PACKET = 2

NF_ACCEPT = 1
SO_MARK = getattr(socket, "SO_MARK", 36)


def ipv4(value: str) -> str:
    return str(ipaddress.IPv4Address(value))


def _ones_complement_raw(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total & 0xFFFF


def _ones_complement_sum(data: bytes) -> int:
    return (~_ones_complement_raw(data)) & 0xFFFF


def ipv4_checksum(header: bytes) -> int:
    """Return 16-bit IPv4 header checksum (0 when verifying a valid header)."""
    return _ones_complement_sum(header)


def tcp_pseudo_sum(src_ip: bytes, dst_ip: bytes, tcp_len: int) -> int:
    """Return raw 16-bit pseudo-header sum (used by Linux CHECKSUM_PARTIAL TX offload)."""
    if len(src_ip) != 4 or len(dst_ip) != 4:
        raise ValueError("IPv4 addresses must be 4 bytes")
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, socket.IPPROTO_TCP, tcp_len)
    return _ones_complement_raw(pseudo)


def tcp_checksum(src_ip: bytes, dst_ip: bytes, tcp_segment: bytes) -> int:
    """Compute RFC 793 TCP checksum over IPv4 pseudo-header and TCP segment."""
    if len(src_ip) != 4 or len(dst_ip) != 4:
        raise ValueError("IPv4 addresses must be 4 bytes")
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp_segment))
    return _ones_complement_sum(pseudo + tcp_segment)


def verify_ipv4_tcp_checksum(ip_packet: bytes) -> tuple[bool, int, int]:
    """Verify TCP checksum of an IPv4/TCP packet; returns (valid, wire, expected)."""
    if len(ip_packet) < 40 or (ip_packet[0] >> 4) != 4:
        raise ValueError("expected IPv4 TCP packet")
    ihl = (ip_packet[0] & 0x0F) * 4
    total_len = int.from_bytes(ip_packet[2:4], "big")
    if ihl < 20 or total_len < ihl + 20 or total_len > len(ip_packet) or ip_packet[9] != socket.IPPROTO_TCP:
        raise ValueError("invalid IPv4 TCP packet bounds or protocol")
    tcp_seg = ip_packet[ihl:total_len]
    wire_sum = int.from_bytes(tcp_seg[16:18], "big")
    zeroed = tcp_seg[:16] + b"\x00\x00" + tcp_seg[18:]
    expected = tcp_checksum(ip_packet[12:16], ip_packet[16:20], zeroed)
    return wire_sum == expected, wire_sum, expected


def build_geneva_dupack(
    synack_ip_packet: bytes,
    *,
    variant: str = DEFAULT_GENEVA_VARIANT,
    public_sport: int | None = None,
) -> bytes:
    """Craft a duplicate ACK with valid IPv4 header and corrupted TCP checksum."""
    if variant not in SUPPORTED_GENEVA_VARIANTS:
        raise ValueError(f"unsupported Geneva variant: {variant!r}")
    if public_sport is not None and not 1 <= public_sport <= 65535:
        raise ValueError("invalid public_sport")
    if len(synack_ip_packet) < 40 or (synack_ip_packet[0] >> 4) != 4:
        raise ValueError("expected IPv4 TCP SYN+ACK packet")
    ihl = (synack_ip_packet[0] & 0x0F) * 4
    total_len = int.from_bytes(synack_ip_packet[2:4], "big")
    if ihl < 20 or total_len < ihl + 20 or total_len > len(synack_ip_packet):
        raise ValueError("truncated IPv4 TCP packet")
    if synack_ip_packet[9] != socket.IPPROTO_TCP:
        raise ValueError("expected TCP packet")

    src_ip = synack_ip_packet[12:16]
    dst_ip = synack_ip_packet[16:20]
    ip_id = int.from_bytes(synack_ip_packet[4:6], "big")
    ttl = synack_ip_packet[8] or 64

    tcp_off = ihl
    sport, dport, seq_s0, ack_c1, doff_byte, flags, window = struct.unpack_from(
        "!HHIIBBH", synack_ip_packet, tcp_off
    )
    if public_sport is not None:
        sport = public_sport
    tcp_hdr_len = (doff_byte >> 4) * 4
    if tcp_hdr_len < 20 or tcp_off + tcp_hdr_len > total_len:
        raise ValueError("invalid TCP header length")
    if (flags & 0x12) != 0x12:
        raise ValueError("expected TCP SYN+ACK flags")

    if variant == "ack-exact":
        dup_seq = (seq_s0 + 1) & 0xFFFFFFFF
        dup_ack = ack_c1 & 0xFFFFFFFF
    else:  # ack-desync
        dup_seq = (seq_s0 + 1 + 1000) & 0xFFFFFFFF
        dup_ack = (ack_c1 + 1460) & 0xFFFFFFFF

    tcp_wo_sum = struct.pack(
        "!HHIIBBHHH",
        sport,
        dport,
        dup_seq,
        dup_ack,
        0x50,  # 20-byte TCP header
        0x10,  # ACK only
        window,
        0,
        0,
    )
    valid_tcp_sum = tcp_checksum(src_ip, dst_ip, tcp_wo_sum)
    bad_tcp_sum = valid_tcp_sum ^ 0xFFFF
    tcp_seg = tcp_wo_sum[:16] + struct.pack("!H", bad_tcp_sum) + tcp_wo_sum[18:]

    new_total_len = 20 + len(tcp_seg)
    new_ip_id = (ip_id + 1) & 0xFFFF
    ip_wo_sum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        new_total_len,
        new_ip_id,
        0x4000,  # DF
        ttl,
        socket.IPPROTO_TCP,
        0,
        src_ip,
        dst_ip,
    )
    ip_sum = ipv4_checksum(ip_wo_sum)
    ip_hdr = ip_wo_sum[:10] + struct.pack("!H", ip_sum) + ip_wo_sum[12:]
    return ip_hdr + tcp_seg


def _pad4(n: int) -> int:
    return (n + 3) & ~3


def encode_nlattr(attr_type: int, payload: bytes) -> bytes:
    nla_len = 4 + len(payload)
    padded = _pad4(nla_len)
    return struct.pack("<HH", nla_len, attr_type) + payload + b"\x00" * (padded - nla_len)


def parse_nlattrs(buf: bytes) -> dict[int, bytes]:
    attrs: dict[int, bytes] = {}
    pos = 0
    while pos + 4 <= len(buf):
        nla_len, nla_type = struct.unpack_from("<HH", buf, pos)
        if nla_len < 4 or pos + nla_len > len(buf):
            break
        attrs[nla_type & 0x3FFF] = buf[pos + 4 : pos + nla_len]
        pos += _pad4(nla_len)
    return attrs


def build_config_msg(
    *,
    queue_num: int,
    command: int | None = None,
    copy_mode: int | None = None,
    copy_range: int = 1600,
    flags: int | None = None,
    mask: int | None = None,
    seq: int = 1,
) -> bytes:
    nfgen = struct.pack("!BBH", socket.AF_UNSPEC, 0, queue_num)
    attrs = bytearray()
    if command is not None:
        attrs.extend(encode_nlattr(NFQA_CFG_CMD, struct.pack("!BBH", command, 0, 0)))
    if copy_mode is not None:
        attrs.extend(encode_nlattr(NFQA_CFG_PARAMS, struct.pack("!IB", copy_range, copy_mode)))
    if flags is not None and mask is not None:
        attrs.extend(encode_nlattr(NFQA_CFG_FLAGS, struct.pack("!I", flags)))
        attrs.extend(encode_nlattr(NFQA_CFG_MASK, struct.pack("!I", mask)))
    nl_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG
    total_len = 16 + len(nfgen) + len(attrs)
    hdr = struct.pack("<IHHII", total_len, nl_type, NLM_F_REQUEST | NLM_F_ACK, seq, 0)
    return hdr + nfgen + bytes(attrs)


def build_verdict_msg(*, queue_num: int, packet_id: int, verdict: int = NF_ACCEPT, seq: int = 0) -> bytes:
    nfgen = struct.pack("!BBH", socket.AF_INET, 0, queue_num)
    attr = encode_nlattr(NFQA_VERDICT_HDR, struct.pack("!II", verdict, packet_id))
    nl_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT
    total_len = 16 + len(nfgen) + len(attr)
    hdr = struct.pack("<IHHII", total_len, nl_type, NLM_F_REQUEST, seq, 0)
    return hdr + nfgen + attr


def parse_nfq_packet(msg: bytes) -> tuple[int, bytes] | None:
    """Extract (packet_id, ip_payload) from an NFQNL_MSG_PACKET netlink message."""
    if len(msg) < 20:
        return None
    nl_len, nl_type, _flags, _seq, _pid = struct.unpack_from("<IHHII", msg, 0)
    if nl_len > len(msg) or nl_type != ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET):
        return None
    attrs = parse_nlattrs(msg[20:nl_len])
    hdr = attrs.get(NFQA_PACKET_HDR)
    payload = attrs.get(NFQA_PAYLOAD)
    if not hdr or len(hdr) < 7 or not payload:
        return None
    packet_id, _hw_proto, _hook = struct.unpack_from("!IHB", hdr, 0)
    return packet_id, payload


def nft_geneva_rules(
    edge: str,
    peer: str,
    *,
    port: int = 18443,
    interface: str = "ens3",
    table: str = "mneby_meta_v26_ru",
    queue_num: int = GENEVA_QUEUE,
) -> str:
    """Build isolated nftables rules for Geneva SYN+ACK NFQUEUE interception."""
    edge = ipv4(edge)
    shared = peer == "all"
    if shared and (edge != "188.120.254.223" or interface != "ens3"):
        raise ValueError("shared ingress is supported only on reviewed RU ens3")
    peer_ip = None if shared else ipv4(peer)
    if edge == peer_ip or not 1024 < port < 65536 or port == 443:
        raise ValueError("invalid canary endpoint")
    if not 1 <= queue_num <= 65535:
        raise ValueError("invalid nfqueue number")
    if not re.fullmatch(r"[a-zA-Z0-9_]{1,40}", table):
        raise ValueError("invalid table")
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", interface):
        raise ValueError("invalid interface")

    source = "" if shared else f"ip saddr {peer_ip} "
    destination = "" if shared else f"ip daddr {peer_ip} "
    ct_source = "" if shared else f"ct original ip saddr {peer_ip} "
    ct_match = (
        f"oifname \"{interface}\" ip saddr {edge} {destination}"
        f"ct direction reply ct status dnat {ct_source}ct original ip daddr {edge} "
        f"ct original proto-dst 443 ct reply proto-src {port}"
    )
    return (
        f"add table inet {table}\n"
        f"add chain inet {table} pre {{ type nat hook prerouting priority -101; policy accept; }}\n"
        f'add rule inet {table} pre iifname "{interface}" {source}ip daddr {edge} '
        f"tcp dport 443 counter dnat ip to {edge}:{port}\n"
        f"add chain inet {table} predefrag {{ type filter hook output priority -401; policy accept; }}\n"
        f"add rule inet {table} predefrag meta mark & {BYPASS:#x} != 0 notrack\n"
        f"add chain inet {table} post {{ type filter hook postrouting priority 100; policy accept; }}\n"
        f"add rule inet {table} post {ct_match} meta mark & {BYPASS:#x} == 0 "
        f"tcp flags & (syn | ack) == (syn | ack) counter queue num {queue_num} bypass\n"
        f"add rule inet {table} post {ct_match} counter meta mark set meta mark | {BYPASS:#x}\n"
    )


class GenevaEgressVerifier:
    """In-memory verifier checking outbound SYN+ACK and bad-checksum ACK on wire."""

    def __init__(self, *, edge: str = "188.120.254.223") -> None:
        self.edge = ipv4(edge)
        self.edge_bytes = socket.inet_aton(self.edge)
        self.lock = threading.Lock()
        self.egress_synack = 0
        self.egress_dupack_badsum = 0
        self.egress_dupack_valid_sum = 0

    def ethernet(self, frame: bytes) -> None:
        if len(frame) < 54 or frame[12:14] != b"\x08\x00":
            return
        ip_pkt = frame[14:]
        if (ip_pkt[0] >> 4) != 4:
            return
        ihl = (ip_pkt[0] & 0x0F) * 4
        if ihl < 20 or len(ip_pkt) < ihl + 20 or ip_pkt[9] != socket.IPPROTO_TCP:
            return
        total_len = int.from_bytes(ip_pkt[2:4], "big")
        if total_len < ihl + 20 or total_len > len(ip_pkt):
            return
        if ip_pkt[12:16] != self.edge_bytes:
            return
        if ipv4_checksum(ip_pkt[:ihl]) != 0:
            return
        sport = int.from_bytes(ip_pkt[ihl : ihl + 2], "big")
        if sport != 443:
            return
        flags = ip_pkt[ihl + 13]
        tcp_hdr_len = (ip_pkt[ihl + 12] >> 4) * 4
        payload_len = total_len - ihl - tcp_hdr_len
        if tcp_hdr_len < 20 or payload_len < 0:
            return
        try:
            csum_ok, wire_sum, expected_sum = verify_ipv4_tcp_checksum(ip_pkt[:total_len])
        except ValueError:
            return
        pseudo_sum = tcp_pseudo_sum(ip_pkt[12:16], ip_pkt[16:20], total_len - ihl)
        with self.lock:
            if (flags & 0x12) == 0x12:
                self.egress_synack += 1
            elif (flags & 0x17) == 0x10 and payload_len == 0:
                if csum_ok or wire_sum == pseudo_sum:
                    self.egress_dupack_valid_sum += 1
                elif wire_sum == (expected_sum ^ 0xFFFF):
                    self.egress_dupack_badsum += 1

    def snapshot(self) -> dict[str, int]:
        with self.lock:
            return {
                "egress_synack": self.egress_synack,
                "egress_dupack_badsum": self.egress_dupack_badsum,
                "egress_dupack_valid_sum": self.egress_dupack_valid_sum,
            }


class NetfilterQueueWorker:
    """Pure-stdlib NFQUEUE + IPPROTO_RAW Geneva duplicate-ACK injector."""

    def __init__(
        self,
        *,
        queue_num: int = GENEVA_QUEUE,
        variant: str = DEFAULT_GENEVA_VARIANT,
        repeats: int = DEFAULT_GENEVA_REPEATS,
        public_sport: int = 443,
    ) -> None:
        if variant not in SUPPORTED_GENEVA_VARIANTS:
            raise ValueError(f"unsupported Geneva variant: {variant!r}")
        if type(repeats) is not int or repeats not in SUPPORTED_GENEVA_REPEATS:
            raise ValueError("repeats must be 1, 2 or 3")
        self.queue_num = queue_num
        self.variant = variant
        self.repeats = repeats
        self.public_sport = public_sport
        self.nl_sock: socket.socket | None = None
        self.raw_sock: socket.socket | None = None
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.lock = threading.Lock()
        self.stats = {
            "synack_seen": 0,
            "dupack_sent": 0,
            "send_errors": 0,
            "other_packets": 0,
        }
        self._seq = 1

    def _send_and_check_ack(self, msg: bytes) -> None:
        assert self.nl_sock is not None
        self.nl_sock.sendall(msg)
        data = self.nl_sock.recv(4096)
        if len(data) < 20:
            raise RuntimeError("short netlink ACK")
        _nl_len, nl_type, _flags, _seq, _pid = struct.unpack_from("<IHHII", data, 0)
        if nl_type != NLMSG_ERROR:
            raise RuntimeError(f"unexpected netlink reply type {nl_type}")
        err = struct.unpack_from("<i", data, 16)[0]
        if err != 0:
            raise OSError(-err, os.strerror(-err))

    def start(self) -> None:
        nl = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        try:
            nl.bind((0, 0))
            nl.settimeout(2.0)
            self.nl_sock = nl
            self._send_and_check_ack(
                build_config_msg(queue_num=self.queue_num, command=NFQNL_CFG_CMD_BIND, seq=1)
            )
            self._send_and_check_ack(
                build_config_msg(
                    queue_num=self.queue_num,
                    copy_mode=NFQNL_COPY_PACKET,
                    copy_range=1600,
                    flags=NFQA_CFG_F_FAIL_OPEN,
                    mask=NFQA_CFG_F_FAIL_OPEN,
                    seq=2,
                )
            )
            raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            raw.setsockopt(socket.SOL_SOCKET, SO_MARK, BYPASS)
            self.raw_sock = raw
        except BaseException:
            self.nl_sock = None
            self.raw_sock = None
            nl.close()
            raw.close()
            raise
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _handle_message(self, msg: bytes) -> None:
        parsed = parse_nfq_packet(msg)
        if parsed is None:
            return
        pkt_id, payload = parsed
        assert self.nl_sock is not None and self.raw_sock is not None
        self._seq += 1
        self.nl_sock.sendall(
            build_verdict_msg(queue_num=self.queue_num, packet_id=pkt_id, verdict=NF_ACCEPT, seq=self._seq)
        )
        try:
            dup = build_geneva_dupack(payload, variant=self.variant, public_sport=self.public_sport)
        except ValueError:
            with self.lock:
                self.stats["other_packets"] += 1
            return

        with self.lock:
            self.stats["synack_seen"] += 1
        dst_ip = socket.inet_ntoa(dup[16:20])
        for _ in range(self.repeats):
            try:
                self.raw_sock.sendto(dup, (dst_ip, 0))
                with self.lock:
                    self.stats["dupack_sent"] += 1
            except OSError:
                with self.lock:
                    self.stats["send_errors"] += 1

    def _run(self) -> None:
        assert self.nl_sock is not None
        while not self.stop_event.is_set():
            ready, _, _ = select.select([self.nl_sock], [], [], 0.2)
            if not ready:
                continue
            try:
                buf = self.nl_sock.recv(65535)
            except OSError:
                if self.stop_event.is_set():
                    break
                continue
            pos = 0
            while pos + 16 <= len(buf):
                nl_len = struct.unpack_from("<I", buf, pos)[0]
                if nl_len < 16 or pos + nl_len > len(buf):
                    break
                self._handle_message(buf[pos : pos + nl_len])
                pos += _pad4(nl_len)

    def snapshot(self) -> dict[str, int]:
        with self.lock:
            return dict(self.stats)

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=3)
        if self.nl_sock is not None:
            try:
                self.nl_sock.sendall(
                    build_config_msg(queue_num=self.queue_num, command=NFQNL_CFG_CMD_UNBIND, seq=999)
                )
            except OSError:
                pass
            try:
                self.nl_sock.close()
            finally:
                self.nl_sock = None
        if self.raw_sock is not None:
            try:
                self.raw_sock.close()
            finally:
                self.raw_sock = None
