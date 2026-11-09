#!/usr/bin/env python3
"""Read-only, synthetic-only regression tests for the temporary packet observer."""
import contextlib
import importlib.util
import io
import ipaddress
import os
import pathlib
import struct
import tempfile

here=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('meta_observer',here/'mnebydns-meta-packet-observer.py')
assert spec and spec.loader
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def hello(name):
    sni_name=name.encode()
    entry=b'\x00'+struct.pack('!H',len(sni_name))+sni_name
    sni=struct.pack('!H',len(entry))+entry
    ext=struct.pack('!HH',0,len(sni))+sni
    ch=b'\x03\x03'+bytes(range(32))+b'\x00'+b'\x00\x02\x13\x01'+b'\x01\x00'+struct.pack('!H',len(ext))+ext
    hs=b'\x01'+len(ch).to_bytes(3,'big')+ch
    return b'\x16\x03\x01'+struct.pack('!H',len(hs))+hs


def ipv4(src,dst,proto,transport):
    addresses=ipaddress.IPv4Address(src).packed+ipaddress.IPv4Address(dst).packed
    head=b'\x45\x00'+struct.pack('!H',20+len(transport))+b'\x00\x00\x00\x00\x40'+bytes((proto,))+b'\x00\x00'+addresses
    return head+transport


def tcp(src,dst,sport,dport,flags,data=b''):
    hdr=struct.pack('!HHII',sport,dport,1,1)+bytes((0x50,flags))+b'\x00\x00\x00\x00\x00\x00'
    return ipv4(src,dst,6,hdr+data)


def udp(src,dst,sport,dport,data=b''):
    header=struct.pack('!HHHH',sport,dport,8+len(data),0)
    return ipv4(src,dst,17,header+data)


def pcap_file(frames,linktype=101):
    header=b'\xd4\xc3\xb2\xa1'+struct.pack('<HHiIII',2,4,0,0,4096,linktype)
    return header+b''.join(struct.pack('<IIII',1,0,len(f),len(f))+f for f in frames)


def run():
    local='188.120.254.223';client='198.51.100.28'
    frames=[tcp(client,local,55555,443,0x02),
            tcp(local,client,443,55555,0x12),
            tcp(client,local,55555,443,0x18,hello('i.instagram.com')),
            tcp(local,client,443,55555,0x18,b'\x16\x03\x03\x00\x04\x02\x00\x00\x00'),
            udp(client,local,33333,443,b'\xc0\x00\x00\x00\x01'+b'\x00'*1230),
            udp(local,client,443,33333,b'\xc0\x00\x00\x00\x01'+b'\x00'*1230),
            tcp(local,client,443,55555,0x14)]
    obj=m.Observer('ru')
    for frame in frames:obj.packet(frame,101)
    assert obj.c['tcp_syn_in']==1
    assert obj.c['tcp_synack_out']==1
    assert obj.c['tcp_clienthello_in']==1
    assert obj.c['tcp_clienthello_meta_in']==1
    assert obj.c['tcp_payload_bytes_out']>0
    assert obj.c['tcp_reset_out']==1
    assert obj.c['udp_in']==1 and obj.c['udp_out']==1
    assert obj.c['udp_quic_v1_initial_in']==1
    assert m.tls_clienthello_name(hello('x.com'))==(True,False)
    assert m.tls_clienthello_name(hello('i.instagram.com'))==(True,True)
    assert m.tls_clienthello_name(hello('i.instagram.com')[:20])==(False,False)
    with tempfile.TemporaryDirectory() as folder:
        path=os.path.join(folder,'fixture.pcap')
        pathlib.Path(path).write_bytes(pcap_file(frames))
        out=io.StringIO()
        with contextlib.redirect_stdout(out): actual=m.consume_file(path,'ru')
        assert actual.c==obj.c
        line=out.getvalue()
        assert 'tcp_clienthello_meta_in=1' in line
        assert client not in line and local not in line
        assert 'instagram' not in line
        # Also support Ethernet and Linux cooked framing.
        for link,prefix in ((1,b'\x00'*12+b'\x08\x00'),
                            (113,b'\x00'*14+b'\x08\x00'),
                            (276,b'\x00'*18+b'\x08\x00')):
            pathlib.Path(path).write_bytes(pcap_file([prefix+frames[0]],link))
            with contextlib.redirect_stdout(io.StringIO()):
                alt=m.consume_file(path,'ru')
            assert alt.c['tcp_syn_in']==1,(link,alt.c)
    print('meta_observer_no_raw_packet_persistence=PASS')
    print('meta_observer_tcp_clienthello_and_udp_stages=PASS')
    print('meta_observer_does_not_log_client_IP_or_SNI=PASS')
    print('meta_observer_pcap_linktypes_101_1_113_276=PASS')

if __name__=='__main__':run()