"""Synthetic-only tests for the focused DE89 Googlevideo media flow observer."""
import importlib.util
from pathlib import Path
import socket
import struct
import unittest

SCRIPT=Path(__file__).resolve().parents[1]/"de89-googlevideo-phone-playback-readonly-20261117.py"
spec=importlib.util.spec_from_file_location("target_tls", SCRIPT)
target=importlib.util.module_from_spec(spec)
spec.loader.exec_module(target)

def hello(host="rr1---sn-gxuo03g-ig3s.googlevideo.com", total_bytes=1573):
    name=host.encode("ascii")
    sni_list=b"\x00"+len(name).to_bytes(2,"big")+name
    sni_body=len(sni_list).to_bytes(2,"big")+sni_list
    ext_sni=b"\x00\x00"+len(sni_body).to_bytes(2,"big")+sni_body
    base=b"\x03\x03"+b"\x00"*32+b"\x00"+b"\x00\x02\x13\x01"+b"\x01\x00"
    first=base+len(ext_sni).to_bytes(2,"big")+ext_sni
    base_total=len(first)+9
    pad_size=total_bytes-base_total-4
    if pad_size<0:raise ValueError("too short")
    padding=b"\x00\x15"+pad_size.to_bytes(2,"big")+b"\x00"*pad_size
    exts=ext_sni+padding
    body=base+len(exts).to_bytes(2,"big")+exts
    handshake=b"\x01"+len(body).to_bytes(3,"big")+body
    return b"\x16\x03\x01"+len(handshake).to_bytes(2,"big")+handshake

def frame(src,dst,sp,dp,payload,seq=1,network=276,window=4096):
    tcp=struct.pack("!HHIIHHHH",sp,dp,seq,1,0x5018,window,0,0)+payload
    ip_len=20+len(tcp)
    ip=(struct.pack("!BBHHHBBH",0x45,0,ip_len,0,0,64,6,0)
        +socket.inet_aton(src)+socket.inet_aton(dst))
    if network==276:l2=b"\x08\x00"+b"\x00"*18
    elif network==113:l2=b"\x00"*14+b"\x08\x00"
    else:l2=b"\x00"*12+b"\x08\x00"
    return l2+ip+tcp

class TargetTlsTests(unittest.TestCase):
    def test_media_size_1573_hello_and_sni(self):
        message=hello()
        self.assertEqual(len(message),1573)
        self.assertEqual(target.tls_sni(message),"rr1---sn-gxuo03g-ig3s.googlevideo.com")
        self.assertEqual(5+int.from_bytes(message[3:5],"big"),1573)

    def test_incomplete_record_can_still_classify_sni(self):
        data=hello()
        self.assertEqual(target.tls_sni(data[:1448]),"rr1---sn-gxuo03g-ig3s.googlevideo.com")
        self.assertIsNone(target.tls_sni(data[:45]))

    def test_other_hostname_is_not_target(self):
        self.assertEqual(target.tls_sni(hello("www.youtube.com")),"www.youtube.com")

    def test_tcp_reassembly_of_two_segments(self):
        data=hello()
        chunks={1000:data[:1448],2448:data[1448:]}
        self.assertEqual(target.join_segments(chunks),data)
        self.assertEqual(target.tls_sni(target.join_segments(chunks)),'rr1---sn-gxuo03g-ig3s.googlevideo.com')
        self.assertEqual(len(target.join_segments({1000:data[:1448]})),1448)

    def test_tcp_decode_and_window(self):
        data=hello()
        for link in (1,113,276):
            p=target.decode(frame("198.51.100.20",target.PUBLIC,41000,443,data[:1448],
                                  seq=1000,network=link,window=4),link)
            self.assertIsNotNone(p)
            self.assertEqual(p[4],1000)
            self.assertEqual(p[6],4)
            self.assertEqual(p[7],1448)
            self.assertEqual(p[-1],data[:1448])

if __name__=="__main__":
    unittest.main()
