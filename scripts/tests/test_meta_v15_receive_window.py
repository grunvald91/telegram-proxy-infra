"""Offline contracts plus unprivileged real-socket checks for v15."""
from pathlib import Path
import socket
import sys
import threading
import unittest
from unittest.mock import Mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import meta_v15_receive_window as m
from test_mnebydns_iglite_sni_observer import tls_hello,fragment_records


class FakeConnection:
    def __init__(self,chunks):self.chunks=list(chunks);self.options=[]
    def settimeout(self,value):pass
    def setsockopt(self,*args):self.options.append(args)
    def recv(self,size):
        if not self.chunks:return b""
        value=self.chunks.pop(0)
        if len(value)>size:
            self.chunks.insert(0,value[size:]);value=value[:size]
        return value


class ReceiveWindowTests(unittest.TestCase):
    def test_lab_control_handshake_check_ignores_teardown_window(self):
        import struct
        from integration_meta_v15_netns import LabAnalyzer,EDGE,CONTROL
        from test_mnebydns_iglite_sni_observer import packet
        analyzer=LabAnalyzer()
        for flags,window in ((0x12,32768),(0x04,0)):
            frame=bytearray(packet(100,flags))
            frame[26:30]=socket.inet_aton(EDGE)
            frame[30:34]=socket.inet_aton(CONTROL)
            struct.pack_into('!HH',frame,34,443,42424)
            struct.pack_into('!H',frame,48,window)
            analyzer.ethernet(bytes(frame))
        self.assertEqual(analyzer.control_synack_windows,[32768])
        self.assertEqual(analyzer.control_windows,[32768,0])

    def test_prefix_waits_for_sni_across_tls_record_fragments(self):
        hello=tls_hello("i.instagram.com")
        fragmented=fragment_records(hello,(30,))
        first=fragmented[:35]
        conn=FakeConnection([first,fragmented[35:]])
        data,host=m.read_prefix(conn)
        self.assertEqual(host,"i.instagram.com")
        self.assertEqual(data,fragmented)

    def test_accept_failure_stops_worker_instead_of_silent_blackhole(self):
        proxy=m.WindowProxy("89.125.90.101","8.8.8.8")
        proxy.listener=Mock();proxy.listener.accept.side_effect=OSError("synthetic accept failure")
        proxy.accept()
        self.assertTrue(proxy.stop.is_set())
        self.assertEqual(proxy.stats["accept_failed"],1)

    def test_complete_sni_from_real_small_reads(self):
        hello=tls_hello("i.instagram.com")
        conn=FakeConnection([hello[i:i+8] for i in range(0,len(hello),8)])
        data,host=m.read_prefix(conn)
        self.assertEqual(host,"i.instagram.com")
        self.assertEqual(data,hello[:len(data)])
        self.assertTrue(conn.options)
        self.assertTrue(all(opt==(socket.IPPROTO_TCP,socket.TCP_QUICKACK,1)
                            for opt in conn.options))

    def test_no_sni_empty_and_oversize_records(self):
        data,host=m.read_prefix(FakeConnection([b"GET / HTTP/1.0\r\n\r\n"]))
        self.assertIsNone(host);self.assertTrue(data.startswith(b"GET"))
        with self.assertRaises(ConnectionError):m.read_prefix(FakeConnection([b"\x16"]))
        with self.assertRaises(ValueError):
            m.read_prefix(FakeConnection([b"\x16\x03\x03\xff\xff"]))

    def test_rules_apply_only_to_one_peer_and_listener(self):
        rules=m.nft_rules("89.125.90.101","8.8.8.8")
        self.assertIn("ip saddr 8.8.8.8 ip daddr 89.125.90.101 tcp dport 443",rules)
        self.assertIn("ip saddr 89.125.90.101 ip daddr 8.8.8.8 tcp sport 18443",rules)
        self.assertIn("meta mark & 0x20000000 == 0",rules)
        self.assertIn("tcp window set 8",rules)
        self.assertIn("tcp window > 8",rules)
        self.assertIn("dnat ip to 89.125.90.101:18443",rules)
        self.assertNotIn("sysctl",rules)
        self.assertNotIn("tcp option",rules)

    def test_no_rule_injection_or_wildcard_peer(self):
        for options in ({"peer":"0.0.0.0/0"},{"interface":"eth0; flush ruleset"},
                        {"table":"x\nflush ruleset"},{"port":443},{"port":65536}):
            kwargs={"edge":"89.125.90.101","peer":"8.8.8.8"};kwargs.update(options)
            with self.assertRaises(ValueError):m.nft_rules(**kwargs)

    def test_queue_bypass_must_match_exact_bitwise_expression(self):
        match={"op":"==","left":{"&":[{"meta":{"key":"mark"}},m.BYPASS]},"right":0}
        def rules(expr):return {"nftables":[{"rule":{"expr":expr}}]}
        self.assertTrue(m.verify_queue_exemption(rules([{"match":match},{"queue":{"num":210}}])))
        for wrong in (dict(match,op="!="),dict(match,right=m.BYPASS),
                      {"left":"mentions 1073741824","op":"==","right":0}):
            with self.assertRaises(ValueError):
                m.verify_queue_exemption(rules([{"match":wrong},{"queue":{"num":210}}]))
        with self.assertRaises(ValueError):
            m.verify_queue_exemption(rules([{"queue":{"num":210}},{"match":match}]))

    def test_per_listener_clamp_negotiates_zero_without_sysctl_change(self):
        original=Path("/proc/sys/net/ipv4/tcp_window_scaling").read_bytes()
        with socket.socket() as listener:
            listener.setsockopt(socket.IPPROTO_TCP,socket.TCP_WINDOW_CLAMP,m.CLAMP)
            listener.bind(("127.0.0.1",0));listener.listen(1);listener.settimeout(2)
            with socket.create_connection(listener.getsockname(),timeout=2) as client:
                server,_=listener.accept()
                with server:
                    self.assertEqual(m.receive_scale(server),0)
        self.assertEqual(Path("/proc/sys/net/ipv4/tcp_window_scaling").read_bytes(),original)

    def test_relay_preserves_large_payload_and_half_close(self):
        source,left=socket.socketpair();right,destination=socket.socketpair()
        self.addCleanup(source.close);self.addCleanup(destination.close)
        self.addCleanup(left.close);self.addCleanup(right.close)
        stop=threading.Event();errors=[]
        def relay():
            try:m.relay(left,right,stop,idle=5)
            except BaseException as exc:errors.append(exc)
        worker=threading.Thread(target=relay,daemon=True);worker.start()
        body=b"synthetic"*20000;received=[]
        def read_server():
            while True:
                part=destination.recv(8192)
                if not part:break
                received.append(part)
            destination.sendall(b"response-after-half-close")
            destination.shutdown(socket.SHUT_WR)
        server=threading.Thread(target=read_server,daemon=True);server.start()
        source.settimeout(5);source.sendall(body);source.shutdown(socket.SHUT_WR)
        reply=b""
        while True:
            part=source.recv(8192)
            if not part:break
            reply+=part
        worker.join(timeout=5);server.join(timeout=5)
        self.assertFalse(errors,errors)
        self.assertFalse(worker.is_alive())
        self.assertEqual(b"".join(received),body)
        self.assertEqual(reply,b"response-after-half-close")

    def test_cleanup_stops_owned_worker_even_if_nft_delete_fails(self):
        import importlib
        import tempfile
        from types import SimpleNamespace
        from unittest.mock import patch
        import mnebydns_iglite_route_only_v11 as route
        names=("ROOT","UNIT","TABLE","PERSISTENT_STAGE")
        before={key:getattr(route.base,key) for key in names}
        route_keys=("ROLLBACK_SCRIPT","TRANSPORT_LABEL","MUTATION_GUARD","LIVE_CHECK","TRIAL_WAIT","rollback")
        route_before={key:getattr(route,key) for key in route_keys}
        try:
            trial=importlib.import_module("meta_v15_phone_trial")
            with tempfile.TemporaryDirectory() as td:
                state=Path(td);(state/"armed").write_text("yes")
                calls=[]
                def command(args,**kwargs):
                    calls.append(tuple(args))
                    if args[:2]==["nft","delete"]:raise RuntimeError("synthetic failure")
                    return SimpleNamespace(returncode=0 if args[0]=="nft" else 3)
                with patch.object(trial,"STATE",state),patch.object(trial,"command",side_effect=command), \
                     patch.object(trial.route,"rollback") as restore:
                    with self.assertRaisesRegex(RuntimeError,"cleanup failed"):trial.cleanup()
                    restore.assert_called_once()
                    self.assertIn(("systemctl","stop",trial.WORKER+".service"),calls)
                    self.assertFalse(any(c[0]=="sysctl" for c in calls))
        finally:
            for key,value in before.items():setattr(route.base,key,value)
            for key,value in route_before.items():setattr(route,key,value)


if __name__=="__main__":unittest.main()
