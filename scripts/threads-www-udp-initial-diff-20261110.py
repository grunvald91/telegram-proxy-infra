#!/usr/bin/env python3
"""Sends synthetic same-sized QUIC v1 Initial datagrams to an owned endpoint.
No phone traffic or user data; observes only local UDP send status and source ports.
"""
import argparse
import importlib.util
import os
import pathlib
import random
import socket
import time

HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("quic_fixture",HERE/"test-mnebydns-meta-quic.py")
fixture=importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

def cases():
    pairs=(
      ("threadswww", "www.threads.com", "www.example.com"),
      ("threadsgraph", "graph.threads.com", "graph.example.com"),
      ("threadsnet", "www.threads.net", "www.example.net"),
    )
    items=[]
    for label,meta,control in pairs:
        assert len(meta)==len(control)
        for which,sni in (("meta",meta),("control",control)):
            data=fixture.fixture_sni(sni)
            assert len(data)==1252,(label,len(data))
            items.append((label+"_"+which,data))
    items.append(("nonquic_equal_length",bytes((0x12,))+bytes(1251)))
    items.append(("fake_quic_equal_length",bytes.fromhex("c000000001")+bytes(1247)))
    items.append(("nonquic_small",bytes((0x12,))+bytes(599)))
    return items

def selftest():
    items=cases()
    assert len(items)==9
    for key,data in items:
        print("udp_fixture_"+key+"_bytes="+str(len(data)),flush=True)
    print("udp_equal_size_fixture_selftest=PASS",flush=True)

def send(host,port,count):
    selftest()
    seen=set()
    for n in range(count):
        items=cases()
        random.Random(293+n).shuffle(items)
        for label,data in items:
            localport=-1
            sent=0
            error="none"
            try:
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                    sock.settimeout(2)
                    sent=sock.sendto(data,(host,port))
                    localport=sock.getsockname()[1]
                    assert localport not in seen, "local ephemeral UDP port was reused; abort"
                    seen.add(localport)
                    time.sleep(.08)
            except OSError as e:
                error=type(e).__name__+"_"+str(e.errno)
            print("udp_trial="+label+" local_port="+str(localport)+
                  " sent="+str(sent)+" error="+error,flush=True)
            time.sleep(.10)

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("command",choices=("self-test","send"))
    p.add_argument("--host",default="188.120.254.223")
    p.add_argument("--port",type=int,default=443)
    p.add_argument("--repeat",type=int,default=4)
    args=p.parse_args()
    if args.command=="self-test":selftest()
    else:
        assert 1<=args.repeat<=5
        send(args.host,args.port,args.repeat)
