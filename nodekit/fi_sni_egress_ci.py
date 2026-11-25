#!/usr/bin/env python3
"""Actual isolated network namespace test; never touches host nftables."""
import os
import socket
import subprocess
import sys
from fi_sni_egress_guard import rules,table,digest,TABLE

def cmd(*args,data=None):
    return subprocess.run(args,input=data,capture_output=True,check=True,timeout=8).stdout

def test():
    assert os.geteuid()==0
    cmd("ip","link","set","lo","up")
    assert table() is None
    n=65534
    data=rules(n).encode()
    cmd("nft","-c","-f","-",data=data)
    cmd("nft","-f","-",data=data)
    before=table();assert before is not None
    with socket.socket() as listener:
        listener.bind(("127.0.0.1",0));listener.listen(1)
        port=listener.getsockname()[1]
        with socket.create_connection(("127.0.0.1",port),timeout=2),listener.accept()[0]:pass
        code="import socket,sys\ntry:\n s=socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=2);sys.exit(9)\nexcept OSError:sys.exit(0)"
        cmd("setpriv","--reuid=65534","--regid=65534","--clear-groups",sys.executable,"-c",code,str(port))
    # Inbound reply by the guarded UID must remain functional.
    code="import socket,sys\ns=socket.socket();s.bind(('127.0.0.1',0));s.listen(1);print(s.getsockname()[1],flush=True);c,_=s.accept();c.sendall(b'OK');c.close()"
    child=subprocess.Popen(["setpriv","--reuid=65534","--regid=65534","--clear-groups",sys.executable,"-c",code],stdout=subprocess.PIPE,text=True)
    try:
        port=int(child.stdout.readline())
        with socket.create_connection(("127.0.0.1",port),timeout=2) as raw:assert raw.recv(2)==b"OK"
        assert child.wait(3)==0
    finally:
        if child.poll() is None:child.kill();child.wait(3)
    after=table()
    assert digest(before)==digest(after),"counter changes must not invalidate rule integrity"
    def rejected(t):
        return sum(e["counter"]["packets"] for row in t["nftables"] if "rule" in row and any("reject" in x for x in row["rule"]["expr"]) for e in row["rule"]["expr"] if "counter" in e)
    assert rejected(after)>rejected(before)
    cmd("nft","add","rule","inet",TABLE,"proxy_out","counter","reject")
    assert digest(table())!=digest(before)
    print("FI_SNI_NFT_UID_ISOLATION_AND_DRIFT_TEST=PASS")

if __name__=="__main__":test()
