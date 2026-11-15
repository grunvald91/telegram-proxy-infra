#!/usr/bin/env python3
"""One-shot bounded TCP payload test on WireGuard ONLY, no configuration mutations."""
import json,socket,sys,time,os,pathlib,subprocess
IP="10.66.77.1";PORT=45379;TOTAL=12*1024*1024
def out(label,value):
    print("WG_BULK_"+label+"="+json.dumps(value,sort_keys=True),flush=True)
def tcp():
    try:
        m=pathlib.Path("/proc/net/netstat").read_text().splitlines()
        d={}
        for i in range(len(m)-1):
            a,b=m[i].split(),m[i+1].split()
            if a and b and a[0]==b[0]=="TcpExt:":
                d=dict(zip(a[1:],map(int,b[1:])))
        return {k:d.get(k,0) for k in ("TCPTimeouts","TCPLossProbes","TCPSynRetrans","TCPLossProbeRecovery","TCPRcvQDrop")}
    except Exception:return {}
def main():
    mode=sys.argv[1] if len(sys.argv)==2 else ""
    if mode=="server":
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            s.bind((IP,PORT));s.listen(1);s.settimeout(45)
            out("SERVER_READY",{"ip":IP,"port":PORT,"bytes":TOTAL,"pid":os.getpid()})
            with s.accept()[0] as c:
                c.settimeout(35)
                n=0;chunk=b"X"*65536;start=time.monotonic()
                while n<TOTAL:
                    k=min(len(chunk),TOTAL-n)
                    c.sendall(chunk[:k]);n+=k
                elapsed=time.monotonic()-start
                out("SERVER_COMPLETED",{"bytes":n,"seconds":round(elapsed,3),"mbps":round(n*8/(elapsed*1000000),2)})
    elif mode=="client":
        before=tcp()
        start=time.monotonic()
        with socket.create_connection((IP,PORT),timeout=6) as s:
            s.settimeout(32)
            recv=0;last=start;max_idle=0;milestones=[]
            while recv<TOTAL:
                buf=s.recv(65536)
                if not buf:break
                now=time.monotonic()
                max_idle=max(max_idle,now-last);last=now;recv+=len(buf)
                if recv//(1024*1024)>len(milestones):
                    milestones.append({"mb":recv//(1024*1024),"elapsed_s":round(now-start,2)})
        elapsed=time.monotonic()-start
        after=tcp()
        out("CLIENT_RESULT",{"complete":recv==TOTAL,"bytes":recv,"seconds":round(elapsed,3),
           "mbps":round(recv*8/(elapsed*1000000),2),"max_inter_recv_s":round(max_idle,3),
           "milestones":milestones,"tcp_counter_delta":{k:after.get(k,0)-v for k,v in before.items()}})
        if recv!=TOTAL:raise SystemExit(3)
    else:raise SystemExit(2)
if __name__=="__main__":
    main()
