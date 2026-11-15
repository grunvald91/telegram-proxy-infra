#!/usr/bin/env python3
"""Read only evaluate concrete DNS routing for named public products.
No customer DNS labels, secrets, server config bodies or user data.
"""
import json,ssl,socket,struct,pathlib,re
def emit(k,v):print("COVERAGE_"+k+"="+json.dumps(v,sort_keys=True,ensure_ascii=False),flush=True)
def read(s,n):
    b=b""
    while len(b)<n:
        z=s.recv(n-len(b))
        if not z:raise EOFError("DNS truncated")
        b+=z
    return b
def skipname(buf,o):
    for i in range(130):
        if o>=len(buf):raise ValueError("end")
        k=buf[o];o+=1
        if k==0:return o
        if k>=192:return o+1
        if k>63:raise ValueError("label")
        o+=k
    raise ValueError("loop")
def a_records(qname):
    q=b"".join(bytes([len(z)])+z.encode("ascii") for z in qname.split("."))+b"\0"
    q=struct.pack("!HHHHHH",30013,256,1,0,0,0)+q+struct.pack("!HH",1,1)
    with socket.create_connection(("89.125.90.101",853),timeout=5) as sock:
        sock.settimeout(5)
        with ssl.create_default_context().wrap_socket(sock,server_hostname="dns.mnebyvpn.site") as tls:
            tls.sendall(struct.pack("!H",len(q))+q)
            size=struct.unpack("!H",read(tls,2))[0]
            data=read(tls,size)
    assert data[:2]==q[:2]
    rc=data[3]&15;count=struct.unpack_from("!H",data,6)[0]
    offset=skipname(data,12)+4
    ips=[]
    for _ in range(count):
        offset=skipname(data,offset)
        if offset+10>len(data):break
        kind,cls,ttl,ln=struct.unpack_from("!HHIH",data,offset);offset+=10
        if kind==1 and ln==4:ips.append(socket.inet_ntoa(data[offset:offset+4]))
        offset+=ln
    return {"rcode":rc,"a_total":len(ips),"smartdns_de89_A":sum(a=="89.125.90.101" for a in ips),
            "ru188_A":sum(a=="188.120.254.223" for a in ips)}
names=("groq.com","www.groq.com","api.groq.com","console.groq.com",
       "oracle.com","www.oracle.com","cloud.oracle.com","console.oracle.com",
       "www.youtube.com","generativelanguage.googleapis.com",
       "chatgpt.com","copilot.microsoft.com")
core=pathlib.Path("/opt/mnebydns-dot/Corefile")
data=core.read_text(errors="replace")
for name in names:
    try:
        status=a_records(name)
    except Exception as exc:
        status={"error":type(exc).__name__}
    # CoreDNS emits exact domain strings or escaped Corefile regexes.
    root=name.removeprefix("www.").removeprefix("api.").removeprefix("console.").removeprefix("cloud.")
    status["mentions_domain_or_root"]=root.lower() in data.lower() or root.lower().replace(".",r"\.") in data.lower()
    emit("DNS_"+name.replace(".","_"),status)
emit("DONE",True)
