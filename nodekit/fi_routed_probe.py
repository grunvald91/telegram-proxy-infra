"""Strict DNS probe, reused from the passed FI canary with explicit local port."""
import secrets,socket,ssl,struct
from fi_shared_routes import need,FI
from fi_dns_origin_canary import HOSTS,read_exact
from fi_dns_metered_dot import valid_answer

def routed_dns_query(name,kind,*,port=8853):
    qid=secrets.randbits(16)
    q=struct.pack("!HHHHHH",qid,256,1,0,0,0)+b"".join(bytes([len(x)])+x.encode("ascii") for x in name.split("."))+b"\0"+struct.pack("!HH",kind,1)
    with socket.create_connection(("127.0.0.1",port),timeout=5) as raw:
        with ssl.create_default_context().wrap_socket(raw,server_hostname=HOSTS[0]) as tls:
            tls.sendall(struct.pack("!H",len(q))+q)
            size=struct.unpack("!H",read_exact(tls,2))[0]
            need(12<=size<=16384,"route_dns_size")
            reply=read_exact(tls,size)
    valid_answer(q,reply)
    _,flags,qd,an,_,_=struct.unpack("!HHHHHH",reply[:12])
    need(flags&15==0 and qd==1,"route_dns_response")
    if kind!=1:
        need(an==0,"alternate_route_not_suppressed")
        return
    need(an==1,"route_A_count")
    # The existing strict DNS parser validated the complete message. Here
    # independently check the sole A record's type and four-byte data.
    off=len(q)
    if reply[off]&0xc0==0xc0:off+=2
    else:
        while reply[off]:off+=1+reply[off]
        off+=1
    rt,cl,_,rdlen=struct.unpack_from("!HHIH",reply,off)
    need(rt==1 and cl==1 and rdlen==4 and reply[off+10:off+14]==socket.inet_aton(FI),"route_A_not_FI")

