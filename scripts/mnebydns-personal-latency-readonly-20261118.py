#!/usr/bin/env python3
"""Read-only latency and denial checks for PERSONAL DoT. Not a subscriber test.

Only cold TLS setup, unknown-identity denial, and route health metadata.
Does not read bearer credentials, issue profiles, or touch DNS/proxy/VPN rules.
"""
from __future__ import annotations
import argparse
import json
import math
import os
import re
import secrets
import socket
import ssl
import statistics
import struct
import subprocess
import time

PUBLIC="dns.mnebyvpn.site"
BACKEND_NAME="mnebydns-personal-dot-private"
N=5
TIMEOUT=4

def run(args, timeout=5):
    try:
        result=subprocess.run(args,text=True,capture_output=True,timeout=timeout)
        return result.stdout.strip() if result.returncode==0 else ""
    except (OSError,subprocess.TimeoutExpired):
        return ""

def private_endpoint():
    raw=run(["docker","inspect","--format","{{json .Config.Env}}",BACKEND_NAME],6)
    if not raw:raise RuntimeError("private_container_unavailable")
    values=dict(v.split("=",1) for v in json.loads(raw)
                if isinstance(v,str) and "=" in v)
    host=values.get("MNEBYDNS_PERSONAL_DOT_BIND_IP","")
    port=values.get("MNEBYDNS_PERSONAL_DOT_PORT","")
    if not (re.fullmatch(r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",host)
            and port.isdigit() and 1024<=int(port)<=65535):
        raise RuntimeError("private_endpoint_undetermined")
    return host,int(port)

def do_handshake(address,port,sni):
    start=time.perf_counter()
    with socket.create_connection((address,port),timeout=TIMEOUT) as tcp:
        tcp_ms=(time.perf_counter()-start)*1000
        tcp.settimeout(TIMEOUT)
        with ssl.create_default_context().wrap_socket(tcp,server_hostname=sni) as tls:
            return (round(tcp_ms,2), round((time.perf_counter()-start)*1000,2),
                    tls.version())

def recvn(sock,n):
    value=bytearray()
    while len(value)<n:
        chunk=sock.recv(n-len(value))
        if not chunk:break
        value.extend(chunk)
    return bytes(value)

def unknown_personal_denial(address,port,sni):
    # The 12-character SNI is newly random. Never print it.
    host="example.org"
    qname=b"\x07example\x03org\x00"
    tx=secrets.randbelow(65535)+1
    query=struct.pack("!HHHHHH",tx,0x100,1,0,0,0)+qname+struct.pack("!HH",1,1)
    try:
        with socket.create_connection((address,port),timeout=TIMEOUT) as tcp:
            tcp.settimeout(TIMEOUT)
            with ssl.create_default_context().wrap_socket(tcp,server_hostname=sni) as tls:
                tls.settimeout(1.5)
                tls.sendall(struct.pack("!H",len(query))+query)
                length=recvn(tls,2)
                if len(length)<2:return "rejected_closed"
                n=struct.unpack("!H",length)[0]
                if n<12 or n>8192:return "invalid_dns_frame"
                response=recvn(tls,n)
                if len(response)!=n:return "incomplete_dns_response"
                if int.from_bytes(response[:2],"big")!=tx:return "unmatched_dns_response"
                flags=struct.unpack_from("!H",response,2)[0]
                qd,an=struct.unpack_from("!HH",response,4)
                if (flags&0x8000) and (flags&0x000f)==0 and qd==1 and an>0:
                    return "SECURITY_FAILURE_UNISSUED_SNI_ANSWERED"
                return "rejected_dns_response"
    except socket.timeout:
        return "indeterminate_timeout"
    except (EOFError,ConnectionError,ssl.SSLError,BrokenPipeError,ConnectionResetError):
        return "rejected_closed"
    except OSError:
        return "endpoint_unavailable"

def stats(samples):
    if not samples:return None
    a=sorted(samples)
    return {"n":len(a),"p50_ms":round(statistics.median(a),2),
            "p95_ms":round(a[math.ceil(0.95*len(a))-1],2),
            "max_ms":round(a[-1],2)}

def check(name,endpoint):
    address,port=endpoint
    outcomes=[]
    failures={}
    versions=set()
    for _ in range(N):
        token="".join(secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(12))
        sni=token+".dns.mnebyvpn.site"
        try:
            tcp,full,ver=do_handshake(address,port,sni)
            versions.add(ver)
            outcomes.append((tcp,full))
        except ssl.SSLCertVerificationError as ex:
            # Do not log certificate subject, host addresses, or client identity.
            key="SSLCertVerificationError_code_"+str(ex.verify_code)
            failures[key]=failures.get(key,0)+1
        except Exception as ex:
            key=type(ex).__name__
            failures[key]=failures.get(key,0)+1
    label="".join(secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(12))
    denied=unknown_personal_denial(address,port,label+".dns.mnebyvpn.site")
    return {"name":name,"cold_tcp":stats([x[0] for x in outcomes]),
            "cold_tcp_tls_total":stats([x[1] for x in outcomes]),
            "cold_attempts":N,"cold_failures":failures,
            "tls_versions":sorted(versions),"unknown_sni_denial":denied,
            "authenticated_dns_queries":"NOT_TESTED_NO_SERVICE_PROFILE"}

def endpoints_for(role):
    if role=="de":
        # Self-connect to DE's public IP bypasses eth0/PREROUTING, so it would
        # reach the legacy :853 listener instead of the external personal SNI
        # redirect to :8854. Never classify this as a client TLS failure.
        return [("de_local_personal_sni",("127.0.0.1",8854))]
    return [("public_personal_ingress",(PUBLIC,853))]

def node(role):
    endpoints=endpoints_for(role)
    if role=="ru":
        try:
            active=private_endpoint()
            endpoints.append(("ru_private_personal_backend",active))
            # Old generation is an UNVERIFIED candidate, not an authorized
            # fallback. Its real subscriber / revoked / expired behavior is
            # NOT implied by a successful TLS handshake.
            if active[1] != 8856:
                endpoints.append(("ru_legacy_8856_transport_only",(active[0],8856)))
        except Exception as ex:
            return {"vantage":role,"error":str(ex),"authenticated_dns_queries":"NOT_TESTED"}
    result={"vantage":role,"time_utc":int(time.time()),
            "measurement":"synthetic unauthenticated TLS and denial; not client DNS/video",
            "checks":[check(name,endpoint) for name,endpoint in endpoints]}
    if role=="de":
        raw=run(["systemctl","is-active","mnebydns-personal-sni-watch.timer"])
        result["personal_watch_timer"]=raw or "unknown"
        result["personal_ingress_redirect_unit"]=run([
            "systemctl","is-active","mnebydns-personal-sni-redirect.service"]) or "unknown"
        result["self_to_public"]= "SKIPPED_OUTPUT_BYPASSES_PREROUTING"
    print(json.dumps(result,separators=(",",":"),sort_keys=True))
    # Bad denial is an explicit security test failure; report not a silent pass.
    if any(c["unknown_sni_denial"]=="SECURITY_FAILURE_UNISSUED_SNI_ANSWERED"
           for c in result["checks"]):
        raise SystemExit(2)

def main():
    a=argparse.ArgumentParser()
    a.add_argument("--vantage",choices=("runner","ru","de"),required=True)
    a.add_argument("--self-test",action="store_true")
    opt=a.parse_args()
    if opt.self_test:
        assert stats([1,3,7,9,12])["p50_ms"]==7
        assert stats([1,3,7,9,12])["p95_ms"]==12
        assert "aaa".isascii()
        assert endpoints_for("de")==[("de_local_personal_sni",("127.0.0.1",8854))]
        assert endpoints_for("ru")==[("public_personal_ingress",(PUBLIC,853))]
        assert "ru_legacy_8856_transport_only" in open(__file__,encoding="utf8").read()
        print("PERSONAL_DOT_LATENCY_OFFLINE=PASS")
    else:node(opt.vantage)

if __name__=="__main__":
    main()
