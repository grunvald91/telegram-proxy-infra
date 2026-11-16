#!/usr/bin/env python3
"""Read-only inventory of effective Google/YouTube CoreDNS -> shared SNI -> GooglePilot paths.
Reads production files but does not emit file contents, private domains or keys.
Synthetic hostname coverage is NOT client-verified use of a personalized DoT identity.
"""
from __future__ import annotations
import json
import pathlib
import re
import socket
import ssl
import sys
import time

CORE=pathlib.Path("/opt/mnebydns-dot/Corefile")
SHARED=pathlib.Path("/etc/nginx/nginx.conf")
PILOT=pathlib.Path("/etc/mnebydns-googlepilot/nginx.conf")
TARGET="89.125.90.101"
# Representative host families, auth, playback, experiments, and Android system controls.
YOUTUBE=(
"youtube.com","www.youtube.com","m.youtube.com","music.youtube.com",
"kids.youtube.com","studio.youtube.com","tv.youtube.com","gaming.youtube.com",
"signaler-pa.youtube.com","youtubei.youtube.com","youtubei.googleapis.com",
"youtube.googleapis.com","youtubeembeddedplayer.googleapis.com",
"www.youtube-nocookie.com","youtube-nocookie.com","youtu.be","yt.be",
"i.ytimg.com","i9.ytimg.com","s.ytimg.com","ytimg.com",
"yt3.ggpht.com","yt4.ggpht.com","ggpht.com","lh3.googleusercontent.com",
"yt3.googleusercontent.com","yt4.googleusercontent.com",
"yt-video.googleusercontent.com","manifest.googlevideo.com",
"r1---sn-abcd.googlevideo.com","rr1---sn-gxuo03g-ig3s.googlevideo.com",
"googlevideo.com","redirector.googlevideo.com","wide-youtube.l.google.com",
"youtube-ui.l.google.com","ytimg.l.google.com","ytstatic.l.google.com",
"yt-video-upload.l.google.com","cdn.youtube.com","rtmps.youtube.com",
"withyoutube.com","youtubeeducation.com","youtubekids.com",
"jnn-pa.googleapis.com","optimizationguide-pa.googleapis.com",
"waa-pa.clients6.google.com","suggestqueries.google.com","accounts.youtube.com",
)
GOOGLE=(
"google.com","www.google.com","accounts.google.com","myaccount.google.com",
"ogs.google.com","apis.google.com","www.googleapis.com","ajax.googleapis.com",
"fonts.googleapis.com","fonts.gstatic.com","www.gstatic.com","ssl.gstatic.com",
"gstatic.com","googleapis.com","googleusercontent.com","ggpht.com",
"google.ru","www.google.ru","google.de","www.google.de","google.co.uk",
"www.google.co.uk","play.google.com","play.googleapis.com","play-fe.googleapis.com",
"mail.google.com","gmail.com","drive.google.com","docs.google.com","sheets.google.com",
"calendar.google.com","photos.google.com","maps.google.com","maps.googleapis.com",
"maps.gstatic.com","encrypted-tbn0.gstatic.com","google-analytics.com",
"www.google-analytics.com","googleadservices.com","www.googletagmanager.com",
"doubleclick.net","googleads.g.doubleclick.net","static.doubleclick.net",
"generativelanguage.googleapis.com","aistudio.google.com","gemini.google.com",
"storage.googleapis.com","oauth2.googleapis.com","people.googleapis.com",
"content-autofill.googleapis.com","google.com.au","www.google.com.au",
"gvt1.com","gvt2.com","gvt3.com","r2---sn-a5mekn76.gvt1.com",
"beacons.gvt2.com","dl.google.com","dl-ssl.google.com","play-lh.googleusercontent.com",
"googleplay.com","android.clients.google.com","g.co","goo.gl",
"withgoogle.com","stitch.withgoogle.com","csp.withgoogle.com",
"labs.google","blog.google","ai.google.dev","cloud.google.com",
)
ANDROID=(
"mtalk.google.com","mtalk4.google.com","alt1-mtalk.google.com",
"android.apis.google.com","firebaseinstallations.googleapis.com",
"fcm.googleapis.com","gcm-http.googleapis.com",
"device-provisioning.googleapis.com","time.google.com",
"stun.l.google.com","connectivitycheck.gstatic.com",
"clients3.google.com","ocsp.pki.goog",
)
PROBES=(
"www.youtube.com","youtubei.googleapis.com","i.ytimg.com",
"rr1---sn-gxuo03g-ig3s.googlevideo.com","accounts.google.com",
"google.com","www.google.com","fonts.gstatic.com",
"jnn-pa.googleapis.com","yt3.ggpht.com","m.youtube.com",
"play.google.com","manifest.googlevideo.com",
)
# Strictly scoped to 1 CoreDNS /etc file; no subscriber identifier is emitted.
BLOCK=re.compile(r"(?ms)^[ \t]*template\s+IN\s+(\w+)\s+(\S+)\s*\{\s*\n(.*?)^[ \t]{4}\}")
MAP=re.compile(r"(?s)\bmap\s+\$ssl_preread_server_name\s+\$(\w+)\s*\{([^{}]*)\}")

def dns_templates(s):
    d={}
    for kind,zone,body in BLOCK.findall(s):
        matches=re.findall(r"(?m)^[ \t]*match[ \t]+([^ \t\r\n]+)",body)
        if not matches:matches=[".*"]
        result="EDGE89" if re.search(r"(?m)^[ \t]*answer\b[^\n]*\b89\.125\.90\.101\b",body) else (
            "RU188" if re.search(r"(?m)^[ \t]*answer\b[^\n]*\b188\.120\.254\.223\b",body) else
            ("NOERROR" if re.search(r"(?m)^[ \t]*rcode NOERROR\b",body) else "OTHER"))
        d.setdefault(kind,[]).append((zone,matches,result))
    return d
def route_dns(d,host,kind):
    hits=[]
    for zone,matches,value in d.get(kind,[]):
        for raw in matches:
            try:
                if re.fullmatch(raw,host+".",flags=re.I):
                    hits.append(value)
                    break
            except re.error: pass
    return sorted(set(hits))
def nginx_maps(s):
    maps=[]
    for name,body in MAP.findall(s):
        rules=[]
        for line in body.splitlines():
            line=line.split("#",1)[0].strip()
            if not line or not line.endswith(";"):continue
            parts=line[:-1].split(None,1)
            if len(parts)==2:rules.append(tuple(parts))
        maps.append((name,rules))
    return maps
def match_sni(rules,host):
    # Nginx map gives exact-string keys precedence over regex entries.
    for key,value in rules:
        if key.lower()==host:return value
    for key,value in rules:
        if not key.startswith("~"):continue
        expr=key[2:] if key.startswith("~*") else key[1:]
        try:
            if re.search(expr,host,re.I if key.startswith("~*") else 0):return value
        except re.error:pass
    for key,value in rules:
        if key=="default":return "DEFAULT:"+value
    return "NO_MATCH"
def route_class(s):
    if "15449" in s:return "GOOGLEPILOT"
    if s.startswith("DEFAULT:"):return "DEFAULT"
    if s.startswith("127.0.0.1:"):return "OTHER_LOCAL"
    if s.startswith("$ssl_preread_server_name:"):return "ORIGIN_SNI"
    if s.endswith(":443"):return "DIRECT_ORIGIN"
    return "OTHER"
def service_status():
    import subprocess
    for svc in ("nginx","mnebydns-dot","mnebydns-googlepilot","mnebydns-google-tcp-only-20261117"):
        v=subprocess.run(["systemctl","is-active",svc],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=5)
        print("SERVICE",svc,v.stdout.strip(),flush=True)
def tls_test(host):
    t=time.monotonic()
    try:
        with socket.create_connection(("127.0.0.1",443),timeout=7) as sock:
            with ssl.create_default_context().wrap_socket(sock,server_hostname=host) as tls:
                return "PASS",round((time.monotonic()-t)*1000),tls.version()
    except Exception as exc:
        return "FAIL",type(exc).__name__,""
def main():
    core=CORE.read_text()
    shared=SHARED.read_text()
    pilot=PILOT.read_text()
    d=dns_templates(core)
    sm=nginx_maps(shared)
    pm=nginx_maps(pilot)
    print("GOOGLE_AUDIT_CONFIG_COUNTS",json.dumps({
        "core_bytes":len(core),"dns_templates_total":sum(map(len,d.values())),
        "dns_A_templates":len(d.get("A",[])),
        "nginx_sni_maps":len(sm),"pilot_sni_maps":len(pm),
        "shared_google_map_found":any(n=="direct_mtproxy_backend" for n,_ in sm),
        "pilot_origin_map_found":any(n=="experimental_origin" for n,_ in pm),
    },sort_keys=True),flush=True)
    print("GOOGLE_AUDIT_CONTENTS_REDACTED=YES",flush=True)
    sr=next((r for n,r in sm if n=="direct_mtproxy_backend"),[])
    pr=next((r for n,r in pm if n=="experimental_origin"),[])
    counters={}
    problems=[]
    seen=set()
    for category,hosts in (("YOUTUBE",YOUTUBE),("GOOGLE",GOOGLE),("ANDROID_SYSTEM",ANDROID)):
        for h in hosts:
            if h in seen:continue
            seen.add(h)
            aa=route_dns(d,h,"A")
            other={kind:route_dns(d,h,kind) for kind in ("AAAA","HTTPS","SVCB","CNAME")}
            sni=match_sni(sr,h) if sr else "UNKNOWN_SHARED_MAP"
            pilot_sni=match_sni(pr,h) if pr else "UNKNOWN_PILOT_MAP"
            sc=route_class(sni)
            pc=route_class(pilot_sni)
            statuses=[]
            if "EDGE89" not in aa:statuses.append("NO_EDGE89_A")
            if sc not in ("GOOGLEPILOT","OTHER_LOCAL"):statuses.append("UNROUTED_SNI")
            if sc=="GOOGLEPILOT" and pc in ("DEFAULT","OTHER","NO_MATCH"):statuses.append("PILOT_DEFAULT_OR_UNKNOWN")
            if "EDGE89" in aa and any(v not in ("NOERROR",) for kind,vals in other.items() for v in vals):statuses.append("OTHER_RRTYPE_ROUTE")
            state="OK" if not statuses else "+".join(statuses)
            print("COVERAGE",category,h,"A="+(",".join(aa) or "NONE"),"SNI="+sc,
                  "PILOT="+(pc if sc=="GOOGLEPILOT" else "NOT_USED"),
                  "OTHER="+"/".join(k+":"+(",".join(other[k]) or "-") for k in other),
                  "STATE="+state,flush=True)
            key=category+"_"+state
            counters[key]=counters.get(key,0)+1
            if statuses and category=="YOUTUBE":problems.append(h+":"+state)
    service_status()
    for h in PROBES:
        a,b,c=tls_test(h)
        print("LOOPBACK_TCP_TLS",h,a,b,c,flush=True)
    print("GOOGLE_AUDIT_SUMMARY",json.dumps({"total_checked":len(seen),"counters":counters,
                  "youtube_mismatches":problems},sort_keys=True),flush=True)
    print("GOOGLE_AUDIT_READONLY_NO_CUSTOMER_RECORDS_PRINTED=true",flush=True)
if __name__=="__main__":main()
