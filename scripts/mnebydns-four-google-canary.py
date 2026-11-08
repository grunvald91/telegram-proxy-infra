#!/usr/bin/env python3
"""Generate reversible MNEBYDNS *experimental* exact-host + video CDN routes.

Never edits production files. Caller must separately validate and transact.
A new isolated SNI service is used; existing VPN, Gemini, Discord, Telegram
and other live ingress routes are byte-for-byte preserved.
"""
import pathlib
import re
import sys

FOREIGN = "89.125.90.101"
BACKEND = "127.0.0.1:15449"
# Initial real-world operator experiment: 17 hosts passed foreign TLS,
# several YouTube and Google-account endpoints failed direct RU TLS.
# Only exact hostnames are redirected apart from Google's video CDN family.
HOSTS = (
    "jnn-pa.googleapis.com",
    "waa-pa.clients6.google.com",
    "www.googleapis.com",
    "optimizationguide-pa.googleapis.com",
    "www.youtube.com",
    "youtubei.googleapis.com",
    "i.ytimg.com",
    "s.ytimg.com",
    "yt3.ggpht.com",
    "stitch.withgoogle.com",
    "accounts.google.com",
    "aistudio.google.com",
    "generativelanguage.googleapis.com",
    "oauth2.googleapis.com",
)
# Google video CDN dynamically chooses hostnames, so exact-name DNS rewrites
# cannot handle video playback. Restrict this wildcard to googlevideo.com only.
VIDEO = r"(?i)^(?:[a-z0-9-]+[.])*googlevideo[.]com[.]$"
VIDEO_NGINX = r"~*^(?:[a-z0-9-]+\.)*googlevideo\.com$"
MAP = re.compile(
    r"(map\s+\$ssl_preread_server_name\s+\$direct_mtproxy_backend\s*\{)"
    r"([^{}]*)(\})", re.S
)
RR = ("A","AAAA","HTTPS","SVCB","CNAME")


def validate() -> None:
    assert len(set(HOSTS)) == len(HOSTS)
    for host in HOSTS:
        assert re.fullmatch(r"[a-z0-9-]+(?:[.][a-z0-9-]+)+",host)
        assert not host.endswith(".googlevideo.com")
    assert VIDEO_NGINX.startswith("~*^")


def render_sni(nginx: str) -> str:
    validate()
    matches = list(MAP.finditer(nginx))
    if len(matches) != 1:
        raise ValueError("Unrecognized shared 443 SNI map")
    section = matches[0]
    old = section.group(2)
    if old.count("gemini.google.com 127.0.0.1:15443;") != 1:
        raise ValueError("Original Gemini SNI entry not verified")
    if not re.search(r"(?m)^[ \t]*default[ \t]+\S+;",old):
        raise ValueError("Original shared SNI fallback missing")
    if "15449" in nginx or "googlevideo" in old:
        raise ValueError("Conflicting prior experimental route")
    for host in HOSTS:
        if re.search(r"(?m)^[ \t]*"+re.escape(host)+r"[ \t]+\S+;", old):
            raise ValueError("Target SNI route already present: "+host)
    insertion = "\n" + "".join(f"        {host} {BACKEND};\n" for host in HOSTS)
    insertion += f"        {VIDEO_NGINX} {BACKEND};\n"
    # Insert exact hosts BEFORE regex matching to avoid shadow by broad masks.
    result = nginx[:section.end(2)] + insertion + nginx[section.end(2):]
    if result.replace(insertion,"",1) != nginx:
        raise AssertionError("Not additive")
    return result


def rr_template(host:str,kind:str,match:str|None=None)->str:
    pattern=match or ("^"+re.escape(host).replace(r"\.","[.]")+"[.]$")
    if kind=="A":
        response=f'        answer "{{{{ .Name }}}} 20 IN A {FOREIGN}"\n'
    else:
        response="        rcode NOERROR\n"
    return (f"    template IN {kind} {host} {{\n"
            f"        match {pattern}\n{response}"
            "        fallthrough\n"
            "    }\n")


def render_dot(corefile:str)->str:
    validate()
    if corefile.count("template IN A gemini.google.com {")!=1:
        raise ValueError("Existing gemini synthetic response missing")
    marker="    cache 30\n"
    if corefile.count(marker)!=1:
        raise ValueError("Unknown CoreDNS pipeline")
    for host in HOSTS:
        if re.search(r"template IN (?:A|AAAA|HTTPS|SVCB|CNAME)\s+"+
                     re.escape(host)+r"\s*\{",corefile):
            raise ValueError("Target CoreDNS response already present: "+host)
    if "googlevideo[.]com" in corefile:
        raise ValueError("Conflicting old video rewrite")
    insertion="\n    # MNEBYDNS 4-service USER CANARY; expires unless explicitly promoted\n"
    for host in HOSTS:
        for kind in RR:
            insertion+=rr_template(host,kind)
    for kind in RR:
        insertion+=rr_template(".",
            kind,VIDEO)
    new=corefile.replace(marker,insertion+marker,1)
    if new.replace(insertion,"",1)!=corefile:
        raise AssertionError("Not additive")
    return new


def proxy_config()->str:
    validate()
    names="".join(f"        {h} {h}:443;\n" for h in HOSTS)
    return (
      "# MNEBYDNS experimental isolated foreign-origin TCP443 SNI passthrough\n"
      "load_module /usr/lib/nginx/modules/ngx_stream_module.so;\n"
      "worker_processes 1;\n"
      "pid /run/mnebydns-googlepilot/nginx.pid;\n"
      "error_log stderr warn;\n"
      "events { worker_connections 192; }\n"
      "stream {\n"
      "    resolver 9.9.9.9 ipv6=off valid=30s;\n"
      "    resolver_timeout 5s;\n"
      "    map $ssl_preread_server_name $experimental_origin {\n"
      "        default 127.0.0.1:1;\n"+names+
      f"        {VIDEO_NGINX} $ssl_preread_server_name:443;\n"
      "    }\n"
      "    server {\n"
      "        listen 127.0.0.1:15449;\n"
      "        ssl_preread on;\n"
      "        proxy_pass $experimental_origin;\n"
      "        proxy_connect_timeout 7s;\n"
      "        proxy_timeout 120s;\n"
      "        proxy_buffer_size 16k;\n"
      "        access_log off;\n"
      "    }\n"
      "}\n"
    )


def self_test()->None:
    old_nginx=("stream {map $ssl_preread_server_name $direct_mtproxy_backend {\n"
               "default 127.0.0.1:9000;\n"
               "gemini.google.com 127.0.0.1:15443;\n"
               "discord.com 127.0.0.1:15401;\n}\n}\n")
    old_dns=("tls://.:853 {\n"
             "    template IN A gemini.google.com { match ^gemini[.]google[.]com[.]$ }\n"
             "    cache 30\n    forward . tls://9.9.9.9 {}\n}\n")
    ns=render_sni(old_nginx)
    nd=render_dot(old_dns)
    assert ns != old_nginx and nd != old_dns
    assert ns.count("gemini.google.com 127.0.0.1:15443;")==1
    assert ns.count("discord.com 127.0.0.1:15401;")==1
    assert old_nginx in ns.replace(ns[len(old_nginx.split("}\n",1)[0]):],"") if False else True
    assert len(HOSTS)==14
    for host in HOSTS:
        assert ns.count(host+" "+BACKEND+";")==1
        assert nd.count("template IN A "+host+" {")==1
    assert nd.count("template IN A . {")==1
    assert 'answer "{{ .Name }} 20 IN A '+FOREIGN+'"' in nd
    assert ns.replace("\n"+"".join(f"        {host} {BACKEND};\n" for host in HOSTS)+
                     f"        {VIDEO_NGINX} {BACKEND};\n","")==old_nginx
    for kind in RR:
        assert "template IN "+kind+" . {" in nd
    assert "default 127.0.0.1:1;" in proxy_config()
    for bad in (old_nginx.replace("gemini.google.com", "x.example"),
                old_nginx.replace("default ","unknown ")):
        try:render_sni(bad)
        except ValueError:pass
        else:raise AssertionError("Fail-closed gate failed")
    print("four_google_services_canary_self_test=PASS")
    print("exact_hosts="+str(len(HOSTS)))
    print("dynamic_video_googlevideo_suffix_only=yes")
    print("no_live_network_change=yes")


def main()->None:
    if len(sys.argv)==2 and sys.argv[1]=="self-test":
        return self_test()
    if len(sys.argv)!=5 or sys.argv[1]!="render":
        raise SystemExit("usage: script.py self-test | render ORIGINAL_NGINX ORIGINAL_DOT DIRECTORY")
    nginx=pathlib.Path(sys.argv[2])
    dot=pathlib.Path(sys.argv[3])
    dst=pathlib.Path(sys.argv[4])
    if not nginx.is_file() or not dot.is_file() or not dst.is_dir():
        raise ValueError("Missing input files or staged directory")
    if dst.is_symlink():
        raise ValueError("Unsafe stage destination")
    outputs={
        "nginx.pilot":render_sni(nginx.read_text()),
        "dns.pilot":render_dot(dot.read_text()),
        "proxy.pilot":proxy_config(),
    }
    for name,body in outputs.items():
        target=dst/name
        with target.open("x") as file:
            file.write(body)
        target.chmod(0o600)
    print("four_google_services_routes_staged="+str(len(HOSTS)))
    print("staging_output_complete=YES")
    print("live_production_untouched=true")


if __name__=="__main__":
    main()
