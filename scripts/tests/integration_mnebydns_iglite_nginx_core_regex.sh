#!/usr/bin/env bash
# Offline, real nginx and Go RE2 syntax checks for exact Instagram Lite pilot.
# Runs only on disposable GitHub Actions runner, NEVER production hosts.
set -Eeuo pipefail
cd "$(dirname "$0")/../.."
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
python3 - "$tmp" <<'PY'
import importlib.util
from pathlib import Path
import sys
spec=importlib.util.spec_from_file_location("lite","scripts/mnebydns_iglite_route_render_20261111.py")
lite=importlib.util.module_from_spec(spec);spec.loader.exec_module(lite)
core="""tls://.:853 {
    template IN A gemini.google.com { match ^gemini[.]google[.]com[.]$ }
    cache 30
}
"""
nginx="""load_module /usr/lib/nginx/modules/ngx_stream_module.so;
worker_processes 1;
pid /tmp/mnebydns-iglite-nginx-syntax.pid;
events { worker_connections 32; }
stream {
    map $ssl_preread_server_name $direct_mtproxy_backend {
        default 127.0.0.1:9443;
    }
    server {
        listen 127.0.0.1:18443;
        ssl_preread on;
        proxy_pass $direct_mtproxy_backend;
    }
}
"""
new_core,new_nginx=lite.render(core,nginx,"157.240.0.160")
assert lite.m.core_remove(new_core,lite.HOST)==core
assert lite.m.nginx_remove(new_nginx,lite.HOST)==nginx
p=Path(sys.argv[1])
(p/"nginx.conf").write_text(new_nginx)
(p/"Corefile").write_text(new_core)
PY
nginx -t -c "$tmp/nginx.conf"
echo "iglite_offline_nginx_actual_syntax=PASS"
cat > "$tmp/core_regex.go" <<'GO'
package main
import ("bufio";"fmt";"os";"regexp";"strings")
func main(){
    f,e:=os.Open(os.Args[1]);if e!=nil{panic(e)};defer f.Close()
    s:=bufio.NewScanner(f);count:=0
    for s.Scan(){
        line:=strings.TrimSpace(s.Text())
        if !strings.HasPrefix(line,"match ^iglite"){continue}
        pat:=strings.TrimPrefix(line,"match ")
        re,e:=regexp.Compile(pat);if e!=nil{panic(e)}
        if !re.MatchString("iglite-z.instagram.com."){panic("host does not match")}
        for _,name:=range []string{"www.instagram.com.","evil.iglite-z.instagram.com.","iglite-z.instagram.com.evil."}{
            if re.MatchString(name){panic("unexpected wildcard match "+name)}
        }
        count++
    }
    if e:=s.Err();e!=nil{panic(e)}
    if count!=5{panic(fmt.Sprintf("got %d matching DNS patterns, expected five",count))}
    fmt.Println("iglite_offline_golang_regexp_exact_host=PASS")
}
GO
go run "$tmp/core_regex.go" "$tmp/Corefile"
echo "iglite_offline_no_live_change=PASS"
