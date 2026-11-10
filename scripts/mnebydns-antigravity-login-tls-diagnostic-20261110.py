#!/usr/bin/env python3
"""Read-only TLS comparison for one failing accounts.google.com route."""
from __future__ import annotations
import importlib.util
import re
import shlex
from pathlib import Path

p=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("owner",p/"mnebydns-owner-domain-controller-20261110.py")
owner=importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)
host="accounts.google.com"
py="""
import socket,ssl
host='accounts.google.com'
edge='89.125.90.101'
for dest in (edge,host):
    print('tls_destination_type='+('MNEBY_EDGE' if dest==edge else 'ORIGIN_PUBLIC'),flush=True)
    try:
        with socket.create_connection((dest,443),timeout=9) as raw:
            raw.settimeout(9)
            with ssl.create_default_context().wrap_socket(raw,server_hostname=host) as tls:
                print('tls_verified=true tls_version='+str(tls.version()),flush=True)
    except Exception as ex:
        print('tls_verified=false exception='+type(ex).__name__+':'+str(ex).replace(chr(10),' ')[:220],flush=True)
"""
def main():
    src=owner.ssh("de","cat /etc/nginx/nginx.conf")
    m=re.search(r"(?m)^\s*accounts[.]google[.]com\s+(\S+);",src)
    print("accounts_nginx_exact_map="+(m.group(1) if m else "NONE"),flush=True)
    script="python3 -c "+shlex.quote(py)
    for role in ("de","ru"):
        print("accounts_probe_from="+role,flush=True)
        print(owner.ssh(role,script,55),flush=True)
    print("accounts_diagnostic_readonly=true",flush=True)
if __name__=="__main__":main()
