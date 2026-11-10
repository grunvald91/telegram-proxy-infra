#!/usr/bin/env python3
"""Read-only: identify which safety predicate rejects Antigravity exact-host routes."""
import importlib.util
from pathlib import Path
import traceback

root=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("owner_dns",root/"mnebydns-owner-domain-controller-20261110.py")
owner=importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)
hosts=(
 "antigravity.google",
 "daily-cloudcode-pa.googleapis.com",
 "aicode.googleapis.com",
 "accounts.google.com",
 "oauth2.googleapis.com",
 "generativelanguage.googleapis.com",
 "cloudcode-pa.googleapis.com",
 "antigravity-pa.googleapis.com",
 "antigravity.googleapis.com",
 "businessaicode.googleapis.com",
 "aiplatform.googleapis.com",
 "discoveryengine.googleapis.com",
)
def main():
    if not owner.live_checkpoint_unchanged():
        print("diagnostic_live_baseline=DRIFT (will not modify)",flush=True)
    else:print("diagnostic_live_baseline=STABLE",flush=True)
    core=owner.ssh("de","cat /opt/mnebydns-dot/Corefile")
    nginx=owner.ssh("de","cat /etc/nginx/nginx.conf")
    for host in hosts:
        print("diagnostic_domain="+host,flush=True)
        for kind,func,arguments in (
          ("core",owner._render.core_add,(core,host)),
          ("nginx",owner._render.nginx_add,(nginx,host,"93.184.215.14")),
        ):
            try:
                func(*arguments)
                print("diagnostic_"+kind+"=OK",flush=True)
            except Exception as exc:
                msg=str(exc).replace("\n"," ")[:160]
                print("diagnostic_"+kind+"="+type(exc).__name__+": "+msg,flush=True)
    print("diagnostic_server_files_modified=false",flush=True)

if __name__=="__main__":main()
