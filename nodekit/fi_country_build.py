#!/usr/bin/env python3
"""Build a versioned FI runtime; keep original modules for rollback."""
from pathlib import Path
import sys
import os
import py_compile

MODULES=("fi_dns_ssh_stage.py","fi_dns_origin_canary.py","fi_dns_guarded_ingress.py",
"fi_dns_highwater.py","fi_dns_signed_grants.py","fi_dns_meter_rpc.py","fi_enrollment_ssh.py",
"fi_dns_reverse_channel.py","fi_dns_ssh_bridge.py","fi_dns_metered_dot.py","fi_dns_tls_session.py",
"fi_shared_routes.py","fi_routed_runtime.py","fi_routed_probe.py")

def convert(text):
    return text.replace("fi.dns.mnebyvpn.site","fi.mnebyvpn.site").replace(r"fi\.dns\.mnebyvpn\.site",r"fi\.mnebyvpn\.site")

def once(text,old,new):
    if text.count(old)!=1:raise ValueError("unexpected_source_contract")
    return text.replace(old,new)

def build(src,dst):
    os.umask(0o077)
    dst.mkdir(mode=0o700)
    for name in MODULES:
        text=convert((src/name).read_text())
        if name=="fi_dns_ssh_stage.py":
            text=once(text,'FI_RUNTIME=Path("/opt/mnebyvpn-fi-dns-node")','FI_RUNTIME=Path("/opt/mnebyvpn-fi-dns-country-v2")')
        if name=="fi_routed_runtime.py":
            text=once(text,'CONFIG=STATE/"RoutedCorefile"','CONFIG=STATE/"CountryRoutedCorefile"')
            text=once(text,'MARKER=STATE/"routed-dataplane.enable"','MARKER=STATE/"country-dataplane.enable"')
            text=once(text,'b"fi-dns-routed-v2\\n"','b"fi-dns-country-v2\\n"')
            # Keep validation of the original staged bundle unchanged.
            text=once(text,'str(REGIONAL_TLS/"fullchain.pem")+" "+str(REGIONAL_TLS/"privkey.pem")','str(FI_ROOT/"fi-regional-tls/fullchain.pem")+" "+str(FI_ROOT/"fi-regional-tls/privkey.pem")')
            text=once(text,'candidate.replace("tls://.:18855 {","tls://.:8853 {").encode()','country_corefile(candidate.replace("tls://.:18855 {","tls://.:8853 {").encode())')
            text=once(text,'def atomic_snapshot(path,raw):','''def country_corefile(original):
    old=str(FI_ROOT/"fi-regional-tls").encode()+b"/"
    new=str(REGIONAL_TLS).encode()+b"/"
    require(original.count(old)==2,"old_tls_path_count")
    return original.replace(old,new)

def atomic_snapshot(path,raw):''')
        if name=="fi_dns_origin_canary.py":
            text=once(text,'units=("mnebyvpn-fi-dns-private.service","mnebyvpn-fi-dns-routed.service")','units=("mnebyvpn-fi-dns-country.service",)')
            text=once(text,'("RoutedCorefile" if unit.endswith("-routed.service") else "PrivateCorefile")','"CountryRoutedCorefile"')
        if "fi.dns.mnebyvpn.site" in text or r"fi\.dns\.mnebyvpn\.site" in text:
            raise ValueError("obsolete_fi_hostname_in_runtime")
        (dst/name).write_text(text)
    (dst/"fi_regional_cert_stage.py").write_text((src/"fi_country_cert_stage.py").read_text())
    for file in dst.glob("*.py"):
        py_compile.compile(str(file),doraise=True)
        file.chmod(0o600)

if __name__=="__main__":build(Path(sys.argv[1]),Path(sys.argv[2]))
