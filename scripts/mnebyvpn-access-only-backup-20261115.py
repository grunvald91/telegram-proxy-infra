#!/usr/bin/env python3
"""Safely export ONLY DNS names, WireGuard keys, certificates and user credentials.

Produces gzipped tar bytes on stdout. Must be piped directly to OpenSSL CMS
public-key encryption; NEVER redirect its output to an unencrypted file.
No network topology, proxy service configuration or deployment scripts exported.
"""
import datetime
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse

ROLE = sys.argv[1] if len(sys.argv)==2 else ""
if ROLE not in ("RU", "DE"):
    raise SystemExit("role must be RU or DE")
ROOTS = ["/etc/letsencrypt/archive", "/etc/mnebydns", "/etc/ssl/private",
         "/opt/mnebyvpn", "/etc/xray", "/etc/mtg", "/etc/telemt",
         "/etc/tproxy-server", "/etc/tproxy-server-ru"]
MAX_FILE=10*1024*1024
FILE_LIMIT=1800
counts = {"domains":0,"wg_secret_files":0,"cert_files":0,"credential_sources":0,"db_tables":0,"db_rows":0,"exported_files":0}
def warn(label):
    print("DATA_BACKUP_"+ROLE+"_"+label, file=sys.stderr, flush=True)
def secure_data(root,relative,contents):
    target=root/relative
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_bytes(contents if isinstance(contents,bytes) else contents.encode())
    target.chmod(0o600)
    counts["exported_files"]+=1
def norm_domain(s):
    s=s.strip().strip("*.").lower()
    if len(s)>253 or len(s)<4 or "." not in s or "/" in s or ":" in s:return None
    if not re.fullmatch(r"[a-z0-9*._-]+",s):return None
    if not re.search(r"\.[a-z]{2,}$",s):return None
    return s
def domain_tokens(value):
    # DNS policy literals only. Convert escaped and bracketed DNS dots.
    value=value.replace(r"\.",".").replace("[.]",".")
    found=set()
    for s in re.findall(r"(?<![\w.-])(?:[a-zA-Z0-9_-]+\.)+[A-Za-z]{2,}(?![\w.-])",value):
        n=norm_domain(s)
        if n:found.add(n)
    return found
def build_domains(root):
    domains=set()
    match_domains=set()
    p=pathlib.Path("/opt/mnebydns-dot/Corefile")
    if p.is_file():
        txt=p.read_text(errors="replace")
        for m in re.finditer(r"(?m)^\s*template\s+IN\s+(?:A|AAAA|CNAME|HTTPS|SVCB)\s+([^\s{]+)",txt):
            n=norm_domain(m.group(1))
            if n:domains.add(n)
        for m in re.finditer(r"(?m)^\s*match\s+(.+)$",txt):
            match_domains.update(domain_tokens(m.group(1)))
    # DNS policy is read only for domain literal strings, never IP routes.
    for base in ("/etc/mnebydns/personal-dot","/opt/mnebyvpn/private","/opt/mnebyvpn/shared"):
        p=pathlib.Path(base)
        if not p.is_dir():continue
        for path in p.glob("*.json"):
            if "policy" not in path.name.lower() and "domain" not in path.name.lower():continue
            if path.is_file() and path.stat().st_size<2_000_000:
                match_domains.update(domain_tokens(path.read_text(errors="replace")))
    combined=sorted(domains|match_domains)
    if ROLE=="DE" and len(combined)<100:
        raise RuntimeError("DNS_DOMAIN_INVENTORY_TOO_SMALL")
    secure_data(root,"dns/active_domains.txt","\n".join(combined)+"\n" if combined else "")
    secure_data(root,"dns/exact_host_templates.txt","\n".join(sorted(domains))+"\n")
    secure_data(root,"dns/wildcard_policy_domains.txt","\n".join(sorted(match_domains))+"\n")
    counts["domains"]=len(combined)
def wireguard(root):
    base=pathlib.Path("/etc/wireguard")
    allkeys={}
    if base.is_dir():
        for p in base.iterdir():
            if not p.is_file() or p.is_symlink() or p.stat().st_size>MAX_FILE:continue
            if p.suffix in (".private",".public") or p.name.endswith(".private") or p.name.endswith(".public"):
                secret=p.read_text(errors="replace").strip()
                if re.fullmatch(r"[A-Za-z0-9+/]{43}=",secret):
                    allkeys[p.name]={"raw_key":secret}
            elif "conf" in p.name or "wg" in p.name or "relay" in p.name:
                txt=p.read_text(errors="replace")
                keys=re.findall(r"(?mi)^\s*(PrivateKey|PublicKey|PresharedKey)\s*=\s*([A-Za-z0-9+/]{43}=)\s*$",txt)
                if keys:allkeys[p.name]={"keys":[{"kind":k,"value":v} for k,v in keys]}
    if not allkeys:raise RuntimeError("WG_KEY_MATERIAL_MISSING")
    secure_data(root,"wireguard/key_material_only.json",json.dumps(allkeys,indent=2,ensure_ascii=False)+"\n")
    counts["wg_secret_files"]=len(allkeys)
def certs(root):
    allowed_prefixes=[pathlib.Path("/etc/letsencrypt/archive"),
                      pathlib.Path("/etc/mnebydns/personal-dot"),
                      pathlib.Path("/opt/mnebyvpn/secrets"),
                      pathlib.Path("/opt/mnebyvpn/private"),
                      pathlib.Path("/etc/ssl/private")]
    items={}
    for base in allowed_prefixes:
        if not base.exists():continue
        try:
            iterator=base.rglob("*")
            for p in iterator:
                if len(items)>=FILE_LIMIT:raise RuntimeError("CERTIFICATE_FILE_LIMIT")
                if p.is_symlink() or not p.is_file():continue
                if p.suffix.lower() not in (".pem",".crt",".key",".p12",".pfx",".pub",".cer"):continue
                if p.stat().st_size>MAX_FILE:continue
                # avoid configs disguised as .key; only cert/key file formats, encrypted at source
                if str(p) in items:continue
                data=p.read_bytes()
                if not data:continue
                target="certificates/"+str(p).lstrip("/")
                secure_data(root,target,data)
                items[str(p)]=len(data)
        except PermissionError:
            continue
    if not items:raise RuntimeError("NO_CERTIFICATES_FOUND")
    counts["cert_files"]=len(items)
def credentials(root):
    # Preserve secret values and identifiers; don't include endpoint/route/network configs.
    files=[]
    for file in ("/opt/mnebyvpn/bot/web.env","/opt/mnebyvpn/bot/worker.env",
                 "/opt/mnebyvpn/bot/provisioner.key","/etc/xray/config.json",
                 "/etc/xray/CREDENTIALS.txt"):
        p=pathlib.Path(file)
        if p.is_file():files.append(p)
    for name in ("/etc/telemt","/etc/mtg","/etc/tproxy-server","/etc/tproxy-server-ru"):
        p=pathlib.Path(name)
        if p.is_dir():
            for f in p.iterdir():
                if f.is_file() and f.suffix in (".toml",".json",".env") and ".bak" not in f.name:
                    files.append(f)
    for name in ("/opt/mnebyvpn/private","/opt/mnebyvpn/secrets"):
        p=pathlib.Path(name)
        if p.is_dir():
            for f in p.glob("*"):
                if f.is_file() and f.suffix in (".key",".secret",".env",".token"):
                    files.append(f)
    keep=re.compile(r"(password|passphrase|private.?key|public.?key|preshared|api.?key|secret|token|uuid|client.?id|client.?secret|user|credential|bearer|auth|provision|short.?ids|access.?key|subscri|license|email)",re.I)
    records={}
    for p in files:
        if p.is_symlink() or p.stat().st_size>MAX_FILE:continue
        b=p.read_bytes()
        try:txt=b.decode()
        except UnicodeError:continue
        if p.suffix.lower()==".json":
            try:
                obj=json.loads(txt)
            except ValueError:obj=None
            collected=[]
            def walk(v,trail="",level=0):
                if level>14:return
                if isinstance(v,dict):
                    for k,val in v.items():
                        key=str(k)
                        if keep.search(key):
                            if isinstance(val,(str,int,float,bool)) and str(val):
                                collected.append({"field":trail+"."+key,"value":val})
                            elif isinstance(val,list) and len(val)<500:
                                # User credentials may be nested in client arrays.
                                for i,item in enumerate(val):walk(item,trail+"."+key+"["+str(i)+"]",level+1)
                            elif isinstance(val,dict):walk(val,trail+"."+key,level+1)
                        elif isinstance(val,(dict,list)):
                            walk(val,trail+"."+key,level+1)
                elif isinstance(v,list):
                    for i,item in enumerate(v[:1000]):walk(item,trail+"["+str(i)+"]",level+1)
            if obj is not None:
                walk(obj)
                if collected:records[str(p)]=collected
                continue
        assignments=[]
        for line in txt.splitlines():
            m=re.match(r'^\s*(?:export\s+)?([A-Za-z0-9_.$-]+)\s*[=:]\s*(.*?)\s*,?\s*$',line)
            if not m:continue
            key=m.group(1);value=m.group(2).strip().strip('"').strip("'")
            if not keep.search(key) or not value or len(value)>30000:continue
            if "url" in key.lower() and ("://" in value or "@" in value):
                parsed=urllib.parse.urlsplit(value)
                if parsed.password:
                    assignments.append({"name":key+"_PASSWORD","value":urllib.parse.unquote(parsed.password)})
                if parsed.username:
                    assignments.append({"name":key+"_USERNAME","value":urllib.parse.unquote(parsed.username)})
                continue
            assignments.append({"name":key,"value":value})
        if p.name.endswith(".key") or p.suffix in (".token",".secret"):
            if len(b)<8192:assignments.append({"name":"opaque_credential","value":txt.strip()})
        if assignments:records[str(p)]=assignments
    if records:
        secure_data(root,"credentials/service_and_client_secrets_only.json",json.dumps(records,ensure_ascii=False,indent=2)+"\n")
    counts["credential_sources"]=len(records)
def postgres_user_data(root):
    if ROLE!="RU":return
    query="SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename"
    command=["docker","exec","mnebyvpn-stage-postgres","psql","-XAt","-v","ON_ERROR_STOP=1",
             "-U","mnebyvpn_stage","-d","mnebyvpn_stage","-c",query]
    result=subprocess.run(command,capture_output=True,timeout=22)
    if result.returncode:raise RuntimeError("USER_DATABASE_UNAVAILABLE")
    tables=set(result.stdout.decode().splitlines())
    allowed={
       "accounts","billing_plans","checkout_requests","dns_mtproxy_bonus_credentials",
       "entitlement_credits","entitlements","order_referrals","order_renewals","order_terms",
       "orders","payment_delivery_receipts","personal_dns_credentials",
       "personal_dns_query_reservations","personal_dns_query_windows","pricing_drafts",
       "provider_captures","quota_usage_events","referral_invites","telegram_invoice_dispatch",
       "trial_device_claims","trial_grants","trial_offers","verified_payment_events",
       "vpn_expiry_reminders","vpn_operator_test_grants","vpn_purchase_notifications",
       "vpn_subscription_links","vpn_trial_ready_notifications",
       "web_email_codes","web_guest_claims","web_review_login","website_support_tickets"
    }
    selected=sorted(allowed&tables)
    if len(selected)<12 or "accounts" not in selected or "vpn_subscription_links" not in selected or "personal_dns_credentials" not in selected:
        raise RuntimeError("ESSENTIAL_USER_ACCESS_TABLES_NOT_FOUND")
    manifest=[]
    for table in selected:
        q='COPY (SELECT row_to_json(t) FROM public."'+table+'" t) TO STDOUT'
        proc=subprocess.run(command[:-1]+[q],capture_output=True,timeout=45)
        if proc.returncode:
            raise RuntimeError("USER_TABLE_EXPORT_FAILED_"+table)
        contents=proc.stdout
        secure_data(root,"users/postgresql/"+table+".jsonl",contents)
        rows=contents.count(b"\n")
        counts["db_rows"]+=rows
        manifest.append({"table":table,"rows":rows})
    # The DNS-admin table may carry routing IPs. Export ONLY domain/status columns.
    if "dns_admin_domains" in tables:
        q='COPY (SELECT json_build_object('+"'domain',domain,'status',status"+') FROM public.dns_admin_domains) TO STDOUT'
        proc=subprocess.run(command[:-1]+[q],capture_output=True,timeout=22)
        if proc.returncode:raise RuntimeError("DNS_ADMIN_DOMAIN_EXPORT_FAILED")
        secure_data(root,"dns/user_submitted_domains.jsonl",proc.stdout)
        manifest.append({"table":"dns_admin_domains_domain_names_only","rows":proc.stdout.count(b"\n")})
    secure_data(root,"users/table_row_counts.json",json.dumps(manifest,indent=2)+"\n")
    counts["db_tables"]=len(selected)
def main():
    with tempfile.TemporaryDirectory(prefix="mnebyvpn-access-only-",dir="/run") as d:
        root=pathlib.Path(d)
        os.chmod(root,0o700)
        build_domains(root)
        wireguard(root)
        certs(root)
        credentials(root)
        postgres_user_data(root)
        if ROLE=="RU" and counts["db_rows"]<=0:raise RuntimeError("USER_DATA_EXPORT_EMPTY")
        secure_data(root,"README.txt","MNEBYVPN access-only export (UTC 2026-11-15)\n"
            "Contains domain names, WG key material, TLS certificates and keys, user access records and application credentials.\n"
            "Does NOT include network design, IP routes, firewall, server setup, deployment scripts or proxy configurations.\n")
        warn("COUNTS="+json.dumps(counts,sort_keys=True))
        with tarfile.open(fileobj=sys.stdout.buffer,mode="w|gz",format=tarfile.PAX_FORMAT) as archive:
            for path in sorted(root.rglob("*")):
                if not path.is_file() or path.is_symlink():continue
                arcname=path.relative_to(root)
                archive.add(str(path),arcname=str(arcname),recursive=False)
if __name__=="__main__":
    try:main()
    except Exception as e:
        warn("FAILED="+type(e).__name__+":"+str(e)[:90])
        raise SystemExit(2)
