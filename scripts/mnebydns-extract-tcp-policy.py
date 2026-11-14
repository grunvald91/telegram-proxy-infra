#!/usr/bin/env python3
"""Extract explicit domain admission rules from the DE TCP SNI map, read only."""
import hashlib,json,pathlib,re,sys
MAP_RE=re.compile(r'(?ms)^\s*map\s+\$ssl_preread_server_name\s+\$direct_mtproxy_backend\s*\{\s*\n(.*?)^\s*}\s*')
DOMAIN_RE=re.compile(r'(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$',re.I)
def extract(source):
    blocks=list(MAP_RE.finditer(source))
    if len(blocks)!=1:raise ValueError('Expected one explicit DE TCP SNI map')
    block=blocks[0].group(1)
    rules=[];hostnames=False;skipped=[]
    for line in block.splitlines():
        line=line.strip()
        if not line or line.startswith('#'):continue
        line=re.sub(r'\s+#.*$','',line).strip()
        if line=='hostnames;':hostnames=True;continue
        if not line.endswith(';'):raise ValueError('Unexpected multiline SNI map rule')
        fields=line[:-1].rsplit(None,1)
        if len(fields)!=2:raise ValueError('Unexpected SNI map directive')
        key,destination=fields
        if key=='default' or key in ('""',"''"):
            skipped.append('default_or_empty_sni');continue
        if key in ('include','volatile'):raise ValueError('Expanded SNI map required')
        if destination in ('127.0.0.1:1','0.0.0.0:1','""',"''"):
            skipped.append('explicit_reject');continue
        if key[0:1] in ('"',"'"):
            if len(key)<2 or key[-1]!=key[0]:raise ValueError('Unclosed quoted map key')
            key=key[1:-1].replace('\\\\','\\')
        if key.startswith('~*'):
            pattern=key[2:].strip();re.compile(pattern,re.I)
            rules.append({'kind':'regex_i','value':pattern})
        elif key.startswith('~'):
            pattern=key[1:].strip();re.compile(pattern)
            rules.append({'kind':'regex','value':pattern})
        elif key.startswith('*.') and DOMAIN_RE.fullmatch(key[2:]):
            rules.append({'kind':'subdomains','value':key[2:].lower()})
        elif key.startswith('.') and DOMAIN_RE.fullmatch(key[1:]):
            if not hostnames:raise ValueError('Leading-dot hostname without hostnames directive')
            rules.append({'kind':'suffix','value':key[1:].lower()})
        elif key.endswith('.*') and DOMAIN_RE.fullmatch(key[:-2]):
            rules.append({'kind':'prefix','value':key[:-2].lower()})
        elif DOMAIN_RE.fullmatch(key):
            rules.append({'kind':'exact','value':key.lower()})
        else:raise ValueError('Unsupported explicit SNI map key')
    if not rules:raise ValueError('No explicit domain rules in DE TCP map')
    unique=list({json.dumps(x,sort_keys=True):x for x in rules}.values())
    return {'schema':1,'source':'DE89 TCP direct_mtproxy_backend',
            'source_map_sha256':hashlib.sha256(block.encode()).hexdigest(),
            'rules':unique,'raw_rule_count':len(rules),'skipped':skipped}
if __name__=='__main__':
    path=pathlib.Path(sys.argv[1] if len(sys.argv)>1 else '/etc/nginx/nginx.conf')
    print('DE89_TCP_POLICY_JSON='+json.dumps(extract(path.read_text()),sort_keys=True,separators=(',',':')),flush=True)
