#!/usr/bin/env python3
"""Check the entire copied TCP map, family coverage and DNS name boundaries."""
import importlib.util,pathlib,re,sys
sys.dont_write_bytecode=True
root=pathlib.Path(__file__).resolve().parent

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m)
    return m

relay=module('copied_policy_relay',root/'mnebydns-youtube-quic.py')
extractor=module('tcp_policy_extractor',root/'mnebydns-extract-tcp-policy.py')
rules=relay.TCP_ALLOWLIST_RULES
assert len(rules)==288
assert len(set(rules))==len(rules)
assert sum(k=='exact' for k,v in rules)==286
assert sum(k in ('regex','regex_i') for k,v in rules)==2
families=[]
prefix=r'^(?:[a-z0-9-]+\.)*(?:'
for kind,value in rules:
    if kind=='exact':
        assert relay.allowed(value),value
    elif kind in ('regex','regex_i'):
        # The current live map uses two explicit anchored family expressions.
        # Check every family, including base and nested subdomains.
        assert value.startswith(prefix) and value.endswith(')$'),value
        for item in value[len(prefix):-2].split('|'):
            name=item.replace(r'\.','.').replace(r'\-','-')
            assert '\\' not in name and re.fullmatch(r'[a-z0-9.-]+',name),name
            families.append(name)
            for host in (name,'probe-sub.'+name,'a.b.'+name):
                assert relay.allowed(host),host
            assert not relay.allowed(name+'.outside.invalid'),name
            assert not relay.allowed('unrelated-prefix'+name),name
    else:raise AssertionError('Unexpected rule kind in current live copy')
for host in ('example.org','evilgoogle.com','evilgoogleapis.com','google.com.evil.org',
             'gstatic.com.evil.org','openai.com.outside.invalid','127.0.0.1','10.66.77.1',
             'localhost','foo..google.com','bad_.google.com','-bad.google.com',
             'google.com:443','https://google.com','GOOGLE.COM'):
    assert not relay.allowed(host),host
# Preserve wildcard and regex type semantics in the read-only extractor.
fixture='stream {\nmap $ssl_preread_server_name $direct_mtproxy_backend {\n default 127.0.0.1:9443;\n hostnames;\n example.com 127.0.0.1:15449;\n .example.net 127.0.0.1:15449;\n *.example.org 127.0.0.1:15449;\n api.* 127.0.0.1:15449;\n ~*^a\\.example\\.com$ 127.0.0.1:15449;\n blocked.example 127.0.0.1:1;\n}\n}\n'
p=extractor.extract(fixture)
assert [r['kind'] for r in p['rules']]==['exact','suffix','subdomains','prefix','regex_i']
assert 'explicit_reject' in p['skipped']
for bad in (fixture.replace('example.com 127.0.0.1:15449;','include /tmp/unknown.conf;'),
            fixture.replace(' hostnames;','')):
    try:extractor.extract(bad)
    except ValueError:pass
    else:raise AssertionError('Unsupported or ambiguous map accepted')
print('COPIED_TCP_EXACT_DOMAINS=286')
print('COPIED_TCP_REGEX_RULES=2')
print('COPIED_TCP_DOMAIN_FAMILIES='+str(len(families)))
print('COPIED_TCP_ALL_RULES_AND_NESTED_SUBDOMAINS=PASS')
print('COPIED_TCP_LOOKALIKE_IP_AND_UNLISTED_DENIAL=PASS')
print('COPIED_TCP_EXTRACTOR_CONTROL_AND_WILDCARD_SEMANTICS=PASS')
