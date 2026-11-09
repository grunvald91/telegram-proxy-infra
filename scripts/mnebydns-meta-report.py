#!/usr/bin/env python3
"""Read-only aggregate MNEBYDNS Meta trial report from systemd journals.

Run on RU and DE after a real phone test; prints no IPs, hostnames, tokens,
packets, TLS bytes or credentials. The packet observer emits cumulative counters.
GitHub Actions logs a PRE_PHONE baseline before synthetic DNS cutover; compare
that baseline with the latest report rather than counting CI probes as phones.
"""
from __future__ import annotations
import argparse
import collections
import re
import subprocess

KEYS_OBSERVER=('tcp_syn_in','tcp_synack_out','tcp_clienthello_in',
               'tcp_clienthello_meta_in','tcp_clienthello_other_or_ech_in',
               'tcp_payload_packets_in','tcp_payload_packets_out',
               'tcp_payload_bytes_in','tcp_payload_bytes_out',
               'tcp_reset_in','tcp_reset_out','udp_in','udp_out',
               'udp_quic_v1_initial_in','udp_other_long_header_in','unparsed')
KEYS_QUIC=('active','admitted','rejected','expired','resolve_error','rx',
           'to_upstream','upstream_rx','client_tx','oversize','undersize',
           'peer_drop','overflow','socket_error','emsgsize')
KEYS_META=('status','sent_to_ru','recv_from_ru','sent_to_origin',
           'recv_from_origin','connect','duration')


def journal(unit):
    try:
        result=subprocess.run(['journalctl','-u',unit,'--no-pager','-o','cat'],
                              capture_output=True,text=True,timeout=10)
        if result.returncode != 0:return []
        return result.stdout.splitlines()
    except (OSError,subprocess.TimeoutExpired):return []


def get_last_counts(lines, prefix, keys):
    rows=[s for s in lines if s.startswith(prefix)]
    if not rows:return None
    body=rows[-1][len(prefix):]
    result={}
    if prefix.endswith('active='):
        active=re.match(r'^(\d+)',body)
        if active:result['active']=int(active.group(1))
    for key in keys:
        m=re.search(r'(?:^|\s)'+re.escape(key)+r'=(\d+)(?:\s|$)',body)
        if m:result[key]=int(m.group(1))
    return result


def parse_nginx_meta(lines):
    rows=[s for s in lines if s.startswith('META_DE ')]
    stats=collections.Counter()
    for line in rows:
        fields=dict(re.findall(r'\b([a-z_]+)=([^\s]+)',line))
        status=fields.get('status','unknown')
        stats['sessions']+=1
        if status in ('200','201'):stats['status_ok']+=1
        else:stats['status_other']+=1
        values={}
        for k in ('sent_to_ru','recv_from_ru','sent_to_origin','recv_from_origin'):
            try:values[k]=max(0,int(fields[k]))
            except (KeyError,ValueError):values[k]=0
            stats[k]+=values[k]
        if values['recv_from_origin']>0:
            stats['sessions_with_origin_reply']+=1
        else:stats['sessions_without_origin_reply']+=1
    return stats


def report(role,runid,journal_getter=journal):
    assert role in ('ru','de') and re.fullmatch(r'\d{9,13}',runid)
    unit=f'mnebydns-meta-observe-{role}-{runid}.service'
    observer=get_last_counts(journal_getter(unit),f'meta_stage_{role}_FINAL_',KEYS_OBSERVER)
    if observer is None:
        observer=get_last_counts(journal_getter(unit),f'meta_stage_{role}_WINDOW_',KEYS_OBSERVER)
    quic=get_last_counts(journal_getter(f'mnebydns-meta-quic-{role}-{runid}.service'),
                         f'meta_quic_{role}_active=',KEYS_QUIC)
    meta=None
    if role=='de':meta=parse_nginx_meta(journal_getter(f'mnebydns-meta-pilot-{runid}.service'))
    data={'observer':observer,'quic':quic,'meta_tcp':meta}
    prefix=f'meta_report_{role}_{runid}_'
    for area,result in data.items():
        if result is None:
            print(prefix+area+'_journal_missing_or_no_samples=true',flush=True)
            continue
        for k,v in sorted(result.items()):
            print(prefix+area+'_'+k+'='+str(v),flush=True)
    print(prefix+'raw_payloads_IPs_and_SNI_not_emitted=true',flush=True)
    print(prefix+'compare_with_PRE_PHONE_baseline_required=true',flush=True)
    return data


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--role',choices=('ru','de'),required=True)
    p.add_argument('--run-id',required=True)
    args=p.parse_args()
    report(args.role,args.run_id)

if __name__=='__main__':main()