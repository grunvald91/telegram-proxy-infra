#!/usr/bin/env python3
"""Synthetic report parser regression, no live user journal."""
from __future__ import annotations
import contextlib,importlib.util,io,pathlib
spec=importlib.util.spec_from_file_location('meta_report',pathlib.Path(__file__).with_name('mnebydns-meta-report.py'))
assert spec and spec.loader
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
run='12345678901'
lines={
 'mnebydns-meta-observe-ru-'+run+'.service':[
  'meta_stage_ru_WINDOW_tcp_syn_in=3 meta_stage_ru_WINDOW_tcp_clienthello_meta_in=2 meta_stage_ru_WINDOW_udp_in=5',
  'meta_stage_ru_FINAL_tcp_syn_in=4 meta_stage_ru_FINAL_tcp_clienthello_meta_in=3 meta_stage_ru_FINAL_udp_in=10'],
 'mnebydns-meta-quic-ru-'+run+'.service':[
  'meta_quic_ru_active=2 admitted=5 rx=10 to_upstream=8 upstream_rx=0 client_tx=0 emsgsize=1'],
 'mnebydns-meta-observe-de-'+run+'.service':['meta_stage_de_WINDOW_tcp_syn_in=2 meta_stage_de_WINDOW_tcp_payload_packets_out=1'],
 'mnebydns-meta-quic-de-'+run+'.service':['meta_quic_de_active=2 admitted=4 upstream_rx=3 client_tx=3'],
 'mnebydns-meta-pilot-'+run+'.service':[
  'META_DE status=200 sent_to_ru=248 recv_from_ru=550 sent_to_origin=550 recv_from_origin=248 connect=0.12 duration=0.55',
  'META_DE status=502 sent_to_ru=0 recv_from_ru=550 sent_to_origin=550 recv_from_origin=0 connect=- duration=7.0']}

def source(unit):return lines.get(unit,[])
out=io.StringIO()
with contextlib.redirect_stdout(out):
 ru=m.report('ru',run,source)
 de=m.report('de',run,source)
assert ru['observer']['tcp_syn_in']==4
assert ru['quic']['emsgsize']==1
assert de['meta_tcp']['sessions']==2
assert de['meta_tcp']['sessions_with_origin_reply']==1
assert de['meta_tcp']['recv_from_origin']==248
text=out.getvalue()
assert 'IP' in text and 'raw_payloads_IPs' in text
assert 'META_DE status=' not in text and 'connect=0.12 duration=0.55' not in text
assert '198.51.' not in text
print('meta_report_aggregate_only_and_origin_reply_discrimination=PASS')