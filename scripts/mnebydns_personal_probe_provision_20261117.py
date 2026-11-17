#!/usr/bin/env python3
"""Provision a private expiring personal DoT monitoring profile on RU.

Only a file readable by root contains the profile identifier. The profile
is never returned in stdout or Actions logs. Rollback revokes just its row.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import uuid

STATE = Path('/etc/mnebydns/personal-dot/monitor-probe-20261117.json')
EXPORT = Path('/tmp/mnebydns-monitor-probe-sni-20261117')
OWNER = 9000000000000000000
ALPHABET='abcdefghijklmnopqrstuvwxyz0123456789'

def sql(statement):
    proc=subprocess.run(['docker','exec','-i','mnebyvpn-stage-postgres',
        'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','mnebyvpn_stage','-d','mnebyvpn_stage'],
        input=statement,text=True,capture_output=True,timeout=15)
    if proc.returncode:
        raise RuntimeError('MONITOR_DATABASE_COMMAND_FAILED')
    return proc.stdout.strip()

def validate_state(obj):
    assert isinstance(obj,dict)
    assert len(obj['label'])==12 and set(obj['label'])<=set(ALPHABET)
    assert str(uuid.UUID(obj['id']))==obj['id']
    assert obj['request_key'].startswith('internal-monitor-')

def read_state():
    obj=json.loads(STATE.read_text())
    validate_state(obj)
    return obj

def status(label):
    return sql("SELECT owner_dns_link_status('"+label+"');")

def dot(label):
    name=label+'.dns.mnebyvpn.site'
    domain='youtube.com'
    tid=secrets.randbelow(65535)+1
    qname=b''.join(bytes([len(c)])+c.encode() for c in domain.split('.'))+b'\0'
    msg=struct.pack('!HHHHHH',tid,256,1,0,0,0)+qname+struct.pack('!HH',1,1)
    with socket.create_connection(('10.66.77.2',8858),timeout=6) as raw:
        raw.settimeout(6)
        with ssl.create_default_context().wrap_socket(raw,server_hostname=name) as tls:
            tls.sendall(struct.pack('!H',len(msg))+msg)
            hdr=tls.recv(2)
            if len(hdr)!=2:raise RuntimeError('PROBE_DOT_SHORT_FRAME')
            n=struct.unpack('!H',hdr)[0]
            if n<12 or n>8192:raise RuntimeError('PROBE_DOT_BAD_FRAME')
            answer=b''
            while len(answer)<n:
                part=tls.recv(n-len(answer))
                if not part:raise RuntimeError('PROBE_DOT_TRUNCATED')
                answer+=part
    if int.from_bytes(answer[:2],'big')!=tid or answer[3]&15 or not struct.unpack_from('!H',answer,6)[0]:
        raise RuntimeError('PROBE_DOT_ANSWER_INVALID')

def remove(obj):
    sql("DELETE FROM owner_dns_links WHERE id='"+obj['id']+"' AND owner_telegram_id="+
        str(OWNER)+" AND request_key='"+obj['request_key']+"';")

def stage():
    if os.geteuid()!=0:raise RuntimeError('root required')
    if STATE.exists():
        obj=read_state()
        if status(obj['label'])!='ALLOWED_SMART_DNS':
            raise RuntimeError('EXISTING_MONITOR_PROFILE_NOT_AUTHORIZED')
        dot(obj['label'])
        sql("UPDATE owner_dns_links SET expires_at=clock_timestamp()+interval '30 days' "
            "WHERE id='"+obj['id']+"' AND owner_telegram_id="+str(OWNER)+
            " AND request_key='"+obj['request_key']+"' AND permanent=false;")
        print('MONITOR_PERSONAL_CREDENTIAL=REUSED_AND_VERIFIED')
        return
    label=''.join(secrets.choice(ALPHABET) for _ in range(12))
    row_id=str(uuid.uuid4())
    req='internal-monitor-'+uuid.uuid4().hex
    obj={'label':label,'id':row_id,'request_key':req}
    sql("INSERT INTO owner_dns_links (id,owner_telegram_id,token_sha256,token_ciphertext,request_key,permanent,expires_at,video_route) VALUES ('"+
        row_id+"',"+str(OWNER)+",'"+hashlib.sha256(label.encode()).hexdigest()+"',"+
        "repeat('x',54),'"+req+"',false,clock_timestamp()+interval '30 days','smart_dns');")
    try:
        if status(label)!='ALLOWED_SMART_DNS':
            raise RuntimeError('MONITOR_CREDENTIAL_AUTHORIZATION_REJECTED')
        dot(label)
        STATE.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(STATE,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as output:
            json.dump(obj,output)
            output.flush();os.fsync(output.fileno())
        print('MONITOR_PERSONAL_CREDENTIAL=CREATED_AND_VERIFIED')
    except BaseException:
        remove(obj)
        raise

def export():
    obj=read_state()
    if status(obj['label'])!='ALLOWED_SMART_DNS':
        raise RuntimeError('MONITOR_PROFILE_NOT_VALID')
    fd=os.open(EXPORT,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(fd,'w') as out:
        out.write(obj['label']+'.dns.mnebyvpn.site\n')
    print('MONITOR_PROBE_EXPORT=STAGED_SECRET_FILE')

def rollback():
    if not STATE.exists():return
    obj=read_state()
    remove(obj)
    STATE.unlink()
    EXPORT.unlink(missing_ok=True)
    print('MONITOR_PERSONAL_CREDENTIAL=REVOKED')

if __name__=='__main__':
    try:
        {'stage':stage,'export':export,'rollback':rollback}[sys.argv[1]]()
    except Exception as ex:
        print('MONITOR_PROBE_ERROR='+type(ex).__name__,file=sys.stderr)
        sys.exit(1)
