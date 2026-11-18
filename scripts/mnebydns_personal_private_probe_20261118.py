#!/usr/bin/env python3
"""Service-only personal DoT proof on RU188; never print or export the bearer label.

This does not manage subscriber identities, SNI routes or public DNS.
A single non-permanent internal owner row is renewed only after positive checks.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import uuid

STATE=Path('/etc/mnebydns/personal-dot/monitor-probe-20261118.json')
SELF=Path('/usr/local/sbin/mnebydns-personal-private-probe')
SERVICE=Path('/etc/systemd/system/mnebydns-personal-private-probe.service')
TIMER=Path('/etc/systemd/system/mnebydns-personal-private-probe.timer')
OWNER=9000000000000000000
ALPHABET='abcdefghijklmnopqrstuvwxyz0123456789'
BACKEND=('10.66.77.2',8858)
DOMAIN='rr1---sn-4g5ednss.googlevideo.com'

def db(sql):
    result=subprocess.run(
        ['docker','exec','-i','mnebyvpn-stage-postgres','psql','-X','-qAt',
         '-v','ON_ERROR_STOP=1','-U','mnebyvpn_stage','-d','mnebyvpn_stage'],
        input=sql,text=True,capture_output=True,timeout=15)
    if result.returncode:
        raise RuntimeError('DB_OPERATION_FAILED')
    return result.stdout.strip()

def read_state():
    data=json.loads(STATE.read_text())
    if not (isinstance(data,dict)
            and isinstance(data.get('label'),str)
            and len(data['label'])==12
            and set(data['label'])<=set(ALPHABET)
            and str(uuid.UUID(data.get('id','')))==data['id']
            and isinstance(data.get('request_key'),str)
            and data['request_key'].startswith('internal-monitor-')):
        raise RuntimeError('BAD_MONITOR_STATE')
    return data

def status(label):
    if len(label)!=12 or set(label)-set(ALPHABET):
        raise RuntimeError('BAD_MONITOR_LABEL')
    return db("SELECT owner_dns_link_status('"+label+"');")

def recvn(conn,n):
    out=bytearray()
    while len(out)<n:
        piece=conn.recv(n-len(out))
        if not piece:
            raise RuntimeError('DOT_EOF')
        out.extend(piece)
    return bytes(out)

def dns_query(label,domain):
    name=label+'.dns.mnebyvpn.site'
    ident=secrets.randbelow(65535)+1
    qname=b''.join(bytes([len(p)])+p.encode('ascii') for p in domain.split('.'))+b'\0'
    wire=struct.pack('!HHHHHH',ident,256,1,0,0,0)+qname+struct.pack('!HH',1,1)
    with socket.create_connection(BACKEND,timeout=6) as conn:
        conn.settimeout(6)
        with ssl.create_default_context().wrap_socket(conn,server_hostname=name) as tls:
            tls.sendall(struct.pack('!H',len(wire))+wire)
            n=struct.unpack('!H',recvn(tls,2))[0]
            if not 12<=n<=8192:
                raise RuntimeError('DOT_INVALID_FRAME')
            answer=recvn(tls,n)
    if (len(answer)<12 or int.from_bytes(answer[:2],'big')!=ident
            or not answer[2]&0x80 or answer[3]&15):
        raise RuntimeError('DOT_INVALID_ANSWER')
    if struct.unpack_from('!H',answer,6)[0]<1:
        raise RuntimeError('DOT_NO_ANSWER')

def delete_own_row(data):
    db("DELETE FROM owner_dns_links WHERE id='"+data['id']+
       "' AND owner_telegram_id="+str(OWNER)+
       " AND request_key='"+data['request_key']+"';")

def verify_profile(data):
    if status(data['label'])!='ALLOWED':
        raise RuntimeError('MONITOR_SUBSCRIPTION_NOT_ACTIVE')
    for domain in ('youtube.com','youtubei.googleapis.com',DOMAIN):
        dns_query(data['label'],domain)

def stage():
    if os.geteuid()!=0:raise RuntimeError('ROOT_REQUIRED')
    if STATE.is_file():
        data=read_state()
        verify_profile(data)
        db("UPDATE owner_dns_links SET expires_at=clock_timestamp()+interval '30 days' "
           "WHERE id='"+data['id']+"' AND owner_telegram_id="+str(OWNER)+
           " AND request_key='"+data['request_key']+"' AND permanent=false "
           "AND revoked_at IS NULL;")
        if status(data['label'])!='ALLOWED':
            raise RuntimeError('MONITOR_RENEWAL_NOT_CONFIRMED')
        print('PRIVATE_PERSONAL_MONITOR=RENEWED_AND_VERIFIED')
        return
    label=''.join(secrets.choice(ALPHABET) for _ in range(12))
    data={'label':label,'id':str(uuid.uuid4()),
          'request_key':'internal-monitor-'+uuid.uuid4().hex}
    db("INSERT INTO owner_dns_links "
       "(id,owner_telegram_id,token_sha256,token_ciphertext,request_key,"
       "permanent,expires_at,video_route) VALUES ('"+data['id']+"',"+str(OWNER)+
       ",'"+hashlib.sha256(label.encode()).hexdigest()+
       "',repeat('x',54),'"+data['request_key']+
       "',false,clock_timestamp()+interval '30 days','vpn_origin');")
    try:
        verify_profile(data)
        STATE.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(STATE,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'w') as f:
            json.dump(data,f)
            f.flush();os.fsync(f.fileno())
        print('PRIVATE_PERSONAL_MONITOR=CREATED_AND_VERIFIED')
    except BaseException:
        delete_own_row(data)
        raise

def install():
    stage()
    # Restricted to RU monitoring identity and units, no network rule changes.
    if not SERVICE.exists():
        SERVICE.write_text(
            '[Unit]\nDescription=MNEBYDNS private authenticated DoT health\n'
            '[Service]\nType=oneshot\n'
            'ExecStart=/usr/bin/python3 -B '+str(SELF)+' stage\n'
            'TimeoutStartSec=50\nNoNewPrivileges=true\nPrivateTmp=true\n')
    if not TIMER.exists():
        TIMER.write_text(
            '[Unit]\nDescription=MNEBYDNS private DoT health weekly\n'
            '[Timer]\nOnBootSec=15min\nOnUnitInactiveSec=7d\n'
            'Unit=mnebydns-personal-private-probe.service\n'
            '[Install]\nWantedBy=timers.target\n')
    tmpfd,tmpname=tempfile.mkstemp(dir=str(SELF.parent),prefix='.private-probe-')
    try:
        with os.fdopen(tmpfd,'wb') as dest,open(__file__,'rb') as source:
            shutil.copyfileobj(source,dest)
            dest.flush();os.fsync(dest.fileno())
        os.chmod(tmpname,0o750)
        os.replace(tmpname,SELF)
    finally:
        if os.path.exists(tmpname):os.unlink(tmpname)
    subprocess.run(['systemctl','daemon-reload'],check=True,timeout=10,capture_output=True)
    subprocess.run(['systemctl','enable','--now',TIMER.name],
                   check=True,timeout=15,capture_output=True)
    print('PRIVATE_PERSONAL_MONITOR_TIMER=INSTALLED')

def report():
    if not STATE.is_file():
        print('PRIVATE_PERSONAL_MONITOR=NOT_INSTALLED')
        return
    data=read_state()
    verify_profile(data)
    print('PRIVATE_PERSONAL_MONITOR=ACTIVE_DOT_VERIFIED')

def revoke():
    if not STATE.exists():
        print('PRIVATE_PERSONAL_MONITOR=ALREADY_ABSENT');return
    data=read_state()
    delete_own_row(data)
    STATE.unlink()
    print('PRIVATE_PERSONAL_MONITOR=REVOKED')

if __name__=='__main__':
    try:
        action=sys.argv[1] if len(sys.argv)==2 else ''
        {'stage':stage,'install':install,'report':report,'revoke':revoke}[action]()
    except KeyError:
        raise SystemExit('usage: stage|install|report|revoke')
    except Exception as ex:
        print('PRIVATE_PERSONAL_MONITOR_ERROR='+type(ex).__name__,file=sys.stderr)
        sys.exit(1)
