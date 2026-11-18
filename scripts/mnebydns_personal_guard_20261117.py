#!/usr/bin/env python3
"""Bounded, non-mutating personal DoT watchdog. Never falls back to public DNS."""
from __future__ import annotations
import os
import pathlib
import re
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import fcntl

CONF = pathlib.Path('/etc/mnebydns/personal-sni/nginx.conf')
WATCH = pathlib.Path('/usr/local/sbin/mnebydns-personal-sni-watch')
STATE = pathlib.Path('/var/lib/mnebydns-personal-watch-v2')
BACKUP = STATE / 'original-watch'
PROFILE = STATE / 'probe-sni'
COUNT = pathlib.Path('/run/mnebydns-personal-sni-watch/failure-count')
LOCK = pathlib.Path('/run/lock/mnebydns-personal-watch-v2.lock')
SNI_RE = re.compile(r'(?<![a-z0-9])([a-z0-9]{12}\.dns\.mnebyvpn\.site)(?![a-z0-9])')
QUERY = ('youtube.com', 'youtubei.googleapis.com',
         'rr1---sn-4g5ednss.googlevideo.com')

def recv_exact(conn, n):
    out = bytearray()
    while len(out) < n:
        part = conn.recv(n-len(out))
        if not part:
            raise ConnectionError('short DoT response')
        out.extend(part)
    return bytes(out)

def probe(ip, port, server_name, domain='youtube.com', timeout=4):
    """Full CA-verified DoT question with transaction and reply checks."""
    ident = secrets.randbelow(65535)+1
    qname = b''.join(bytes([len(s)])+s.encode('ascii') for s in domain.split('.'))+b'\x00'
    msg = struct.pack('!HHHHHH',ident,0x0100,1,0,0,0)+qname+struct.pack('!HH',1,1)
    with socket.create_connection((ip, port),timeout=timeout) as raw:
        raw.settimeout(timeout)
        with ssl.create_default_context().wrap_socket(raw,server_hostname=server_name) as tls:
            tls.sendall(struct.pack('!H',len(msg))+msg)
            size = struct.unpack('!H',recv_exact(tls,2))[0]
            if not 12 <= size <= 8192:
                raise ValueError('invalid response length')
            data = recv_exact(tls,size)
    if len(data)<12 or int.from_bytes(data[:2],'big')!=ident or not (data[2]&0x80):
        raise ValueError('invalid DNS response header')
    return data[3] & 15, struct.unpack_from('!H',data,6)[0]

def route():
    entries = [line.strip() for line in CONF.read_text().splitlines()
               if '^[a-z0-9]{12}[.]dns[.]mnebyvpn[.]site$' in line]
    if len(entries)!=1:
        raise RuntimeError('personal SNI map unexpected')
    m = re.search(r'\s([^\s;]+):(8856|8858);',entries[0])
    if not m:
        raise RuntimeError('personal backend outside expected allowlist')
    return m.group(1),int(m.group(2))

def candidate_names():
    # Never mine a real customer's bearer SNI out of the legacy watchdog.
    # Only a separately provisioned service profile may be used for DNS tests.
    if not PROFILE.exists():
        return []
    val=PROFILE.read_text().strip()
    return [val] if SNI_RE.fullmatch(val) else []

def profile_name():
    host,port=route()
    valid=[]
    for name in candidate_names():
        try:
            status,answers=probe(host,port,name)
            if status==0 and answers>0:
                valid.append(name)
        except (OSError,ValueError,ssl.SSLError):
            pass
    if len(valid)!=1:
        raise RuntimeError('NO_UNAMBIGUOUS_VALID_PERSONAL_PROBE_SNI')
    return valid[0]

def read_counter():
    try:
        value=int(COUNT.read_text())
        return max(0,min(value,100))
    except (FileNotFoundError,ValueError):
        return 0

def write_counter(count):
    COUNT.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    temp=COUNT.with_suffix('.new')
    temp.write_text(str(count)+'\n')
    os.replace(temp,COUNT)

def tls_reachable(ip, port, sni='aaaaaaaaaaaa.dns.mnebyvpn.site', timeout=4):
    # A wildcard TLS certificate only verifies transport; NOT authorization.
    with socket.create_connection((ip,port),timeout=timeout) as raw:
        raw.settimeout(timeout)
        with ssl.create_default_context().wrap_socket(raw,server_hostname=sni) as conn:
            if not conn.getpeercert():
                raise ValueError('missing TLS certificate')

def reject_unknown_sni():
    unknown=''.join(secrets.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(12))+'.dns.mnebyvpn.site'
    try:
        status,answers=probe('127.0.0.1',8854,unknown,'youtube.com')
    except (OSError,ValueError,ssl.SSLError):
        return
    if status==0 and answers>0:
        raise RuntimeError('UNKNOWN_PERSONAL_SNI_RECEIVED_DNS_ANSWER')

def check():
    host,port=route()
    if not PROFILE.exists():
        # No monitoring bearer stored: perform transport/denial checks only.
        # Do NOT claim that real subscriber DNS works.
        for ip,p in ((host,port),('127.0.0.1',8854)):
            tls_reachable(ip,p)
        reject_unknown_sni()
        print('PERSONAL_DOT_TRANSPORT=PASS')
        print('PERSONAL_DOT_AUTHENTICATED_QUERIES=UNVERIFIED_NO_SERVICE_PROFILE')
        return
    name=profile_name()
    for ip,p in ((host,port),('127.0.0.1',8854)):
        for domain in QUERY:
            status,answers=probe(ip,p,name,domain)
            if status!=0 or answers<1:
                raise RuntimeError('AUTHENTICATED_DOT_DNS_ANSWER_INVALID')
    reject_unknown_sni()
    print('PERSONAL_DOT_INGRESS_AND_BACKEND=PASS')

def preflight():
    if os.geteuid()!=0:
        raise RuntimeError('root required')
    for unit in ('mnebydns-personal-sni-watch.timer',
                 'mnebydns-personal-sni-stream.service'):
        if subprocess.run(['systemctl','is-active','--quiet',unit]).returncode:
            raise RuntimeError('required systemd unit inactive')
    check()
    print('PERSONAL_DOT_WATCH_PREFLIGHT=PASS')

def install():
    preflight()
    STATE.mkdir(parents=True,exist_ok=True,mode=0o700)
    os.chmod(STATE,0o700)
    if not BACKUP.exists():
        shutil.copy2(WATCH,BACKUP)
        os.chmod(BACKUP,0o600)
    # Keep any existing service-only profile, but never copy a customer SNI.
    fd,temp=tempfile.mkstemp(prefix='.personal-watch-',dir=str(WATCH.parent))
    try:
        with os.fdopen(fd,'wb') as output, open(__file__,'rb') as source:
            shutil.copyfileobj(source,output)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temp,0o750)
        os.replace(temp,WATCH)
        result=subprocess.run(['systemctl','start','mnebydns-personal-sni-watch.service'],
                              capture_output=True,timeout=35)
        if result.returncode:
            raise RuntimeError('new watchdog first run failed')
    except Exception:
        if BACKUP.exists():
            shutil.copy2(BACKUP,WATCH)
            os.chmod(WATCH,0o750)
        raise
    print('PERSONAL_DOT_WATCH_V2=INSTALLED')
    print('PERSONAL_DOT_ROUTING=UNCHANGED')

def rollback():
    if os.geteuid()!=0 or not BACKUP.is_file():
        raise RuntimeError('root and existing backup required')
    shutil.copy2(BACKUP,WATCH)
    os.chmod(WATCH,0o750)
    print('PERSONAL_DOT_WATCH_V2=ROLLED_BACK')
    print('PERSONAL_DOT_ROUTING=UNCHANGED')

def tick():
    LOCK.parent.mkdir(parents=True,exist_ok=True)
    with open(LOCK,'a+') as lock:
        try:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            print('PERSONAL_DOT_WATCH=LOCK_BUSY')
            return
        try:
            check()
            write_counter(0)
            print('PERSONAL_DOT_WATCH=HEALTHY_NO_CHANGES')
        except Exception as ex:
            n=read_counter()+1
            write_counter(n)
            print('PERSONAL_DOT_WATCH=UNHEALTHY_PERSONAL_ROUTE_PRESERVED')
            print('PERSONAL_DOT_WATCH_FAILURES='+str(n))
            print('PERSONAL_DOT_WATCH_FAILURE_CLASS='+type(ex).__name__)
            if n>=3:
                raise RuntimeError('PERSONAL_DOT_FAILED_THREE_CHECKS') from None

if __name__=='__main__':
    try:
        command=sys.argv[1] if len(sys.argv)>1 else 'tick'
        {'preflight':preflight,'install':install,'rollback':rollback,'tick':tick}[command]()
    except KeyError:
        raise SystemExit('usage: preflight|install|rollback|tick')
    except Exception as exc:
        allowed={'personal SNI map unexpected',
                 'personal backend outside expected allowlist',
                 'NO_UNAMBIGUOUS_VALID_PERSONAL_PROBE_SNI',
                 'AUTHENTICATED_DOT_DNS_ANSWER_INVALID',
                 'UNKNOWN_PERSONAL_SNI_RECEIVED_DNS_ANSWER',
                 'required systemd unit inactive',
                 'root required'}
        reason=str(exc) if str(exc) in allowed else type(exc).__name__
        print('PERSONAL_DOT_REPAIR_REASON='+reason,file=sys.stderr)
        sys.exit(1)
