#!/usr/bin/env python3
"""MNEBYVPN isolated VPN entitlement agent.

- Only existing WireGuard peer can reach the HTTP API (10.66.77.1).
- Every request authenticated with HMAC-SHA256 over entire JSON body.
- Auth credentials are stored only in root-only local files.
- Isolated Xray child shares the agent systemd cgroup and dies on agent failure.
- One-second offline expiry sweep removes expired users, disconnecting sessions.
- Only the dedicated MNEBYVPN Xray config is changed; no shared Xray instance.
"""
import base64
import copy
import datetime as dt
import hashlib
import hmac
import http.server
import json
import os
import pathlib
import pwd
import grp
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from typing import Any

UUID_LOG_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
IPV4_LOG_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b')


def redact_xray_log_line(line: str) -> str:
    cleaned = UUID_LOG_RE.sub('[redacted-uuid]', line.strip())
    cleaned = IPV4_LOG_RE.sub('[redacted-ip]', cleaned)
    if len(cleaned) > 300:
        cleaned = cleaned[:297] + '...'
    return cleaned


def _drain_xray_stderr(stream: Any) -> None:
    try:
        for raw in iter(stream.readline, b''):
            text = raw.decode('utf-8', errors='replace')
            redacted = redact_xray_log_line(text)
            if redacted:
                sys.stderr.write(f'xray-canary: {redacted}\n')
                sys.stderr.flush()
    except Exception:
        pass
    finally:
        try:
            stream.close()
        except Exception:
            pass

ETC = pathlib.Path('/etc/mnebyvpn')
DATA = pathlib.Path('/var/lib/mnebyvpn-vpn')
CONF = ETC / 'xray-canary.json'
STATE = DATA / 'state.json'
SECRET = ETC / 'provisioner.key'
XRAY = '/opt/xray/xray'
WG = '10.66.77.1'
PORT = 18944
SOCK_PORT = 18943
REALITY_PORT = 2053
REALITY_PUBLIC = ETC / 'reality-public.json'
REALITY_ANNOUNCE = ETC / 'reality-announce-enabled'

def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)

def normalized_datetime(s: str) -> dt.datetime:
    if not isinstance(s, str) or len(s) > 48:
        raise ValueError('Invalid expiry')
    parsed = dt.datetime.fromisoformat(s.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Expiry must be timezone-aware')
    return parsed.astimezone(dt.timezone.utc)

def atomic_json(path: pathlib.Path, obj: Any, mode: int = 0o600) -> None:
    temp = path.with_name('.' + path.name + '.tmp')
    try:
        with temp.open('w', encoding='utf8') as stream:
            json.dump(obj, stream, separators=(',', ':'), ensure_ascii=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, mode)
        if path == CONF:
            os.chown(temp, 0, grp.getgrnam('mnebyvpn-xray').gr_gid)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)

XHTTP_PORT = 18945

def _is_valid_loopback_xhttp_inbound(inbound: dict) -> bool:
    if not isinstance(inbound, dict):
        return False
    stream = inbound.get('streamSettings') or {}
    return (
        inbound.get('tag') == 'mnebyvpn-xhttp-inbound'
        and inbound.get('listen') == '127.0.0.1'
        and inbound.get('port') == XHTTP_PORT
        and inbound.get('protocol') == 'vless'
        and stream.get('security') == 'none'
        and stream.get('network') == 'xhttp'
    )

def verified_reality_public(template: dict) -> dict | None:
    inbounds = template.get('inbounds', [])
    if not isinstance(inbounds, list) or not inbounds:
        raise RuntimeError('Unexpected Xray inbounds')
    extra = inbounds[1:]
    xhttp_count = sum(1 for ib in extra if isinstance(ib, dict) and ib.get('tag') == 'mnebyvpn-xhttp-inbound')
    if xhttp_count > 1:
        raise RuntimeError('Duplicate XHTTP inbound')
    non_xhttp = []
    for ib in extra:
        if isinstance(ib, dict) and ib.get('tag') == 'mnebyvpn-xhttp-inbound':
            if not _is_valid_loopback_xhttp_inbound(ib):
                raise RuntimeError('Unexpected XHTTP inbound')
        else:
            non_xhttp.append(ib)
    if len(non_xhttp) > 1:
        raise RuntimeError('Unexpected Xray inbounds')
    if not non_xhttp:
        return None
    candidate = non_xhttp[0]
    if not isinstance(candidate, dict):
        raise RuntimeError('Unexpected Xray inbounds')
    stream = candidate.get('streamSettings', {})
    settings = stream.get('realitySettings', {})
    if (candidate.get('tag') != 'mnebyvpn-reality-inbound' or
            candidate.get('listen') != '0.0.0.0' or
            candidate.get('port') != REALITY_PORT or
            candidate.get('protocol') != 'vless' or
            stream.get('security') != 'reality' or
            stream.get('network') not in ('tcp', 'raw') or
            settings.get('serverNames') != ['www.cloudflare.com']):
        raise RuntimeError('Unexpected optional REALITY inbound')
    if not REALITY_PUBLIC.is_file():
        raise RuntimeError('REALITY public metadata missing')
    published = json.loads(REALITY_PUBLIC.read_text())
    if (not isinstance(published, dict) or
            published.get('port') != REALITY_PORT or
            not isinstance(published.get('publicKey'), str) or
            not re.fullmatch(r'[A-Za-z0-9_-]{43}', published['publicKey']) or
            not isinstance(published.get('shortId'), str) or
            not re.fullmatch(r'[0-9a-f]{16}', published['shortId']) or
            settings.get('shortIds') != [published['shortId']]):
        raise RuntimeError('REALITY public metadata mismatch')
    private = settings.get('privateKey')
    if not isinstance(private, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', private):
        raise RuntimeError('Invalid REALITY private key')
    secret = base64.urlsafe_b64decode(private + '==')
    pkcs8 = bytes.fromhex('302e020100300506032b656e04220420') + secret
    derived = subprocess.run(
        ['openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'],
        input=pkcs8, capture_output=True, check=True, timeout=8).stdout
    prefix = bytes.fromhex('302a300506032b656e032100')
    if (not derived.startswith(prefix) or
            base64.urlsafe_b64encode(derived[len(prefix):]).rstrip(b'=').decode()
            != published['publicKey']):
        raise RuntimeError('REALITY keypair verification failed')
    return {'publicKey': published['publicKey'],
            'shortId': published['shortId'], 'port': REALITY_PORT}

class Agent:
    def __init__(self) -> None:
        DATA.mkdir(parents=True, exist_ok=True)
        os.chmod(DATA, 0o700)
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.key = bytes.fromhex(SECRET.read_text().strip())
        if len(self.key) != 32:
            raise RuntimeError('Missing 256-bit agent key')
        self.template = json.loads(CONF.read_text())
        self.reality_public = verified_reality_public(self.template)
        self.state = json.loads(STATE.read_text()) if STATE.is_file() else {}
        if not isinstance(self.state, dict):
            raise RuntimeError('Invalid state')
        self.child: subprocess.Popen[bytes] | None = None
        with self.lock:
            self._expire(self.state)
            self._rewrite(self.state)
            self._spawn()

    def _expire(self, table: dict) -> bool:
        changed = False
        for item in table.values():
            if item.get('enabled') and normalized_datetime(item['expiresAt']) <= utcnow():
                item['enabled'] = False
                changed = True
        return changed

    def _rewrite(self, table: dict) -> None:
        cfg = copy.deepcopy(self.template)
        clients = []
        for item in table.values():
            if item.get('enabled') and normalized_datetime(item['expiresAt']) > utcnow():
                clients.append({'id': item['credential'], 'level': 0})
        for inbound in cfg.get('inbounds', []):
            if inbound.get('protocol') != 'vless':
                continue
            settings = inbound.setdefault('settings', {})
            security = (inbound.get('streamSettings') or {}).get('security')
            if security == 'reality':
                if self.reality_public is not None:
                    settings['clients'] = [
                        {**item, 'flow': 'xtls-rprx-vision'} for item in clients]
            else:
                settings['clients'] = copy.deepcopy(clients)
        atomic_json(CONF, cfg, 0o640)
        checked = subprocess.run(
            [XRAY, 'run', '-test', '-config', str(CONF)],
            capture_output=True, timeout=8)
        if checked.returncode != 0:
            raise RuntimeError('Xray config check failed')

    def _shutdown_child(self) -> None:
        if self.child and self.child.poll() is None:
            self.child.terminate()
            try:
                self.child.wait(timeout=4)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait(timeout=3)
        self.child = None

    def _spawn(self) -> None:
        user = pwd.getpwnam('mnebyvpn-xray')
        self.child = subprocess.Popen(
            [XRAY, 'run', '-config', str(CONF)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            user=user.pw_uid, group=user.pw_gid,
        )
        if self.child.stderr is not None:
            threading.Thread(
                target=_drain_xray_stderr, args=(self.child.stderr,), daemon=True
            ).start()
        for _ in range(25):
            if self.child.poll() is not None:
                raise RuntimeError('Isolated Xray child exited')
            try:
                with socket.create_connection(('127.0.0.1', SOCK_PORT), timeout=.2):
                    return
            except OSError:
                time.sleep(.12)
        raise RuntimeError('Isolated Xray did not listen')

    def _commit(self, next_state: dict) -> None:
        previous = copy.deepcopy(self.state)
        # Renewal and revision updates that do not change the set of enabled
        # Xray credentials need only durable state persistence. Restarting
        # Xray for these changes disconnects ALL existing VPN sessions.
        # Compare enabled flags, not expiry timestamps: an expired user's
        # transition to disabled must STILL remove their Xray access.
        def enrolled(table: dict) -> frozenset[str]:
            return frozenset(item['credential'] for item in table.values()
                             if item.get('enabled'))
        if (self.child is not None and self.child.poll() is None
                and enrolled(previous) == enrolled(next_state)):
            atomic_json(STATE, next_state)
            self.state = next_state
            return
        self._shutdown_child()
        try:
            self._rewrite(next_state)
            self._spawn()
            atomic_json(STATE, next_state)
            self.state = next_state
        except Exception:
            self._shutdown_child()
            self._rewrite(previous)
            self._spawn()
            raise

    def sweep(self) -> None:
        with self.lock:
            candidate = copy.deepcopy(self.state)
            if self._expire(candidate):
                self._commit(candidate)
            elif not self.child or self.child.poll() is not None:
                self._spawn()

    def operation(self, body: dict) -> dict:
        op = body.get('op')
        identifier = body.get('id')
        try:
            identifier = str(uuid.UUID(identifier))
        except (ValueError, AttributeError, TypeError):
            raise ValueError('Invalid entitlement')
        if op not in ('inspect', 'apply'):
            raise ValueError('Unknown operation')
        with self.lock:
            self.sweep()
            current = self.state.get(identifier)
            if op == 'inspect':
                if not current:
                    return {'revision': 0, 'enabled': False, 'expiresAt': None}
                active = bool(current['enabled']) and normalized_datetime(
                    current['expiresAt']) > utcnow() and self.child is not None and self.child.poll() is None
                result = {
                    'revision': current['revision'],
                    'enabled': active,
                    'expiresAt': current['expiresAt'] if active else None,
                    'credential': current['credential'] if active else None,
                }
                # ANNOUNCE is enabled only after independent network and
                # revocation tests. Removing it immediately hides fast URLs.
                if active and self.reality_public is not None and REALITY_ANNOUNCE.is_file():
                    result['reality'] = self.reality_public
                return result
            rev = body.get('revision')
            enabled = body.get('enabled')
            if not isinstance(rev, int) or isinstance(rev, bool) or rev < 1 or rev > 1000000000:
                raise ValueError('Invalid revision')
            if not isinstance(enabled, bool):
                raise ValueError('Invalid enabled')
            when = None
            if enabled:
                when = normalized_datetime(body.get('expiresAt'))
                delta = (when-utcnow()).total_seconds()
                if not 0 < delta <= 100*86400:
                    raise ValueError('Invalid access expiry')
            if current and rev < current['revision']:
                return {'status':'stale','revision':current['revision']}
            if current and rev == current['revision']:
                same = current['enabled'] == enabled and (
                    not enabled or current['expiresAt'] == when.isoformat())
                if not same:
                    raise ValueError('Conflicting same-revision operation')
                return {'status':'applied','revision':rev}
            candidate = copy.deepcopy(self.state)
            credential = current['credential'] if current else str(uuid.uuid4())
            candidate[identifier] = {
                'revision':rev,'enabled':enabled,'credential':credential,
                'expiresAt':when.isoformat() if enabled else None,
            }
            self._commit(candidate)
            return {'status':'applied','revision':rev}

    def stop_all(self) -> None:
        self.stop.set()
        with self.lock:
            self._shutdown_child()

AGENT: Agent

class RequestHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args: Any) -> None:
        pass  # Never log credentials, IDs or user traffic.
    def do_GET(self) -> None:
        if self.path == '/healthz':
            healthy=AGENT.child is not None and AGENT.child.poll() is None
            self._reply(200 if healthy else 503, {'healthy':healthy})
        else:
            self._reply(404, {'error':'NOT_FOUND'})
    def do_POST(self) -> None:
        if self.path != '/v1/provision':
            self._reply(404, {'error':'NOT_FOUND'})
            return
        if self.client_address[0] != '10.66.77.2':
            self._reply(403, {'error':'FORBIDDEN'})
            return
        raw_len=self.headers.get('Content-Length','')
        if not raw_len.isdecimal() or not 0 < int(raw_len) <= 4096:
            self._reply(413, {'error':'INVALID_LENGTH'})
            return
        raw=self.rfile.read(int(raw_len))
        signature=self.headers.get('X-Mnebyvpn-Signature','')
        exp=hmac.new(AGENT.key,raw,hashlib.sha256).hexdigest()
        if not hmac.compare_digest(exp,signature):
            self._reply(401, {'error':'AUTH_REQUIRED'})
            return
        try:
            data=json.loads(raw)
            if not isinstance(data,dict):raise ValueError('Invalid body')
            stamp=data.get('ts')
            if not isinstance(stamp,(int,float)) or isinstance(stamp,bool) or abs(time.time()-stamp)>90:
                raise ValueError('Invalid timestamp')
            result=AGENT.operation(data)
            self._reply(200,result)
        except Exception:
            self._reply(503, {'error':'PROVISIONING_RETRY_REQUIRED'})
    def _reply(self,status:int,payload:dict) -> None:
        self.send_response(status)
        self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

def main() -> None:
    global AGENT
    AGENT=Agent()
    server=http.server.ThreadingHTTPServer((WG,PORT),RequestHandler)
    server.daemon_threads=True
    def shutdown(_signum:int,_frame:Any) -> None:
        AGENT.stop.set()
        threading.Thread(target=server.shutdown,daemon=True).start()
    signal.signal(signal.SIGTERM,shutdown)
    signal.signal(signal.SIGINT,shutdown)
    def sweep() -> None:
        while not AGENT.stop.wait(1):
            try:AGENT.sweep()
            except Exception:
                # If we cannot reliably enforce expiry, fail closed.
                AGENT.stop_all()
                os._exit(12)
    threading.Thread(target=sweep,daemon=True).start()
    try:server.serve_forever(poll_interval=.4)
    finally:AGENT.stop_all();server.server_close()

if __name__=='__main__':
    main()
