#!/usr/bin/env python3
"""MNEBYVPN isolated VPN entitlement agent.

- Only existing WireGuard peer can reach the HTTP API (10.66.77.1).
- Every request authenticated with HMAC-SHA256 over entire JSON body.
- Auth credentials are stored only in root-only local files.
- Isolated Xray child shares the agent systemd cgroup and dies on agent failure.
- One-second offline expiry sweep removes expired users, disconnecting sessions.
- Only the dedicated MNEBYVPN Xray config is changed; no shared Xray instance.
"""
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
import tempfile
import threading
import time
import uuid
from typing import Any

ETC = pathlib.Path('/etc/mnebyvpn')
DATA = pathlib.Path('/var/lib/mnebyvpn-vpn')
CONF = ETC / 'xray-canary.json'
STATE = DATA / 'state.json'
SECRET = ETC / 'provisioner.key'
XRAY = '/opt/xray/xray'
WG = '10.66.77.1'
PORT = 18944
SOCK_PORT = 18943
# Match the billing contract: renewals may exceed one 90-day purchase.
MAX_ACCESS_SECONDS = 315360000

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
        if len(self.template.get('inbounds', [])) != 1:
            raise RuntimeError('Unexpected Xray config')
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
        cfg['inbounds'][0]['settings']['clients'] = clients
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
            stderr=subprocess.DEVNULL,
            user=user.pw_uid, group=user.pw_gid,
        )
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
                return {
                    'revision': current['revision'],
                    'enabled': active,
                    'expiresAt': current['expiresAt'] if active else None,
                    'credential': current['credential'] if active else None,
                }
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
                if not 0 < delta <= MAX_ACCESS_SECONDS:
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
