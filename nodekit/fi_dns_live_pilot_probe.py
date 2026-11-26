"""Exercise one synthetic grant on FI using its real certificate and CoreDNS."""

import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import uuid

import fi_dns_guarded_ingress as ingress
from fi_dns_highwater import Highwater
from fi_dns_meter_rpc import timestamp
from fi_dns_metered_dot import LoopbackTlsResolver, valid_answer
from fi_dns_origin_canary import HOSTS
from fi_dns_pilot import PilotAuthorizer, PilotGrant
from fi_dns_signed_grants import hostname_digest, message
from fi_dns_ssh_stage import FI, host, private_dir, require
from fi_dns_tls_session import SignedFiGrantAuthorizer, make_metered_loopback_server
from fi_enrollment_ssh import openssl_sign


class FixtureMeter:
    """Per-query accounting for this disposable probe only."""

    def __init__(self, digest):
        self.digest = digest
        self.held = set()
        self.settled = 0

    async def reserve(self, digest, request):
        if digest != self.digest or self.settled + len(self.held) >= 3:
            return False
        self.held.add(request)
        return True

    async def settle(self, request):
        if request not in self.held:
            return False
        self.held.remove(request)
        self.settled += 1
        return True

    async def release(self, request):
        self.held.discard(request)


def fixture(root, digest):
    key = root / "fixture-private.der"
    public = root / "fixture-public.spki"
    subprocess.run(
        ["/usr/bin/openssl", "genpkey", "-algorithm", "ED25519", "-outform", "DER", "-out", str(key)],
        check=True, timeout=5, capture_output=True,
    )
    spki = subprocess.run(
        ["/usr/bin/openssl", "pkey", "-inform", "DER", "-in", str(key), "-pubout", "-outform", "DER"],
        check=True, timeout=5, capture_output=True,
    ).stdout
    public.write_bytes(spki)
    now = int(time.time())
    snapshot = {
        "schemaVersion": 1, "nodeId": "fi-test-01", "countryCode": "FI", "revision": 1,
        "issuedAt": timestamp(now), "validUntil": timestamp(now + 90),
        "grants": [{
            "entitlementId": str(uuid.uuid4()), "credentialRevision": 1, "tokenSha256": digest,
            "expiresAt": timestamp(now + 75), "state": "ACTIVE",
        }],
    }
    snapshot["signature"] = base64.urlsafe_b64encode(openssl_sign(key, message(snapshot))).rstrip(b"=").decode("ascii")
    key.unlink()
    path = root / "fixture-snapshot.json"
    path.write_text(json.dumps(snapshot), encoding="ascii")
    # These changes are confined to this one process and its temporary paths.
    ingress.SNAPSHOT, ingress.CONTROLLER = path, public
    authorizer = SignedFiGrantAuthorizer(hashlib.sha256(spki).hexdigest())
    authorizer.guard.highwater = Highwater(root / "fixture-highwater.json")
    permit = f"{digest} {now} {now + 75}\n".encode("ascii")
    return authorizer, permit


async def exchange(reader, writer, domain, kind=1):
    require(domain in ("example.com", "www.youtube.com"), "bad_probe_domain")
    labels = [label.encode("ascii") for label in domain.split(".")]
    qname = b"".join(bytes([len(label)]) + label for label in labels) + b"\0"
    question = struct.pack("!HHHHHH", secrets.randbits(16), 256, 1, 0, 0, 0) + qname + struct.pack("!HH", kind, 1)
    writer.write(struct.pack("!H", len(question)) + question)
    await writer.drain()
    try:
        size, = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), 8))
    except asyncio.IncompleteReadError as error:
        require(not error.partial, "partial_dns_frame")
        return None, question
    require(12 <= size <= 16384, "unexpected_dns_frame_size")
    answer = await asyncio.wait_for(reader.readexactly(size), 8)
    valid_answer(question, answer)
    require(answer[3] & 0x0f == 0, "dns_response_error")
    return answer, question


def check_routed_answer(answer, question):
    require(answer is not None and struct.unpack_from("!H", answer, 6)[0] == 1, "missing_routed_A")
    offset = len(question)
    if answer[offset] & 0xc0 == 0xc0:
        offset += 2
    else:
        while answer[offset]:
            offset += 1 + answer[offset]
        offset += 1
    kind, dns_class, _, length = struct.unpack_from("!HHIH", answer, offset)
    require((kind, dns_class, length) == (1, 1, 4), "unexpected_routed_record")
    require(answer[offset + 10:offset + 14] == socket.inet_aton(FI), "routed_A_not_FI")


async def run(root):
    name = secrets.token_hex(6) + ".fi.mnebyvpn.site"
    unknown = secrets.token_hex(6) + ".fi.mnebyvpn.site"
    require(name != unknown, "probe_name_collision")
    digest = hostname_digest(name)
    authorizer, permit = fixture(root, digest)
    lock = root / "fixture-permit"
    meter = FixtureMeter(digest)
    server = await make_metered_loopback_server(
        authorizer=PilotAuthorizer(authorizer, PilotGrant(lock)), meter=meter,
        resolver=LoopbackTlsResolver(HOSTS[0]), listen_port=0,
    )
    port = server.sockets[0].getsockname()[1]
    context = ssl.create_default_context()

    async def connect(hostname):
        return await asyncio.wait_for(asyncio.open_connection(
            "127.0.0.1", port, ssl=context, server_hostname=hostname,
        ), 6)

    async def rejected(hostname):
        reader, writer = await connect(hostname)
        try:
            answer, _ = await exchange(reader, writer, "example.com")
            require(answer is None, "unexpected_dns_grant")
        finally:
            writer.close()
            await writer.wait_closed()

    async with server:
        await rejected(name)
        lock.write_bytes(permit)
        await rejected(unknown)
        reader, writer = await connect(name)
        try:
            answer, _ = await exchange(reader, writer, "example.com")
            require(answer is not None and struct.unpack_from("!H", answer, 6)[0] > 0, "real_origin_no_answer")
            answer, question = await exchange(reader, writer, "www.youtube.com")
            check_routed_answer(answer, question)
            lock.unlink()
            answer, _ = await exchange(reader, writer, "example.com")
            require(answer is None and meter.settled == 2, "revoked_connection_continued")
        finally:
            writer.close()
            await writer.wait_closed()
        lock.write_bytes(permit)
        reader, writer = await connect(name)
        try:
            answer, _ = await exchange(reader, writer, "www.youtube.com", 65)
            require(answer is not None and struct.unpack_from("!H", answer, 6)[0] == 0, "unexpected_HTTPS_record")
        finally:
            writer.close()
            await writer.wait_closed()
        await rejected(name)
        require(meter.settled == 3 and not meter.held, "fixture_quota_mismatch")
    print("FI_LIVE_PILOT_REAL_TLS_DNS_AND_ROUTE=true;FIXTURE_SETTLED=3;REVOKE=true;QUOTA_DENIAL=true", flush=True)


if __name__ == "__main__":
    os.umask(0o077)
    try:
        host(FI)
        stage = Path(sys.argv[1])
        require(re.fullmatch(r"/run/fi-dns-pilot-[0-9]+-[0-9]+", str(stage)), "bad_stage")
        private_dir(stage)
        with tempfile.TemporaryDirectory(dir=stage) as workspace:
            asyncio.run(run(Path(workspace)))
    except (OSError, RuntimeError, ValueError, IndexError, subprocess.SubprocessError) as exc:
        reason = str(exc)
        if not re.fullmatch(r"[a-z0-9_]+", reason):
            reason = type(exc).__name__
        print("FI_LIVE_PILOT_BLOCKED=" + reason, file=sys.stderr, flush=True)
        raise SystemExit(2)
