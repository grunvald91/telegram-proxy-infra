"""A bounded, local allowlist for the FI metered DoT pilot."""

import asyncio
from pathlib import Path
import re
import time

from fi_dns_origin_canary import HOSTS
from fi_dns_signed_grants import hostname_digest
from fi_dns_ssh_stage import FI_ROOT, private_dir, read

PILOT_FILE = FI_ROOT / "dns-auth" / "single-profile-pilot"
MAX_PILOT_SECONDS = 900
RECORD = re.compile(rb"([0-9a-f]{64}) ([0-9]{10}) ([0-9]{10})\n")
RESERVED = frozenset(hostname_digest(name) for name in HOSTS)


class PilotGrant:
    def __init__(self, path: Path = PILOT_FILE):
        self.path = path

    def digest(self, *, now=None):
        try:
            private_dir(self.path.parent)
            record = RECORD.fullmatch(read(self.path, 87))
        except (OSError, RuntimeError):
            return None
        if record is None:
            return None
        digest = record[1].decode("ascii")
        issued, expires = int(record[2]), int(record[3])
        current = time.time() if now is None else now
        if not issued <= current < expires <= issued + MAX_PILOT_SECONDS or digest in RESERVED:
            return None
        return digest

    def accepts_snapshot(self, grants):
        return not grants or (len(grants) == 1 and grants[0]["tokenSha256"] == self.digest())


class PilotAuthorizer:
    def __init__(self, signed_authorizer, pilot: PilotGrant):
        self.signed_authorizer = signed_authorizer
        self.pilot = pilot

    async def allowed(self, hostname: str) -> bool:
        try:
            digest = hostname_digest(hostname)
        except ValueError:
            return False
        if digest != await asyncio.to_thread(self.pilot.digest):
            return False
        if not await self.signed_authorizer.allowed(hostname):
            return False
        return digest == await asyncio.to_thread(self.pilot.digest)
