"""FI country runtime policy for an explicit customer release."""

import asyncio
from pathlib import Path

from fi_dns_metered_dot import question_end
from fi_dns_ssh_stage import FI_ROOT, read
from fi_shared_routes import covered

RELEASE = FI_ROOT / "dns-auth" / "customer-dataplane.enable"
RELEASE_STAMP = b"fi-dns-customer-v1\n"


def customer_enabled(path: Path = RELEASE) -> bool:
    try:
        return read(path, len(RELEASE_STAMP)) == RELEASE_STAMP
    except (OSError, RuntimeError):
        return False


class CustomerAuthorizer:
    def __init__(self, signed_authorizer):
        self.signed_authorizer = signed_authorizer

    async def allowed(self, hostname: str) -> bool:
        return (
            await asyncio.to_thread(customer_enabled)
            and await self.signed_authorizer.allowed(hostname)
            and await asyncio.to_thread(customer_enabled)
        )


def chargeable_questions(policy):
    # Read the same catalog that produced the checked local CoreDNS config.
    routes = {"exact": frozenset(policy["exact"]), "families": tuple(policy["families"])}

    def chargeable(query):
        end = question_end(query)
        offset = 12
        labels = []
        while offset < end - 5:
            width = query[offset]
            label = query[offset + 1:offset + 1 + width]
            if b"." in label:
                raise ValueError("Ambiguous DNS route label")
            labels.append(label.decode("ascii").lower())
            offset += width + 1
        return covered(routes, ".".join(labels))

    return chargeable
