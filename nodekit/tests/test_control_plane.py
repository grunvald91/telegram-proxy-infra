import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile
import unittest
from urllib.parse import quote
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from control_plane import (
    ContractError, VerifiedNode, Incident, canonical, country_flag,
    render_subscription, route_incident, safe_agent_payload, parse_agent_advice
)
from incident_gateway import (
    agent_url, dispatch, private_secret, send_agent, validate_envelope
)

NOW = datetime.now(timezone.utc).replace(microsecond=0)
ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
CREDENTIAL = "12222222-3333-4333-8333-555555555555"
KEY = bytes.fromhex("af" * 32)
EXPIRY = NOW + timedelta(hours=24)


def time_(value):
    return value.isoformat().replace("+00:00", "Z")


def node(country="DE", country_name="Германия", state="enabled", ident="de-node-01"):
    checks = {
        key: {"ok": True, "at": time_(NOW), "report_sha256": "1" * 64}
        for key in (
            "vpn_client_e2e", "revoke_and_expiry", "dns_tls", "proxy_tls",
            "data_flow", "external_probe", "egress_country"
        )
    }
    return {
        "node_id": ident, "role": "combined",
        "services": ["dns", "vpn", "sni-proxy", "tunnel"],
        "country_code": country, "country_name_ru": country_name,
        "address": ident + ".vpn.example.org", "vpn_port": 2053,
        "state": state, "checks": checks, "country_evidence_sha256": "2" * 64,
    }


def profile(n):
    return (
        f"vless://{CREDENTIAL}@{n.address}:2053?encryption=none"
        "&security=reality&type=tcp&flow=xtls-rprx-vision"
        "&sni=www.cloudflare.com&fp=chrome&pbk="
        + "A" * 43 + "&sid=ab12cd34ef56a789&spx=%2F"
    )


def receipt(n, entitlement=ID, expires=EXPIRY, uri=None):
    unsigned = {
        "node_id": n.node_id, "entitlement_id": entitlement,
        "revision": 7, "expires_at": time_(expires),
        "observed_at": time_(NOW), "profile_uri": uri or profile(n)
    }
    return {**unsigned, "mac": hmac.new(KEY, canonical(unsigned), hashlib.sha256).hexdigest()}


def envelope(event, key=KEY, timestamp=NOW):
    unsigned = {
        "incident": event, "observed_at": time_(timestamp), "nonce": "a" * 32
    }
    return {**unsigned, "mac": hmac.new(key, canonical(unsigned), hashlib.sha256).hexdigest()}


def incident(kind="owned_sidecar_down", nodes=None, services=None, probes=2, repeats=2):
    return {
        "incident_id": str(uuid4()), "kind": kind,
        "nodes": nodes or ["de-node-01"],
        "services": services or ["vpn"],
        "independent_probes": probes,
        "repeated_failures": repeats, "detail_code": "PROBE_TIMEOUT"
    }


class SubscriptionContracts(unittest.TestCase):
    def test_country_flag_and_publication_requires_all_verified_checks(self):
        self.assertEqual(country_flag("DE"), "🇩🇪")
        self.assertEqual(country_flag("NL"), "🇳🇱")
        n = VerifiedNode.parse(node())
        self.assertTrue(n.eligible(NOW))
        for bad in ("testing", "canary", "degraded", "disabled"):
            self.assertFalse(VerifiedNode.parse(node(state=bad)).eligible(NOW))
        raw = node()
        raw["checks"]["vpn_client_e2e"]["ok"] = False
        self.assertFalse(VerifiedNode.parse(raw).eligible(NOW))
        raw = node()
        raw["checks"]["external_probe"]["at"] = time_(NOW-timedelta(hours=3))
        self.assertFalse(VerifiedNode.parse(raw).eligible(NOW))

    def test_profile_preserves_original_and_adds_verified_countries(self):
        de = VerifiedNode.parse(node())
        nl = VerifiedNode.parse(node("NL", "Нидерланды", ident="nl-node-02"))
        initial = "vless://" + CREDENTIAL + "@cdn.servgo.ru:8443?security=tls#Existing"
        r1, r2 = receipt(de), receipt(nl)
        out = render_subscription(initial, [nl, de], [r2, r1],
                                  {de.node_id: KEY, nl.node_id: KEY}, ID, 7, EXPIRY, NOW)
        self.assertEqual(len(out.splitlines()), 3)
        self.assertEqual(out.splitlines()[0], initial)
        self.assertIn(quote("🇩🇪 MNEBYVPN · Германия · de-node-01"), out)
        self.assertIn(quote("🇳🇱 MNEBYVPN · Нидерланды · nl-node-02"), out)
        self.assertLess(out.index("de-node-01"), out.index("nl-node-02"))
        self.assertEqual(render_subscription(initial, [de], [r1], {}, ID, 7, EXPIRY, NOW), initial)

    def test_fake_receipt_wrong_identity_and_wrong_host_denied(self):
        de = VerifiedNode.parse(node())
        old = "vless://" + CREDENTIAL + "@cdn.servgo.ru:8443?security=tls#Existing"
        for candidate in [
            {**receipt(de), "mac": "0" * 64},
            receipt(de, entitlement="22222222-3333-4333-8333-555555555555"),
            receipt(de, expires=EXPIRY + timedelta(hours=1)),
            receipt(de, uri=profile(de).replace(de.address, "evil.example.net")),
            receipt(de, uri=profile(de) + "&allowInsecure=1"),
            receipt(de, uri=profile(de).replace("security=reality", "security=none")),
            receipt(de, uri=profile(de).replace("&fp=chrome", "&fp=unsafe")),
        ]:
            with self.subTest(candidate=str(candidate.get("mac"))[:6]):
                self.assertEqual(
                    render_subscription(old, [de], [candidate], {de.node_id: KEY},
                                        ID, 7, EXPIRY, NOW), old)
        with self.assertRaises(ContractError):
            render_subscription(old, [de], [receipt(de), receipt(de)], {de.node_id: KEY},
                                ID, 7, EXPIRY, NOW)

    def test_bad_country_host_and_expired_grant_denied(self):
        bad = node()
        bad["country_code"] = "XX!"
        with self.assertRaises(ContractError):
            VerifiedNode.parse(bad)
        bad = node()
        bad["address"] = "127.0.0.1"
        with self.assertRaises(ContractError):
            VerifiedNode.parse(bad)
        n = VerifiedNode.parse(node())
        old = "vless://" + CREDENTIAL + "@cdn.servgo.ru:8443?security=tls#Existing"
        self.assertEqual(
            render_subscription(old, [n], [receipt(n)], {n.node_id: KEY},
                                ID, 7, EXPIRY, NOW + timedelta(hours=2)), old)


class IncidentContracts(unittest.TestCase):
    def test_small_incident_proposes_allowlisted_runbook_but_does_not_execute(self):
        event = Incident.parse(incident())
        d = route_incident(event, {"de-node-01"})
        self.assertEqual(d["classification"], "local_known")
        self.assertEqual(d["action"], "restart-owned-sidecar")
        self.assertFalse(d["auto_execute"])
        self.assertTrue(d["notify_owner"])
        packet = safe_agent_payload(event, d)
        self.assertEqual(packet["permissions"], "advisory_only")
        self.assertNotIn("raw_logs", packet)
        self.assertEqual(
            parse_agent_advice({"action": "restart-owned-sidecar", "reason_code": "SAFE_RESTART"}, d)["reason_code"],
            "SAFE_RESTART")
        with self.assertRaises(ContractError):
            parse_agent_advice({"action": "restart-owned-sidecar", "reason_code": "SAFE_RESTART",
                                "shell": "rm -rf /"}, d)

    def test_global_and_unconfirmed_cannot_auto_repair(self):
        for ev in (
            incident(kind="tunnel_degraded"),
            incident(nodes=["de-node-01", "nl-node-02"]),
            incident(services=["vpn", "dns"]),
            incident(kind="unexpected_event"),
        ):
            d = route_incident(Incident.parse(ev), {"de-node-01", "nl-node-02"})
            self.assertEqual(d["action"], "escalate_read_only")
            self.assertFalse(d["auto_execute"])
        d = route_incident(Incident.parse(incident(probes=1)), {"de-node-01"})
        self.assertEqual(d["action"], "collect_evidence")
        with self.assertRaises(ContractError):
            Incident.parse({**incident(), "detail_code": "SECRET=abc\n"})

    def test_signed_replay_dedup_and_agent_dispatch(self):
        e = envelope(incident())
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            db = root / "eventlog.sqlite"
            sent = []
            def send(payload):
                sent.append(payload)
                return {"action": "restart-owned-sidecar", "reason_code": "SAFE_RESTART"}
            r = dispatch(e, KEY, {"de-node-01"}, db, NOW, send=send)
            self.assertTrue(r["agent_invoked"])
            self.assertFalse(r["deduplicated"])
            self.assertEqual(len(sent), 1)
            repeat = dispatch(e, KEY, {"de-node-01"}, db, NOW, send=send)
            self.assertTrue(repeat["deduplicated"])
            self.assertEqual(len(sent), 1)
        with self.assertRaises(ContractError):
            validate_envelope({**e, "mac": "0" * 64}, KEY, NOW)
        with self.assertRaises(ContractError):
            validate_envelope(envelope(incident(), timestamp=NOW-timedelta(minutes=10)), KEY, NOW)

    def test_https_pinning_and_private_secret(self):
        self.assertEqual(agent_url("https://agents.example.com/advice", "agents.example.com"),
                         "https://agents.example.com/advice")
        for bad in ("http://agents.example.com/advice", "https://127.0.0.1/advice",
                    "https://agents.example.com:8080/advice",
                    "https://evil.example.net/advice",
                    "https://agents.example.com/advice?key=abc"):
            with self.subTest(bad=bad), self.assertRaises(ContractError):
                agent_url(bad, "agents.example.com")
        with tempfile.TemporaryDirectory() as d:
            sec = Path(d) / "secret"
            sec.write_bytes(KEY)
            sec.chmod(0o600)
            self.assertEqual(private_secret(sec), KEY)
            sec.chmod(0o644)
            with self.assertRaises(ContractError):
                private_secret(sec)


if __name__ == "__main__":
    unittest.main()
