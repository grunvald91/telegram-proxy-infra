"""No VPS required: verify fail-closed Reality metadata and key pairing."""
import base64
import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest


PATH = pathlib.Path(__file__).resolve().parents[1] / "scripts/mnebyvpn-vpn-provisioner.py"
spec = importlib.util.spec_from_file_location("mnebyvpn_vpn_agent", PATH)
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


def make_keys():
    der = subprocess.run(
        ["openssl", "genpkey", "-algorithm", "X25519", "-outform", "DER"],
        check=True, capture_output=True).stdout
    assert der.startswith(bytes.fromhex("302e020100300506032b656e04220420"))
    exported = subprocess.run(
        ["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
        input=der, capture_output=True, check=True).stdout
    assert exported.startswith(bytes.fromhex("302a300506032b656e032100"))
    return (
        base64.urlsafe_b64encode(der[-32:]).decode().rstrip("="),
        base64.urlsafe_b64encode(exported[-32:]).decode().rstrip("="),
    )


class RealityMetadataTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        agent.REALITY_PUBLIC = pathlib.Path(self.tmp.name) / "reality-public.json"
        private, public = make_keys()
        self.metadata = {
            "publicKey": public, "shortId": "ab12cd34ef56a789", "port": 2053,
        }
        agent.REALITY_PUBLIC.write_text(json.dumps(self.metadata))
        self.template = {"inbounds": [
            {"tag": "mnebyvpn-inbound"},
            {"tag": "mnebyvpn-reality-inbound", "listen": "0.0.0.0",
             "port": 2053, "protocol": "vless",
             "streamSettings": {
                 "network": "tcp", "security": "reality",
                 "realitySettings": {
                     "serverNames": ["www.cloudflare.com"],
                     "shortIds": ["ab12cd34ef56a789"],
                     "privateKey": private,
                 },
             }},
        ]}

    def test_current_single_inbound_is_unchanged(self):
        self.assertIsNone(agent.verified_reality_public({"inbounds": [{}]}))

    def test_valid_reality_is_published_only_after_verification(self):
        self.assertEqual(agent.verified_reality_public(self.template), self.metadata)

    def test_mismatched_public_key_and_shortcode_are_rejected(self):
        self.metadata["publicKey"] = "A" * 43
        agent.REALITY_PUBLIC.write_text(json.dumps(self.metadata))
        with self.assertRaises(RuntimeError):
            agent.verified_reality_public(self.template)
        self.metadata["publicKey"] = make_keys()[1]
        self.metadata["shortId"] = "0000000000000000"
        agent.REALITY_PUBLIC.write_text(json.dumps(self.metadata))
        with self.assertRaises(RuntimeError):
            agent.verified_reality_public(self.template)

    def test_no_unexpected_inbound_or_public_port(self):
        self.template["inbounds"][1]["port"] = 8443
        with self.assertRaises(RuntimeError):
            agent.verified_reality_public(self.template)
        self.template["inbounds"].append({})
        with self.assertRaises(RuntimeError):
            agent.verified_reality_public(self.template)


if __name__ == "__main__":
    unittest.main()
