#!/usr/bin/env python3
"""Offline contract tests for VPN+SmartDNS Xray inbound-sniffing patch.
No SSH, network, real service calls, production config, or user credentials.
"""
from __future__ import annotations
import copy, hashlib, importlib.util, json, pathlib, tempfile, unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "mnebydns-vpn-dns-sniff-fix-20261115.py"
spec = importlib.util.spec_from_file_location("vpn_sniff_fix_offline", SCRIPT)
assert spec is not None and spec.loader is not None
fix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fix)


class XraySniffingContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        directory = pathlib.Path(self.temp.name)
        self.cfg = directory / "xray-canary.json"
        self.source = directory / "vpn-provisioner.py"
        self.source.write_text("# synthetic fixture\n")
        self.document = {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {"protocol": "vless", "tag": "mnebyvpn-inbound", "port": 18943,
                 "settings": {"clients": [{"id": "SECRET_FIXTURE_1", "email": "do-not-change"}]},
                 "streamSettings": {"network": "tcp"}},
                {"protocol": "vless", "tag": "mnebyvpn-reality-inbound", "port": 2053,
                 "settings": {"clients": [{"id": "SECRET_FIXTURE_2"}]},
                 "streamSettings": {"network": "tcp", "security": "reality",
                                    "realitySettings": {"privateKey": "SECRET_FIXTURE_KEY"}}}
            ],
            "routing": {"domainStrategy": "IPIfNonMatch", "rules": [{"type": "field",
                        "ip": ["geoip:private"], "outboundTag": "blocked"}]},
            "outbounds": [{"protocol": "freedom", "tag": "direct"},
                          {"protocol": "blackhole", "tag": "blocked"}]
        }
        self.original = json.dumps(self.document, separators=(",", ":"), ensure_ascii=True).encode()
        self.cfg.write_bytes(self.original)
        self.previous = (
            fix.CONF, fix.SOURCE, fix.EXPECTED_CONFIG_SHA, fix.EXPECTED_SOURCE_SHA
        )
        self.addCleanup(self._restore)
        fix.CONF = self.cfg
        fix.SOURCE = self.source
        fix.EXPECTED_CONFIG_SHA = hashlib.sha256(self.original).hexdigest()
        fix.EXPECTED_SOURCE_SHA = hashlib.sha256(self.source.read_bytes()).hexdigest()

    def _restore(self):
        fix.CONF, fix.SOURCE, fix.EXPECTED_CONFIG_SHA, fix.EXPECTED_SOURCE_SHA = self.previous

    def test_changes_only_sniffing_at_exact_two_inbounds(self):
        before, changed = fix.candidate()
        self.assertEqual(before, self.original)
        a = json.loads(before)
        b = json.loads(changed)
        self.assertEqual({x["port"] for x in b["inbounds"]}, {18943, 2053})
        for entry in b["inbounds"]:
            self.assertEqual(entry["sniffing"], {
                "enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": False
            })
        for entry in b["inbounds"]:
            del entry["sniffing"]
        self.assertEqual(a, b, "No clients, keys, routing, outbounds, or other attributes may change")

    def test_drift_in_live_config_fails_closed(self):
        self.cfg.write_bytes(self.original + b" ")
        with self.assertRaises(AssertionError):
            fix.candidate()

    def test_source_code_drift_fails_closed(self):
        self.source.write_text("unexpected alteration")
        with self.assertRaises(AssertionError):
            fix.candidate()

    def test_existing_sniffing_fails_closed(self):
        altered = copy.deepcopy(self.document)
        altered["inbounds"][0]["sniffing"] = {"enabled": False}
        raw = json.dumps(altered).encode()
        self.cfg.write_bytes(raw)
        fix.EXPECTED_CONFIG_SHA = hashlib.sha256(raw).hexdigest()
        with self.assertRaises(AssertionError):
            fix.candidate()

    def test_different_inbound_port_fails_closed(self):
        altered = copy.deepcopy(self.document)
        altered["inbounds"][0]["port"] = 18944
        raw = json.dumps(altered).encode()
        self.cfg.write_bytes(raw)
        fix.EXPECTED_CONFIG_SHA = hashlib.sha256(raw).hexdigest()
        with self.assertRaises(AssertionError):
            fix.candidate()

    def test_verify_rejects_partial_change(self):
        altered = copy.deepcopy(self.document)
        altered["inbounds"][0]["sniffing"] = copy.deepcopy(fix.OPTIONS)
        with self.assertRaises(AssertionError):
            fix.verify_json(altered)


if __name__ == "__main__":
    unittest.main(verbosity=2)
