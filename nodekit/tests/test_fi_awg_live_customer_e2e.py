"""Real FI217 production AWG canary requires observed external bytes and signed ACKs."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import fi_awg_live_customer_e2e as m

class ProductionCanaryTests(unittest.TestCase):
    def test_only_canonical_production_test_ip_and_public_key(self):
        with tempfile.TemporaryDirectory() as t:
            path=Path(t)/"request"
            data={"op":"grant","entitlementId":"11111111-2222-4333-8444-555555555555",
                  "peerPublicKey":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
                  "clientIpv4":"10.73.91.253"}
            path.write_text(json.dumps(data))
            with patch.object(m.trust,"protected",side_effect=lambda p,limit:p.read_bytes()):
                self.assertEqual(m.read_request(path),data)
                data["clientIpv4"]="10.73.91.254"
                path.write_text(json.dumps(data))
                with self.assertRaises(m.Blocked):m.read_request(path)
                data["clientIpv4"]=m.CLIENT_IP
                data["op"]="fake"
                path.write_text(json.dumps(data))
                with self.assertRaises(m.Blocked):m.read_request(path)

    def test_database_proof_requires_actual_signed_receipts(self):
        source=(Path(__file__).parents[1]/"fi_awg_live_customer_e2e.py").read_text()
        for check in ("verify_receipt(entry,applied)","GET DIAGNOSTICS affected=ROW_COUNT",
                      "affected<>1","ext[k] is not True","egressIp","state='verified'",
                      "clock_timestamp()","node_receipt"):
            self.assertIn(check,source)
        self.assertNotIn("vpn_release_flags SET",source)
        self.assertNotIn("systemctl stop",source)
        self.assertNotIn("systemctl start",source)

    def test_wrong_or_unsigned_node_receipt_rejected(self):
        cmd={"nodeId":m.NODE,"op":"grant",
             "entitlementId":"11111111-2222-4333-8444-555555555555",
             "revision":1,"peerPublicKey":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
             "clientIpv4":m.CLIENT_IP,"expiresAt":"2026-11-20T12:30:00.000Z",
             "issuedAt":"2026-11-20T12:27:00.000Z","nonce":"a"*64,
             "signature":"A"*86}
        with self.assertRaises(m.Blocked):
            m.verify_receipt(cmd,{"signed_command_verified":False,"active":False})

if __name__=="__main__":unittest.main()
