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

    def test_signed_synthetic_tombstone_pruning_preserves_real_customer(self):
        import contextlib
        import datetime as dt
        from types import SimpleNamespace
        import awg_peer_grants as grants
        key="AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
        other="AgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICE="
        test_id="11111111-2222-4333-8444-555555555555"
        paid_id="22222222-3333-4444-8555-666666666666"
        issued=dt.datetime.now(dt.timezone.utc)-dt.timedelta(seconds=55)
        request={"nodeId":m.NODE,"op":"revoke","entitlementId":test_id,
                 "revision":2,"peerPublicKey":key,"clientIpv4":m.CLIENT_IP,
                 "expiresAt":None,
                 "issuedAt":issued.isoformat(timespec="milliseconds").replace("+00:00","Z"),
                 "nonce":"a"*64,"signature":"A"*86}
        ledger={
            "schema_version":1,"node_id":m.NODE,
            "grants":{
                test_id:{"revision":2,"peerPublicKey":key,"clientIpv4":m.CLIENT_IP,
                         "expiresAt":None,"enabled":False},
                paid_id:{"revision":1,"peerPublicKey":other,"clientIpv4":"10.73.91.2",
                         "expiresAt":(dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=5)).isoformat(
                             timespec="milliseconds").replace("+00:00","Z"),"enabled":True},
            },
        }
        recorded=[]
        with patch.object(m.trust,"is_host",return_value=True),\
             patch.object(m,"secure_json",return_value=request),\
             patch.object(m.subprocess,"run",return_value=SimpleNamespace(returncode=0)),\
             patch.object(grants,"LedgerLock",side_effect=lambda node:contextlib.nullcontext()),\
             patch.object(grants,"protected_file",return_value=json.dumps(ledger).encode()),\
             patch.object(grants,"verify_signature"),\
             patch.object(grants,"assert_runtime_peers") as runtime,\
             patch.object(grants,"persist_state",side_effect=lambda p,data:recorded.append(data)):
            m.prune_on_fi(Path("/unused"))
        self.assertEqual(len(recorded),1)
        self.assertEqual(set(recorded[0]["grants"]),{paid_id})
        runtime.assert_called_once()


    def test_old_revoked_synthetic_slot_can_be_retired_without_customer_changes(self):
        import contextlib
        import datetime as dt
        import os
        import time
        from types import SimpleNamespace
        import awg_peer_grants as grants
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            path=root/"amneziawg/peer-grants.json"
            path.parent.mkdir()
            a="11111111-2222-4333-8444-555555555555"
            b="22222222-3333-4444-8555-666666666666"
            material={
                "schema_version":1,"node_id":m.NODE,
                "grants":{
                    a:{"revision":2,"peerPublicKey":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
                       "clientIpv4":m.CLIENT_IP,"expiresAt":None,"enabled":False},
                    b:{"revision":1,"peerPublicKey":"AgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICE=",
                       "clientIpv4":"10.73.91.2",
                       "expiresAt":(dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=5))
                                  .isoformat(timespec="milliseconds").replace("+00:00","Z"),
                       "enabled":True}
                }
            }
            path.write_text(json.dumps(material))
            old=time.time()-130
            os.utime(path,(old,old))
            saved=[]
            with patch.object(m,"FI",root),\
                 patch.object(m.trust,"is_host",return_value=True),\
                 patch.object(m.subprocess,"run",return_value=SimpleNamespace(returncode=0)),\
                 patch.object(grants,"LedgerLock",side_effect=lambda node:contextlib.nullcontext()),\
                 patch.object(grants,"protected_file",side_effect=lambda fp:fp.read_bytes()),\
                 patch.object(grants,"persist_state",side_effect=lambda fp,data:saved.append(data)),\
                 patch.object(grants,"assert_runtime_peers") as runtime:
                self.assertEqual(m.prune_stale_on_fi(),"PRUNED")
                self.assertEqual(len(saved),1)
                self.assertEqual(set(saved[0]["grants"]),{b})
                runtime.assert_called_once()
                # Revocation just written: replay window is not yet over.
                os.utime(path,None)
                with self.assertRaises(m.Blocked):
                    m.prune_stale_on_fi()
            self.assertEqual(set(material["grants"]),{a,b})

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
