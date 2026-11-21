"""Fail-closed V1/V2 watchdog reconciliation contract; no running interface."""
import base64
import datetime as dt
import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import awg_peer_grants as v1
import awg_slot_contract as v2

NODE="fi-test-01"
UID="11111111-2222-4333-8444-555555555555"
UID2="22222222-3333-4444-8555-666666666666"
KEY1=base64.b64encode(bytes(range(32))).decode()
KEY2=base64.b64encode(bytes(range(32,64))).decode()
NOW=dt.datetime.fromisoformat("2026-11-21T18:00:00+00:00").timestamp()
ISO="2026-11-21T18:00:00.000Z"
EXPIRES="2026-11-21T19:00:00.000Z"


def slot_cmd(**overrides):
    data=dict(nodeId=NODE,op="grant",entitlementId=UID,slotNumber=1,
              revision=1,peerPublicKey=KEY1,clientIpv4="10.73.91.3",
              expiresAt=EXPIRES,issuedAt=ISO,nonce="a"*64,signature="B"*86)
    data.update(overrides)
    return data


def legacy_cmd(**overrides):
    data=dict(nodeId=NODE,op="grant",entitlementId=UID2,revision=1,
              peerPublicKey=KEY2,clientIpv4="10.73.91.2",
              expiresAt=EXPIRES,issuedAt=ISO,nonce="b"*64,signature="B"*86)
    data.update(overrides)
    return data


class MixedRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="awg-merged-fi-")
        self.addCleanup(self.temp.cleanup)
        self.node=pathlib.Path(self.temp.name)/NODE
        (self.node/"amneziawg").mkdir(parents=True)
        self.legacy=v1.transition(v1.empty_state(NODE),legacy_cmd(),NOW)
        self.slots=v2.transition(v2.empty_state(NODE),slot_cmd(),NOW)
        self.slotfile=self.node/"amneziawg"/"owner-device-slots-v2.json"
        self.marker=self.node/"amneziawg"/"owner-v2-release.json"

    def release(self,raw=None):
        self.slotfile.write_text(json.dumps(self.slots))
        self.marker.write_text(json.dumps(
            raw if raw is not None else {"node_id":NODE,"enabled":True}))
        files={self.marker:self.marker.read_bytes(),
               self.slotfile:self.slotfile.read_bytes()}
        # Fixture bypasses root-only lstat: integration tests separately
        # verify protected_file ownership and symlink enforcement.
        return patch.object(v1,"protected_file",side_effect=lambda path,**opts:files[path])

    def test_default_runtime_is_identical_to_v1_without_v2_file(self):
        self.marker.write_text('{"node_id":"fi-test-01","enabled":true}')
        self.assertEqual(v1.effective_active_peers(self.node,self.legacy,NOW),
                         v1.active_peers(self.legacy,NOW))

    def test_explicit_root_release_includes_both_peers(self):
        with self.release():
            peers=v1.effective_active_peers(self.node,self.legacy,NOW)
            self.assertEqual(len(peers),2)
            self.assertEqual([p["allowed_ips"] for p in peers],
                             ["10.73.91.2/32","10.73.91.3/32"])
            self.assertEqual(v1.effective_active_peers(
                self.node,self.legacy,NOW+3601),[])

    def test_disabled_v2_release_fails_closed_and_stops_interface(self):
        with self.release(raw={"node_id":NODE,"enabled":False}):
            with self.assertRaises(v1.GrantError):
                v1.effective_active_peers(self.node,self.legacy,NOW)
            calls=[]
            def runner(argv,**kwargs):
                calls.append(argv)
                return None
            with self.assertRaises(v1.GrantError):
                v1.reconcile(self.node,self.legacy,NOW,runner=runner)
            self.assertTrue(any(c[:2]==["systemctl","stop"] for c in calls),
                "V1 watchdog must stop AWG instead of silently pruning V2")

    def test_integer_release_marker_is_not_a_signed_permission(self):
        with self.release(raw={"node_id":NODE,"enabled":1}):
            with self.assertRaises(v1.GrantError):
                v1.effective_active_peers(self.node,self.legacy,NOW)

    def test_historical_duplicate_v1_and_v2_key_or_address_fails_closed(self):
        self.slots=v2.transition(v2.empty_state(NODE),
                                 slot_cmd(clientIpv4="10.73.91.2"),NOW)
        with self.release():
            with self.assertRaises(v1.GrantError):
                v1.effective_active_peers(self.node,self.legacy,NOW)
        self.slots=v2.transition(v2.empty_state(NODE),
                                 slot_cmd(peerPublicKey=KEY2),NOW)
        with self.release():
            with self.assertRaises(v1.GrantError):
                v1.effective_active_peers(self.node,self.legacy,NOW)

    def test_tampered_slot_json_or_symlink_is_not_ignored(self):
        with self.release():
            self.slotfile.write_text('{"not":"a V2 ledger"}')
            with patch.object(v1,"protected_file",side_effect=lambda p,**kw:
                self.slotfile.read_bytes() if p==self.slotfile else
                self.marker.read_bytes()):
                with self.assertRaises((v1.GrantError,v2.SlotError)):
                    v1.effective_active_peers(self.node,self.legacy,NOW)
        self.slotfile.unlink()
        self.slotfile.symlink_to(self.marker)
        with self.assertRaises(v1.GrantError):
            v1.effective_active_peers(self.node,self.legacy,NOW)

if __name__=="__main__":
    unittest.main()
