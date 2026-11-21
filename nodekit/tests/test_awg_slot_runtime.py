"""Signed FI-only V2 nodekit apply under fake interface, no actual peers."""
import base64
from contextlib import nullcontext
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
import awg_slot_runtime as runtime

NOW=dt.datetime.fromisoformat("2026-11-21T18:00:00+00:00").timestamp()
DATE="2026-11-21T18:00:00.000Z"
EXPIRES="2026-11-21T19:00:00.000Z"
NODE="fi-test-01"
UID="11111111-2222-4333-8444-555555555555"
KEYS=[base64.b64encode(bytes(range(i*32,(i+1)*32))).decode() for i in range(3)]


def command(slot=1,op="grant",revision=1):
    return dict(nodeId=NODE,op=op,entitlementId=UID,slotNumber=slot,
                revision=revision,peerPublicKey=KEYS[slot-1],
                clientIpv4=f"10.73.91.{slot+2}",
                expiresAt=EXPIRES if op=="grant" else None,issuedAt=DATE,
                nonce="a"*64,signature="B"*86)


class Clock:
    def now(self):return NOW


class RuntimeContract(unittest.TestCase):
    def setUp(self):
        self.root=tempfile.TemporaryDirectory(prefix="awg-v2-nodekit-")
        self.addCleanup(self.root.cleanup)
        self.node=pathlib.Path(self.root.name)/NODE
        (self.node/"amneziawg").mkdir(parents=True)
        self.marker=self.node/"amneziawg"/runtime.RELEASE_MARKER
        self.marker.write_text(json.dumps({"enabled":True,"node_id":NODE}))
        self.lock=patch.object(v1,"LedgerLock",side_effect=lambda node:nullcontext())
        self.protected=patch.object(v1,"protected_file",side_effect=lambda p,**kwargs:
            pathlib.Path(p).read_bytes())
        self.pin=patch.object(v1,"pinned_controller_key",return_value=self.marker)
        self.signature=patch.object(v2,"verify_signature",return_value=None)
        self.active=patch.object(runtime,"active_unit",return_value=True)
        for p in (self.lock,self.protected,self.pin,self.signature,self.active):
            p.start();self.addCleanup(p.stop)
        self.observed=[]

    def reconcile(self,node,legacy,now):
        self.observed.append(v1.effective_active_peers(node,legacy,now))
        return {"active":True,"peers":len(self.observed[-1]),"published":False}

    def receipt(self,node,request):
        return {"nodeId":request["nodeId"],"op":request["op"],
                "slotNumber":request["slotNumber"],"revision":request["revision"]}

    def test_three_v2_slots_independent_replay_and_single_revoke(self):
        for slot in (1,2,3):
            result=runtime.execute_signed_slot_command(
                self.node,command(slot),clock=Clock(),
                reconcile_func=self.reconcile,signer=self.receipt)
            self.assertTrue(result["active"])
            self.assertFalse(result["published"])
            self.assertEqual(result["node_receipt"]["slotNumber"],slot)
        self.assertEqual(len(self.observed[-1]),3)
        self.assertEqual([x["allowed_ips"] for x in self.observed[-1]],
            ["10.73.91.3/32","10.73.91.4/32","10.73.91.5/32"])
        ledger=json.loads((self.node/"amneziawg"/runtime.SLOT_LEDGER).read_text())
        self.assertEqual(len(ledger["grants"]),3)
        with self.assertRaises(v2.SlotError):
            runtime.execute_signed_slot_command(
                self.node,command(2),clock=Clock(),
                reconcile_func=self.reconcile,signer=self.receipt)
        result=runtime.execute_signed_slot_command(
            self.node,command(2,op="revoke",revision=2),clock=Clock(),
            reconcile_func=self.reconcile,signer=self.receipt)
        self.assertTrue(result["active"])
        self.assertEqual([x["allowed_ips"] for x in self.observed[-1]],
            ["10.73.91.3/32","10.73.91.5/32"])
        ledger=json.loads((self.node/"amneziawg"/runtime.SLOT_LEDGER).read_text())
        self.assertEqual(ledger["grants"][UID+":2"]["revision"],2)
        self.assertFalse(ledger["grants"][UID+":2"]["enabled"])

    def test_default_closed_and_missing_watchdog(self):
        self.marker.write_text(json.dumps({"enabled":False,"node_id":NODE}))
        with self.assertRaises(runtime.SlotRuntimeError):
            runtime.execute_signed_slot_command(
                self.node,command(),clock=Clock(),
                reconcile_func=self.reconcile,signer=self.receipt)
        self.assertFalse((self.node/"amneziawg"/runtime.SLOT_LEDGER).exists())
        self.marker.write_text(json.dumps({"enabled":True,"node_id":NODE}))
        with patch.object(runtime,"active_unit",return_value=False):
            with self.assertRaises(runtime.SlotRuntimeError):
                runtime.execute_signed_slot_command(
                    self.node,command(),clock=Clock(),
                    reconcile_func=self.reconcile,signer=self.receipt)
        self.assertFalse((self.node/"amneziawg"/runtime.SLOT_LEDGER).exists())

    def test_failed_apply_stops_awg_and_never_confirms_signed_ack(self):
        calls=[]
        def failed(node,state,now):raise RuntimeError("simulated syncconf failure")
        with patch.object(runtime.subprocess,"run",
                          side_effect=lambda args,**kwargs:calls.append(args)):
            with self.assertRaisesRegex(RuntimeError,"simulated syncconf"):
                runtime.execute_signed_slot_command(
                    self.node,command(),clock=Clock(),
                    reconcile_func=failed,signer=self.receipt)
        self.assertTrue(any(x[:2]==["systemctl","stop"] for x in calls))
        ledger=json.loads((self.node/"amneziawg"/runtime.SLOT_LEDGER).read_text())
        self.assertEqual(ledger["grants"][UID+":1"]["revision"],1)

    def test_cross_v1_collision_rejected_before_file_write(self):
        legacy=v1.transition(v1.empty_state(NODE),
             dict(nodeId=NODE,op="grant",
                  entitlementId="22222222-3333-4444-8555-666666666666",
                  revision=1,peerPublicKey=KEYS[0],clientIpv4="10.73.91.2",
                  expiresAt=EXPIRES,issuedAt=DATE,
                  nonce="b"*64,signature="B"*86),NOW)
        (self.node/"amneziawg"/"peer-grants.json").write_text(json.dumps(legacy))
        with self.assertRaises(v2.SlotError):
            runtime.execute_signed_slot_command(
                self.node,command(),clock=Clock(),
                reconcile_func=self.reconcile,signer=self.receipt)
        self.assertFalse((self.node/"amneziawg"/runtime.SLOT_LEDGER).exists())

if __name__=="__main__":
    unittest.main()
