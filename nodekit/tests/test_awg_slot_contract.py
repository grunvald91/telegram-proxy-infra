import base64
import copy
import datetime as dt
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import awg_peer_grants as legacy
import awg_slot_contract as v2

NODE="fi-test-01"
UID="11111111-2222-4333-8444-555555555555"
DATE="2026-11-21T18:00:00.000Z"
EXPIRY="2026-11-21T19:00:00.000Z"
NOW=dt.datetime.fromisoformat(DATE.replace("Z","+00:00")).timestamp()
K1=base64.b64encode(bytes(range(32))).decode()
K2=base64.b64encode(bytes(range(32,64))).decode()
K3=base64.b64encode(bytes(range(64,96))).decode()
K4=base64.b64encode(bytes(range(96,128))).decode()


def command(slot=1, **overrides):
    req=dict(nodeId=NODE,op="grant",entitlementId=UID,slotNumber=slot,
             revision=1,peerPublicKey=[K1,K2,K3][slot-1] if slot in (1,2,3) else K4,
             clientIpv4=f"10.73.91.{slot+2}",
             expiresAt=EXPIRY,issuedAt=DATE,nonce="a"*64,signature="B"*86)
    req.update(overrides)
    return req


class SlotContractTest(unittest.TestCase):
    def test_distinct_lease_domain_and_canonical_v2_payload(self):
        req=command()
        self.assertEqual(json.loads(v2.signed_message(req)),[
            "MNEBYVPN_AWG_DEVICE_LEASE_V2",NODE,"grant",UID,1,1,K1,
            "10.73.91.3",EXPIRY,DATE,"a"*64])
        self.assertNotEqual(v2.signed_message(req),legacy.signed_message({
            k:v for k,v in req.items() if k != "slotNumber"}))
        v2.validate_command(req,NODE,NOW)
        self.assertEqual(len(v2.command_digest(req)),64)

    def test_three_peers_same_entitlement_and_independent_revoke(self):
        state=v2.empty_state(NODE)
        for n in (1,2,3):
            state=v2.transition(state,command(n),NOW)
        self.assertEqual(len(state["grants"]),3)
        self.assertEqual(len(v2.merged_active_peers(
            legacy.empty_state(NODE),state,NOW)),3)
        with self.assertRaises(v2.SlotError):
            v2.transition(state,command(4),NOW)
        with self.assertRaises(v2.SlotError):
            v2.transition(state,command(1),NOW)
        revoked=command(2,op="revoke",revision=2,expiresAt=None,nonce="c"*64)
        state=v2.transition(state,revoked,NOW)
        self.assertEqual(len(v2.merged_active_peers(
            legacy.empty_state(NODE),state,NOW)),2)
        self.assertEqual(state["grants"][UID+":2"]["revision"],2)
        with self.assertRaises(v2.SlotError):
            v2.transition(state,command(2,revision=2),NOW)
        for bad in (dict(peerPublicKey=K4),dict(clientIpv4="10.73.91.12")):
            with self.subTest(bad=bad),self.assertRaises(v2.SlotError):
                v2.transition(state,command(2,revision=3,**bad),NOW)
        # Binding remains immutable; an independently authorized new revision
        # can only restore the original key/address.
        state=v2.transition(state,command(2,revision=3),NOW)
        self.assertEqual(len(v2.merged_active_peers(
            legacy.empty_state(NODE),state,NOW)),3)
        self.assertEqual(v2.merged_active_peers(
            legacy.empty_state(NODE),state,NOW+3601),[])

    def test_merges_v1_peer_without_collisions(self):
        base=dict(nodeId=NODE,op="grant",entitlementId=UID,revision=1,
                  peerPublicKey=K4,clientIpv4="10.73.91.2",
                  expiresAt=EXPIRY,issuedAt=DATE,nonce="a"*64,signature="B"*86)
        old=legacy.transition(legacy.empty_state(NODE),base,NOW)
        slots=v2.transition(v2.empty_state(NODE),command(1),NOW)
        self.assertEqual(len(v2.merged_active_peers(old,slots,NOW)),2)
        duplicate_key=v2.transition(v2.empty_state(NODE),command(1,peerPublicKey=K4),NOW)
        with self.assertRaises(v2.SlotError):
            v2.merged_active_peers(old,duplicate_key,NOW)
        duplicate_ip=v2.transition(v2.empty_state(NODE),command(1,clientIpv4="10.73.91.2"),NOW)
        with self.assertRaises(v2.SlotError):
            v2.merged_active_peers(old,duplicate_ip,NOW)
        # Even revoked legacy keys/IPs remain bound to their old owners.
        old=legacy.transition(old,dict(base,op="revoke",revision=2,
                                       expiresAt=None,nonce="c"*64),NOW)
        with self.assertRaises(v2.SlotError):
            v2.merged_active_peers(old,duplicate_key,NOW)

    def test_v2_rejects_bad_command_fields_and_unauthorized_node(self):
        bad=[
            dict(slotNumber=0),dict(slotNumber=4),dict(slotNumber=True),
            dict(clientIpv4="10.73.91.253"),dict(clientIpv4="10.73.91.1"),
            dict(clientIpv4="10.73.92.3"),dict(clientIpv4="10.73.91.03"),
            dict(peerPublicKey=base64.b64encode(bytes(32)).decode()),
            dict(revision=0),dict(revision=True),
            dict(issuedAt="2026-11-21T17:00:00.000Z"),
            dict(expiresAt="2026-11-21T18:00:00.000Z"),
            dict(nonce="X"*64),dict(entitlementId="../../invalid"),
            dict(nodeId="de-node-01"),
            dict(privateKey="never store this client secret"),
        ]
        for invalid in bad:
            with self.subTest(invalid=invalid),self.assertRaises(v2.SlotError):
                v2.validate_command(command(1,**invalid),NODE,NOW)
        with self.assertRaises(v2.SlotError):
            v2.validate_command(command(), "de-node-01", NOW)
        with self.assertRaises(v2.SlotError):
            v2.validate_command(command(1,op="revoke",expiresAt=EXPIRY),NODE,NOW)
        v2.validate_command(command(1,op="revoke",revision=2,expiresAt=None),NODE,NOW)

    def test_combined_v1_and_v2_capacity_is_bounded(self):
        old=legacy.empty_state(NODE)
        for i in range(250):
            uid=f"00000000-0000-4000-8000-{i+1:012x}"
            k=base64.b64encode((i+1).to_bytes(32,"big")).decode()
            old["grants"][uid]={
                "revision":1,"peerPublicKey":k,
                "clientIpv4":f"10.73.91.{i+2}",
                "enabled":True,"expiresAt":EXPIRY,
            }
        legacy.validate_state(old,NODE)
        new=v2.transition(v2.empty_state(NODE),
            command(1,peerPublicKey=base64.b64encode(
                (251).to_bytes(32,"big")).decode(),
                clientIpv4="10.73.91.252"),NOW)
        with self.assertRaisesRegex(v2.SlotError,"capacity exceeded"):
            v2.merged_active_peers(old,new,NOW)

    def test_invalid_slot_state_and_cross_slot_duplicate_rejected(self):
        state=v2.transition(v2.empty_state(NODE),command(),NOW)
        same=copy.deepcopy(state)
        same["grants"][UID+":2"]=copy.deepcopy(same["grants"][UID+":1"])
        with self.assertRaises(v2.SlotError):
            v2.validate_state(same,NODE)
        old=copy.deepcopy(state)
        old["grants"][UID+":1"]["expiresAt"]=None
        with self.assertRaises(v2.SlotError):
            v2.validate_state(old,NODE)
        with self.assertRaises(v2.SlotError):
            v2.transition(state,command(2,peerPublicKey=K1),NOW)
        with self.assertRaises(v2.SlotError):
            v2.transition(state,command(2,clientIpv4="10.73.91.3"),NOW)
        with self.assertRaises(v2.SlotError):
            v2.validate_state(dict(state,schema_version=1),NODE)

    def test_node_ack_signature_domain_includes_slot(self):
        command_sha=v2.command_digest(command())
        receipt=dict(nodeId=NODE,op="grant",entitlementId=UID,slotNumber=1,
                     revision=1,commandSha256=command_sha,appliedAt=DATE,
                     nonce="e"*64,signature="B"*86)
        self.assertEqual(json.loads(v2.receipt_message(receipt)),[
            "MNEBYVPN_AWG_DEVICE_APPLIED_V2",NODE,"grant",UID,1,1,
            command_sha,DATE,"e"*64])
        with self.assertRaises(v2.SlotError):
            v2.receipt_message(dict(receipt,privateKey="leak"))


if __name__=="__main__":
    unittest.main()
