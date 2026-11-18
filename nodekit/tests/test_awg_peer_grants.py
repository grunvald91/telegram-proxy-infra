import base64
import copy
import datetime as dt
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import awg_peer_grants as awg

NOW=dt.datetime(2026,11,18,4,0,0,tzinfo=dt.timezone.utc).timestamp()
NODE="fi-test-01"
UID="11111111-2222-4333-8444-555555555555"
UID2="22222222-3333-4444-8555-666666666666"
KEY1=base64.b64encode(bytes(range(32))).decode()
KEY2=base64.b64encode(bytes(range(32,64))).decode()
DATE="2026-11-18T04:00:00.000Z"
EXPIRES="2026-11-18T04:30:00.000Z"


def command(op="grant",**overrides):
    req=dict(nodeId=NODE,op=op,entitlementId=UID,revision=1,
             peerPublicKey=KEY1,clientIpv4="10.73.91.2",
             expiresAt=EXPIRES if op=="grant" else None,
             issuedAt=DATE,nonce="a"*64,signature="B"*86)
    req.update(overrides)
    return req


class TestAWGAccess(unittest.TestCase):
    def test_canonical_payload_matches_controller_abi(self):
        request=command()
        self.assertEqual(json.loads(awg.signed_message(request)),[
            "MNEBYVPN_AWG_LEASE_V1",NODE,"grant",UID,1,KEY1,
            "10.73.91.2",EXPIRES,DATE,"a"*64
        ])
        awg.validate_command(request,NODE,NOW)

    def test_grant_revoke_expiry_and_revision_tombstone(self):
        initial=awg.empty_state(NODE)
        added=awg.transition(initial,command(),NOW)
        self.assertEqual(len(awg.active_peers(added,NOW)),1)
        self.assertEqual(len(awg.active_peers(added,NOW+1801)),0)
        self.assertEqual(initial["grants"],{})
        with self.assertRaises(awg.GrantError):
            awg.transition(added,command(),NOW)
        revoked=awg.transition(added,command("revoke",revision=2,nonce="b"*64),NOW)
        self.assertEqual(awg.active_peers(revoked,NOW),[])
        self.assertEqual(revoked["grants"][UID]["revision"],2)
        with self.assertRaises(awg.GrantError):
            awg.transition(revoked,command("grant",revision=1),NOW)
        reenabled=awg.transition(revoked,command("grant",revision=3),NOW)
        self.assertEqual(len(awg.active_peers(reenabled,NOW)),1)

    def test_immutable_key_and_address_no_cross_entitlement_reuse(self):
        start=awg.transition(awg.empty_state(NODE),command(),NOW)
        for changes in (
            dict(revision=2,peerPublicKey=KEY2),
            dict(revision=2,clientIpv4="10.73.91.3"),
        ):
            with self.subTest(changes=changes),self.assertRaises(awg.GrantError):
                awg.transition(start,command(**changes),NOW)
        for changes in (
            dict(entitlementId=UID2,revision=1,clientIpv4="10.73.91.3"),
            dict(entitlementId=UID2,revision=1,peerPublicKey=KEY2),
        ):
            with self.subTest(changes=changes),self.assertRaises(awg.GrantError):
                awg.transition(start,command(**changes),NOW)

    def test_rejects_wrong_node_stale_issued_bad_network(self):
        rejected=[
            dict(nodeId="de-01"),
            dict(clientIpv4="10.73.91.1"),
            dict(clientIpv4="10.73.92.2"),
            dict(clientIpv4="127.0.0.1"),
            dict(clientIpv4="10.73.91.255"),
            dict(clientIpv4="10.73.91.02"),
            dict(expiresAt=DATE),
            dict(expiresAt=None),
            dict(issuedAt="2026-11-18T03:00:00.000Z"),
            dict(revision=0),
            dict(revision=True),
            dict(peerPublicKey="secret"),
            dict(entitlementId="../../root"),
            dict(nonce="whatever"),
        ]
        for change in rejected:
            with self.subTest(change=change),self.assertRaises(awg.GrantError):
                awg.validate_command(command(**change),NODE,NOW)
        with self.assertRaises(awg.GrantError):
            awg.validate_command(command("revoke",expiresAt=EXPIRES),NODE,NOW)

    def test_rejects_invalid_stored_state_and_duplicates(self):
        state=awg.transition(awg.empty_state(NODE),command(),NOW)
        unsafe=copy.deepcopy(state)
        unsafe["grants"][UID2]=copy.deepcopy(unsafe["grants"][UID])
        with self.assertRaises(awg.GrantError):
            awg.validate_state(unsafe,NODE)
        unsafe=copy.deepcopy(state)
        unsafe["grants"][UID]["expiresAt"]=None
        with self.assertRaises(awg.GrantError):
            awg.validate_state(unsafe,NODE)

    def test_render_only_peers_and_pinned_base(self):
        base="[Interface]\nPrivateKey = ABC=\nHeaderProtectionKey = EFG=\nListenPort = 51821\n"
        state=awg.transition(awg.empty_state(NODE),command(),NOW)
        config=awg.render_runtime_config(base,awg.active_peers(state,NOW))
        self.assertIn("PublicKey = "+KEY1,config)
        self.assertIn("AllowedIPs = 10.73.91.2/32",config)
        self.assertEqual(config.count("[Peer]"),1)
        with self.assertRaises(awg.GrantError):
            awg.render_runtime_config(base+"[Peer]\n",[])

    def test_client_private_key_is_not_a_signed_or_stored_field(self):
        data=command()
        self.assertNotIn("privateKey",awg.CMD_FIELDS)
        self.assertNotIn("privateKey",awg.ROW_FIELDS)
        self.assertNotIn("privateKey",data)
        self.assertIn("peerPublicKey",data)


if __name__=="__main__":
    unittest.main()
