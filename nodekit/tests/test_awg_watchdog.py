import base64
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import awg_peer_grants as lease
import install_awg_watchdog as watchdog


class TestWatchdogContract(unittest.TestCase):
    def test_lease_service_kills_interface_on_watchdog_exit(self):
        conf=watchdog.unit()
        self.assertIn('BindsTo=mnebyvpn-nodekit-awg@%i.service',conf)
        self.assertIn('--mode watchdog',conf)
        self.assertIn('--mode controller-check',conf)
        self.assertIn('ExecStopPost=-/opt/mnebyvpn-amneziawg/awg-quick down',conf)
        self.assertIn('Restart=no',conf)
        self.assertNotIn('iptables',conf)
        self.assertNotIn('enable --now',conf)
        self.assertNotIn('WantedBy=network-online.target',conf)

    def test_reconcile_runs_under_exclusive_lock(self):
        import inspect
        body=inspect.getsource(lease.main)
        self.assertIn('with LedgerLock(node)',body)
        self.assertIn('persist_state(ledger, planned)',body)
        self.assertIn('if args.mode == "reconcile"',body)
        self.assertIn('watchdog',body)

    def test_real_openssl_verification_of_canonical_signed_payload(self):
        # Nodekit and official OpenSSL use the same Ed25519 payload; no
        # external Python package and no generated signing key in production.
        now='2026-11-18T04:00:00.000Z'
        later='2026-11-19T04:00:00.000Z'
        request={
            'nodeId':'fi-test-01',
            'op':'grant',
            'entitlementId':'11111111-2222-4333-8444-555555555555',
            'revision':1,
            'peerPublicKey':base64.b64encode(bytes(range(32))).decode(),
            'clientIpv4':'10.73.91.2',
            'expiresAt':later,
            'issuedAt':now,
            'nonce':'a'*64,
            'signature':'B'*86,
        }
        with tempfile.TemporaryDirectory() as temp:
            root=pathlib.Path(temp)
            priv=root/'private.pem'
            pub=root/'pub.der'
            msg=root/'msg'
            sig=root/'sig'
            commands=[
                ['openssl','genpkey','-algorithm','Ed25519','-out',str(priv)],
                ['openssl','pkey','-in',str(priv),'-pubout','-outform','DER',
                 '-out',str(pub)],
            ]
            for cmd in commands:
                subprocess.run(cmd,check=True,capture_output=True)
            msg.write_bytes(lease.signed_message(request))
            subprocess.run(['openssl','pkeyutl','-sign','-inkey',str(priv),
                            '-rawin','-in',str(msg),'-out',str(sig)],
                           check=True,capture_output=True)
            request['signature']=base64.urlsafe_b64encode(
                sig.read_bytes()).rstrip(b'=').decode()
            # The root-only filesystem check is tested in separate tests;
            # CI runner itself runs as a non-root user.
            with patch.object(lease,'protected_file',
                              side_effect=lambda path,**kw:path.read_bytes()):
                lease.verify_signature(request,pub)
                bad=dict(request,clientIpv4='10.73.91.3')
                with self.assertRaises(lease.GrantError):
                    lease.verify_signature(bad,pub)


if __name__=='__main__':
    unittest.main()
