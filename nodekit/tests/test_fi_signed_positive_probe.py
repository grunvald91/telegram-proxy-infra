"""Offline FI217 signed-only forced-SSH probe tests (no live keys/network)."""
import datetime as dt
import importlib.util
from pathlib import Path
from unittest import TestCase, mock

path=Path(__file__).resolve().parents[1]/"fi_signed_positive_probe.py"
spec=importlib.util.spec_from_file_location("fi_signed_positive_probe",path)
probe=importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class FiPositiveProbeTests(TestCase):
    def test_challenge_has_canonical_fields_and_timestamp(self):
        now=dt.datetime(2026,11,19,8,0,0,tzinfo=dt.timezone.utc)
        public=probe.SPKI_PREFIX+bytes(32)
        challenge=probe.make_challenge(public,now)
        self.assertEqual(
            set(challenge),
            {"nodeId","endpointHost","publicSpki","challengeId","nonce","expiresAt"}
        )
        self.assertEqual(challenge["nodeId"],"fi-test-01")
        self.assertEqual(challenge["endpointHost"],"fi.mnebyvpn.site")
        self.assertEqual(challenge["expiresAt"],"2026-11-19T08:02:30.000Z")
        self.assertEqual(len(challenge["nonce"]),43)
        self.assertTrue(probe.canonical_challenge(challenge).startswith(
            b'["MNEBYVPN_ENROLL_CHALLENGE_V1","fi-test-01"'
        ))

    def test_full_five_minute_boundary_is_exact_and_optional(self):
        now=dt.datetime(2026,11,19,8,0,0,tzinfo=dt.timezone.utc)
        key=probe.SPKI_PREFIX+bytes(32)
        self.assertEqual(
            probe.make_challenge(key,now,300)["expiresAt"],
            "2026-11-19T08:05:00.000Z"
        )
        with mock.patch.object(probe,"block",side_effect=probe.ProbeError) as refused:
            with self.assertRaises(probe.ProbeError):
                probe.make_challenge(key,now,301)
            refused.assert_called_once_with("unreviewed_probe_ttl")

    def test_proof_message_matches_existing_node_contract(self):
        fields={"nodeId":"fi-test-01","endpointHost":"fi.mnebyvpn.site",
                "publicSpki":"Z","challengeId":"uuid","nonce":"nonce"}
        self.assertEqual(
            probe.canonical_proof(fields),
            b'["MNEBYVPN_NODE_ENROLL_V1","fi-test-01","fi.mnebyvpn.site","Z","uuid","nonce"]'
        )

    def test_ssh_pin_and_forced_false_command(self):
        args=probe.ssh_args()
        self.assertIn("StrictHostKeyChecking=yes",args)
        self.assertIn("UserKnownHostsFile=/root/mnebyvpn-controller/fi-known_hosts",args)
        self.assertIn("PasswordAuthentication=no",args)
        self.assertIn("IdentitiesOnly=yes",args)
        self.assertEqual(args[-2:],["root@fi.mnebyvpn.site","false"])

    def test_ssh_failure_diagnostic_cannot_echo_sensitive_stderr(self):
        for stderr,expected in (
            ("NODEKIT_ENROLLMENT_ERROR=EnrollmentSshError secret", "fi_handler_rejected_signed_challenge"),
            ("NODEKIT_ENROLLMENT_ERROR=CalledProcessError secret", "fi_handler_crypto_command_failed"),
            ("Permission denied secret", "fi_dedicated_ssh_auth_denied"),
            ("Host key verification failed secret", "fi_host_pin_verification_failed"),
            ("unknown secret", "fi_ssh_signed_probe_failed_unclassified"),
        ):
            with self.subTest(code=expected),mock.patch.object(probe,"block",side_effect=probe.ProbeError) as stopped:
                with self.assertRaises(probe.ProbeError):
                    probe.diagnose_stderr(stderr)
                stopped.assert_called_once_with(expected)

    def test_no_database_modification_or_customer_publication(self):
        source=path.read_text()
        for unsafe in ("psql","PGPASSWORD","UPDATE vpn_node_enrollment",
                       "INSERT INTO","DELETE FROM","SUBSCRIBER_PUBLICATION=true"):
            self.assertNotIn(unsafe,source)
        self.assertIn("DB_WRITES_BY_PROBE=none",source)
