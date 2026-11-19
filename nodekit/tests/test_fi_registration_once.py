"""Offline regression checks for guarded FI registration, canonical DB and no publication."""
import importlib.util
from pathlib import Path
from unittest import TestCase, mock

module_path = Path(__file__).resolve().parents[1] / "fi_registration_once.py"
spec = importlib.util.spec_from_file_location("fi_registration_once", module_path)
registration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(registration)


class FiRegistrationGateTests(TestCase):
    def test_absent_inventory_rejected(self):
        with mock.patch.object(registration, "execute",
                               return_value="FI_CANONICAL_DB_STATE=absent\n"):
            self.assertEqual(registration.db_state("A" * 59), "absent")

    def test_approved_and_enrolled_states_are_strict(self):
        for status in ("approved", "enrolled"):
            with self.subTest(status=status), mock.patch.object(
                registration, "execute",
                return_value="FI_CANONICAL_DB_STATE=" + status + "\n"
            ):
                self.assertEqual(registration.db_state("A" * 59), status)

    def test_fail_closed_malformed_or_duplicate_output(self):
        for raw in (
            "", "approved|fi.mnebyvpn.site", "FI_CANONICAL_DB_STATE=unknown",
            "FI_CANONICAL_DB_STATE=enrolled\nFI_CANONICAL_DB_STATE=approved",
        ):
            with self.subTest(raw=raw), mock.patch.object(
                registration, "execute", return_value=raw
            ):
                with self.assertRaises(registration.GateError):
                    registration.db_state("A" * 59)

    def test_db_state_uses_exact_registrar_systemd_env_not_stage_database(self):
        with mock.patch.object(
            registration, "execute",
            return_value="FI_CANONICAL_DB_STATE=approved"
        ) as cmd:
            self.assertEqual(registration.db_state("A" * 59), "approved")
            args = cmd.call_args.args[0]
            self.assertEqual(args[0], "systemd-run")
            self.assertIn(
                "--property=EnvironmentFile=/root/mnebyvpn-controller/config/fi-enrollment.env",
                args
            )
            self.assertNotIn("docker", args)
            self.assertNotIn("mnebyvpn-stage-postgres", " ".join(args))
            self.assertIn("process.env.DATABASE_URL", registration.DB_CHECK_JS)
            self.assertIn("--property=IPAddressDeny=any", args)
            self.assertIn("--property=IPAddressAllow=127.0.0.0/8", args)

    def test_enrolled_does_not_start_systemd_enroller(self):
        node = bytes.fromhex("302a300506032b6570032100") + bytes(32)
        with (
            mock.patch.object(registration.os, "geteuid", return_value=0),
            mock.patch.object(registration, "assigned_ip", return_value=True),
            mock.patch.object(registration, "spki", return_value=node),
            mock.patch.object(
                registration, "protected",
                side_effect=[b"fi.mnebyvpn.site ssh-ed25519 abc\n", b"key", b"key"]
            ),
            mock.patch.object(registration, "require_runtime") as require,
            mock.patch.object(registration, "await_expiration_once"),
            mock.patch.object(registration, "db_state", return_value="enrolled"),
            mock.patch.object(registration, "execute") as cmd,
        ):
            self.assertEqual(registration.main(), 0)
            require.assert_called_once()
            cmd.assert_not_called()

    def test_absent_or_nonapproved_does_not_start_systemd_enroller(self):
        node = bytes.fromhex("302a300506032b6570032100") + bytes(32)
        for state in ("absent", "planned", "revoked"):
            with (
                self.subTest(state=state),
                mock.patch.object(registration.os, "geteuid", return_value=0),
                mock.patch.object(registration, "assigned_ip", return_value=True),
                mock.patch.object(registration, "spki", return_value=node),
                mock.patch.object(
                    registration, "protected",
                    side_effect=[b"fi.mnebyvpn.site ssh-ed25519 abc\n", b"key", b"key"]
                ),
                mock.patch.object(registration, "require_runtime"),
                mock.patch.object(registration, "await_expiration_once"),
                mock.patch.object(registration, "db_state", return_value=state),
                mock.patch.object(registration, "execute") as cmd,
            ):
                with self.assertRaises(registration.GateError):
                    registration.main()
                cmd.assert_not_called()

    def test_approved_refreshes_conditions_then_checks_enrolled_in_same_db(self):
        node = bytes.fromhex("302a300506032b6570032100") + bytes(32)
        with (
            mock.patch.object(registration.os, "geteuid", return_value=0),
            mock.patch.object(registration, "assigned_ip", return_value=True),
            mock.patch.object(registration, "spki", return_value=node),
            mock.patch.object(
                registration, "protected",
                side_effect=[b"fi.mnebyvpn.site ssh-ed25519 abc\n", b"key", b"key"]
            ),
            mock.patch.object(registration, "require_runtime"),
            mock.patch.object(registration, "await_expiration_once"),
            mock.patch.object(
                registration, "db_state", side_effect=["approved", "approved", "enrolled"]
            ) as database,
            mock.patch.object(registration, "execute", return_value="") as execute,
        ):
            self.assertEqual(registration.main(), 0)
            self.assertEqual(database.call_count, 3)
            self.assertEqual(
                [call.args[0] for call in execute.call_args_list],
                [["systemctl","daemon-reload"],["systemctl","start",
                   "mnebyvpn-fi-enrollment.service"]]
            )

    def test_skipped_unit_requires_all_five_native_systemd_conditions_before_transient(self):
        node=bytes.fromhex("302a300506032b6570032100")+bytes(32)
        commands=[]
        def cmd(args,timeout=12):
            commands.append(args)
            if args[:2]==["systemctl","show"]:
                return "no"
            if args[0]=="systemd-run":
                return "FI_ENROLLMENT=testing;SUBSCRIBER_PUBLICATION=false"
            return ""
        with (
            mock.patch.object(registration.os,"geteuid",return_value=0),
            mock.patch.object(registration,"assigned_ip",return_value=True),
            mock.patch.object(registration,"spki",return_value=node),
            mock.patch.object(
                registration,"protected",
                side_effect=[b"fi.mnebyvpn.site ssh-ed25519 abc\n",b"key",b"key"]
            ),
            mock.patch.object(registration,"require_runtime"),
            mock.patch.object(registration,"await_expiration_once"),
            mock.patch.object(registration.Path,"resolve",
                return_value=registration.Path(
                    "/opt/mnebyvpn-controller/releases/reviewed-release")),
            mock.patch.object(registration.Path,"is_dir",return_value=True),
            mock.patch.object(registration,"db_state",
                              side_effect=["approved", "approved", "approved", "enrolled"]) as db,
            mock.patch.object(registration,"execute",side_effect=cmd),
        ):
            self.assertEqual(registration.main(),0)
        self.assertEqual(db.call_count,4)
        checks=[c for c in commands if c[0]=="systemd-analyze"]
        self.assertEqual(len(checks),5)
        transient=[c for c in commands if c[0]=="systemd-run"]
        self.assertEqual(len(transient),1)
        self.assertIn("--property=IPAddressDeny=any",transient[0])
        self.assertIn("--property=IPAddressAllow=217.11.167.91/32",transient[0])
        self.assertIn("--property=NoNewPrivileges=yes",transient[0])
        self.assertIn("--unit=mnebyvpn-fi-controller-transient",transient[0])
        self.assertIn("--eval", transient[0])
        self.assertIn("enrollApprovedFiNode", transient[0][-1])
        self.assertIn("FI_ENROLLMENT_FAILURE_CLASS", transient[0][-1])
        self.assertIn(
            "--property=EnvironmentFile=/root/mnebyvpn-controller/config/fi-enrollment.env",
            transient[0]
        )

    def test_fallback_cannot_run_after_failed_native_condition(self):
        node=bytes.fromhex("302a300506032b6570032100")+bytes(32)
        calls=[]
        def cmd(args,timeout=12):
            calls.append(args)
            if args[:2]==["systemctl","show"]:return "no"
            if args[0]=="systemd-analyze":
                raise registration.GateError("security condition denied")
            return ""
        with (
            mock.patch.object(registration.os,"geteuid",return_value=0),
            mock.patch.object(registration,"assigned_ip",return_value=True),
            mock.patch.object(registration,"spki",return_value=node),
            mock.patch.object(
                registration,"protected",
                side_effect=[b"fi.mnebyvpn.site ssh-ed25519 abc\n",b"key",b"key"]
            ),
            mock.patch.object(registration,"require_runtime"),
            mock.patch.object(registration,"await_expiration_once"),
            mock.patch.object(registration.Path,"resolve",
                return_value=registration.Path(
                    "/opt/mnebyvpn-controller/releases/reviewed-release")),
            mock.patch.object(registration.Path,"is_dir",return_value=True),
            mock.patch.object(registration,"db_state",
                              side_effect=["approved", "approved", "approved"]),
            mock.patch.object(registration,"execute",side_effect=cmd),
        ):
            with self.assertRaises(registration.GateError):
                registration.main()
        self.assertFalse(any(c[0]=="systemd-run" for c in calls))

    def test_fallback_cannot_run_if_static_unit_condition_is_not_skipped(self):
        node=bytes.fromhex("302a300506032b6570032100")+bytes(32)
        commands=[]
        def cmd(args,timeout=12):
            commands.append(args)
            return "yes" if args[:2]==["systemctl","show"] else ""
        with (
            mock.patch.object(registration.os,"geteuid",return_value=0),
            mock.patch.object(registration,"assigned_ip",return_value=True),
            mock.patch.object(registration,"spki",return_value=node),
            mock.patch.object(
                registration,"protected",
                side_effect=[b"fi.mnebyvpn.site ssh-ed25519 abc\n",b"key",b"key"]
            ),
            mock.patch.object(registration,"require_runtime"),
            mock.patch.object(registration,"await_expiration_once"),
            mock.patch.object(registration.Path,"resolve",
                return_value=registration.Path(
                    "/opt/mnebyvpn-controller/releases/reviewed-release")),
            mock.patch.object(registration.Path,"is_dir",return_value=True),
            mock.patch.object(registration,"db_state",
                              side_effect=["approved", "approved", "approved"]),
            mock.patch.object(registration,"execute",side_effect=cmd),
        ):
            with self.assertRaises(registration.GateError):
                registration.main()
        self.assertFalse(any(c[0]=="systemd-run" for c in commands))

    def test_transient_stdout_decoration_not_a_substitute_for_db_readback(self):
        node=bytes.fromhex("302a300506032b6570032100")+bytes(32)
        def cmd(args,timeout=12):
            if args[:2]==["systemctl","show"]:return "no"
            if args[0]=="systemd-run":return "Finished with result: success"
            return ""
        with (
            mock.patch.object(registration.os,"geteuid",return_value=0),
            mock.patch.object(registration,"assigned_ip",return_value=True),
            mock.patch.object(registration,"spki",return_value=node),
            mock.patch.object(
                registration,"protected",
                side_effect=[b"fi.mnebyvpn.site ssh-ed25519 abc\n",b"key",b"key"]
            ),
            mock.patch.object(registration,"require_runtime"),
            mock.patch.object(registration,"await_expiration_once"),
            mock.patch.object(registration.Path,"resolve",
                return_value=registration.Path(
                    "/opt/mnebyvpn-controller/releases/reviewed-release")),
            mock.patch.object(registration.Path,"is_dir",return_value=True),
            mock.patch.object(registration,"db_state",
                              side_effect=["approved", "approved", "approved", "approved"]),
            mock.patch.object(registration,"execute",side_effect=cmd),
        ):
            with self.assertRaises(registration.GateError):
                registration.main()

    def test_transient_stderr_classification_does_not_expose_raw_diagnostic(self):
        from io import StringIO
        from contextlib import redirect_stdout
        proc = mock.Mock(returncode=0,stdout="Running as unit: transient\n",
                         stderr="FI_ENROLLMENT_STOPPED confidential-canary\n")
        with mock.patch.object(registration.subprocess,"run",return_value=proc):
            out=StringIO()
            with redirect_stdout(out):
                registration.execute(
                    ["systemd-run","--unit=mnebyvpn-fi-controller-transient"],
                    timeout=4
                )
            safe=out.getvalue()
            self.assertIn("FI_TRANSIENT_APP_STOPPED_MARKER=true",safe)
            self.assertIn("FI_TRANSIENT_APP_SUCCESS_MARKER=false",safe)
            self.assertNotIn("confidential-canary",safe)

    def test_embedded_signed_enrollment_js_has_valid_module_syntax(self):
        import shutil
        import subprocess
        self.assertIn("enrollApprovedFiNode",registration.FI_SIGNED_ENROLL_JS)
        self.assertIn("process.env.DATABASE_URL",registration.FI_SIGNED_ENROLL_JS)
        self.assertIn("SUBSCRIBER_PUBLICATION=false",registration.FI_SIGNED_ENROLL_JS)
        self.assertNotIn("console.log(error)",registration.FI_SIGNED_ENROLL_JS)
        if shutil.which("node"):
            result=subprocess.run(
                ["node","--input-type=module","--check"],
                input=registration.FI_SIGNED_ENROLL_JS,
                capture_output=True,text=True,timeout=10
            )
            self.assertEqual(result.returncode,0,"JS parser rejected signed enrollment script")

    def test_pending_challenge_query_uses_canonical_registrar_database(self):
        with mock.patch.object(
            registration,"execute",return_value="FI_PENDING_CHALLENGE_SECONDS=275"
        ) as cmd:
            self.assertEqual(registration.pending_challenge_seconds(),275)
            args=cmd.call_args.args[0]
            self.assertEqual(args[0],"systemd-run")
            self.assertIn("--property=IPAddressDeny=any",args)
            self.assertIn(
                "--property=EnvironmentFile=/root/mnebyvpn-controller/config/fi-enrollment.env",
                args
            )
            self.assertIn("vpn_node_enrollment_challenges",registration.PENDING_CHALLENGE_JS)

    def test_malformed_or_long_pending_challenge_wait_is_rejected(self):
        for raw in ("", "FI_PENDING_CHALLENGE_SECONDS=-1",
                    "FI_PENDING_CHALLENGE_SECONDS=301",
                    "FI_PENDING_CHALLENGE_SECONDS=bad",
                    "FI_PENDING_CHALLENGE_SECONDS=3\nFI_PENDING_CHALLENGE_SECONDS=3"):
            with self.subTest(raw=raw), mock.patch.object(
                registration,"execute",return_value=raw
            ):
                with self.assertRaises(registration.GateError):
                    registration.pending_challenge_seconds()

    def test_waits_for_original_expiry_and_never_mutates_challenge(self):
        with (
            mock.patch.object(registration,"pending_challenge_seconds",
                              side_effect=[87,0]) as pending,
            mock.patch("time.sleep") as sleep,
        ):
            registration.await_expiration_once()
            sleep.assert_called_once_with(89)
            self.assertEqual(pending.call_count,2)

    def test_fails_closed_if_challenge_remains_after_original_expiry(self):
        with (
            mock.patch.object(registration,"pending_challenge_seconds",
                              side_effect=[300,1]),
            mock.patch("time.sleep"),
        ):
            with self.assertRaises(registration.GateError):
                registration.await_expiration_once()

    def test_shortened_signed_db_challenge_preserves_one_use_proof_fields(self):
        """Exercise the exact embedded JS transport adapter with disposable keys."""
        import shutil
        import subprocess
        if not shutil.which("node"):
            self.skipTest("Node.js unavailable")
        source=registration.FI_SIGNED_ENROLL_JS
        start=source.index("function shortenSignedChallenge(")
        end=source.index("\nlet db;",start)
        function=source[start:end]
        harness=r"""
import assert from 'node:assert/strict';
import {generateKeyPairSync,createPublicKey,sign,verify} from 'node:crypto';
const spawnSync=(bin,args,options)=>({status:0,stdout:options.input,stderr:''});
const enrollmentControllerChallengeMessage=(c)=>Buffer.from(JSON.stringify([
  'MNEBYVPN_ENROLL_CHALLENGE_V1',
  c.nodeId,c.endpointHost,c.publicSpki,c.challengeId,c.nonce,
  c.expiresAt.toISOString()
]));
"""
        harness += function
        harness += r"""
const keys=generateKeyPairSync('ed25519');
const challenge={
  challengeId:'a73995b5-3b77-4cb4-8048-4f35d369b283',
  nodeId:'fi-test-01',
  endpointHost:'fi.mnebyvpn.site',
  publicSpki:'A'.repeat(59),
  nonce:'B'.repeat(43),
  expiresAt:new Date(Date.now()+299000).toISOString()
};
challenge.controllerSignature=sign(null,enrollmentControllerChallengeMessage({
  ...challenge,expiresAt:new Date(challenge.expiresAt)
}),keys.privateKey).toString('base64url');
const original=JSON.stringify(challenge)+'\n';
const result=shortenSignedChallenge('/usr/bin/ssh',['-F','/dev/null'],{
  input:original,encoding:'utf8',timeout:20000,maxBuffer:2048
},keys.privateKey);
const revised=JSON.parse(result.stdout);
assert.equal(revised.challengeId,challenge.challengeId);
assert.equal(revised.nonce,challenge.nonce);
assert.equal(revised.nodeId,challenge.nodeId);
assert.equal(revised.publicSpki,challenge.publicSpki);
assert.ok(Date.parse(revised.expiresAt)<=Date.now()+150000);
assert.ok(Date.parse(revised.expiresAt)>Date.now()+140000);
assert.ok(verify(null,enrollmentControllerChallengeMessage({
  ...revised,expiresAt:new Date(revised.expiresAt)
}),createPublicKey(keys.privateKey),Buffer.from(revised.controllerSignature,'base64url')));
assert.notEqual(revised.controllerSignature,challenge.controllerSignature);
assert.equal(challenge.expiresAt,JSON.parse(original).expiresAt);
const tampered={...challenge,nonce:'C'.repeat(43)};
assert.throws(()=>shortenSignedChallenge('/usr/bin/ssh',[],{
  input:JSON.stringify(tampered),encoding:'utf8'
},keys.privateKey),/untrusted/);
assert.throws(()=>shortenSignedChallenge('/usr/bin/bash',[],{
  input:original,encoding:'utf8'
},keys.privateKey),/transport/);
console.log('FI_SIGNED_TTL_TEST=passed');
"""
        result=subprocess.run(["node","--input-type=module"],
                              input=harness,capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,
                         "Synthetic Ed25519 shortened challenge verification failed")
        self.assertIn("FI_SIGNED_TTL_TEST=passed",result.stdout)
