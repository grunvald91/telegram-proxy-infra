"""FI217 real disposable signed apply/revoke: crypto and rollback preflight."""
from __future__ import annotations
import base64
import contextlib
import datetime as dt
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import fi_awg_applied_disposable_canary as mod
import fi_awg_signed_canary as issuer

class AppliedCanaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src=(ROOT/"fi_awg_applied_disposable_canary.py").read_text()

    def build(self,op,revision):
        now=dt.datetime.now(dt.timezone.utc)
        return dict(nodeId=issuer.NODE_ID,entitlementId="11111111-2222-4333-8444-555555555555",
                    op=op,revision=revision,peerPublicKey=base64.b64encode(bytes(range(32))).decode(),
                    clientIpv4=issuer.IP,issuedAt=issuer.iso(now),
                    expiresAt=issuer.iso(now+dt.timedelta(seconds=120)) if op=="grant" else None,
                    nonce=("a" if op=="grant" else "b")*64,signature="A"*86)

    def test_independent_timer_before_any_live_awg_start(self):
        src=self.src
        self.assertIn("fi-awg-disposable-apply-expiry",src)
        self.assertIn('"--on-active=95s"',src)
        self.assertIn("cleaned=safe_cleanup(data[\"grant\"])",src)
        self.assertLess(src.index('"--on-active=95s"'),src.index('["/usr/bin/systemctl","start",UNIT]'))
        self.assertIn("if LEDGER.exists() or LEDGER.is_symlink():",src)
        self.assertIn("if not cleaned:",src)
        self.assertIn('block("cleanup_unverified_systemd_timer_remains_armed")',src)
        self.assertNotIn("vpn_release_flags SET",src)
        self.assertNotIn("UPDATE entitlements",src)

    def test_redacted_live_failure_diagnostics(self):
        # A production failure previously surfaced only as exit code 2;
        # diagnostics must never echo a signed bundle or subprocess output.
        import ast
        ast.parse(self.src)
        expected = (
            "SIGNED_COMMANDS_VERIFIED",
            "STAGED_AWG_INTEGRITY_VERIFIED",
            "SYSTEMD_DORMANT_VERIFIED",
            "DISPOSABLE_PREFLIGHT_PASSED",
            "WATCHDOG_INSTALL_BEGIN",
            "WATCHDOG_INSTALLED",
            "INDEPENDENT_KILL_TIMER_ARMED",
            "AWG_STARTED",
            "WATCHDOG_STARTED",
            "SIGNED_GRANT_APPLIED",
            "SIGNED_REVOKE_APPLIED",
            "DISPOSABLE_CLEANUP_VERIFIED",
        )
        for phase in expected:
            self.assertIn('phase("' + phase + '")', self.src)
        self.assertIn('FI_AWG_APPLY_FAILURE_CLASS=', self.src)
        self.assertNotIn('print(str(exc)', self.src)
        self.assertNotIn('traceback.print_exc(', self.src)
        with contextlib.redirect_stderr(io.StringIO()) as output:
            mod.phase("SIGNED_COMMANDS_VERIFIED")
        self.assertEqual(output.getvalue(), "FI_AWG_APPLY_PHASE=SIGNED_COMMANDS_VERIFIED" + chr(10))

    def test_watchdog_installer_drift_is_readonly_and_fail_closed(self):
        target = mock.Mock()
        target.is_symlink.return_value = False
        target.exists.return_value = True
        target.is_file.return_value = True
        target.stat.return_value = mock.Mock(st_uid=0, st_mode=0o644)
        target.read_bytes.return_value = b"old"
        self.assertEqual(mod.watchdog_file_state(target, b"new"), "DRIFT")
        self.assertEqual(mod.watchdog_file_state(target, b"old"), "MATCH")
        target.is_symlink.return_value = True
        self.assertEqual(mod.watchdog_file_state(target, b"old"), "SYMLINK")
        target.write_bytes.assert_not_called()
        target.unlink.assert_not_called()
        self.assertIn('block("watchdog_authorizer_install_drift")', self.src)
        self.assertIn('block("watchdog_systemd_unit_install_drift")', self.src)
        self.assertIn("WATCHDOG_AUTHORIZER_OLD_SHA256_", self.src)
        self.assertIn("WATCHDOG_AUTHORIZER_NEW_SHA256_", self.src)

    def test_pinned_authorizer_migration_rejects_unrecognized_code(self):
        old, new = b"approved-legacy-sample", b"candidate-sample"
        sha_old, sha_new = hashlib.sha256(old).hexdigest(), hashlib.sha256(new).hexdigest()
        self.assertFalse(mod.authorizer_upgrade_allowed(old, new))
        with mock.patch.object(mod, "LEGACY_AUTHORIZER_SHA256", sha_old):
            with mock.patch.object(mod, "CANDIDATE_AUTHORIZER_SHA256", sha_new):
                self.assertTrue(mod.authorizer_upgrade_allowed(old, new))
                self.assertFalse(mod.authorizer_upgrade_allowed(b"unknown", new))
                self.assertFalse(mod.authorizer_upgrade_allowed(old, b"unknown"))
        for required in ("os.O_EXCL", "os.O_NOFOLLOW", "os.fsync(",
                         "os.replace(", "authorizer_upgrade_backup_already_exists",
                         "authorizer_upgrade_service_enabled",
                         "WATCHDOG_AUTHORIZER_PINNED_MIGRATION_APPLIED"):
            self.assertIn(required, self.src)

    def test_cleanup_service_states_are_whitelisted_and_timer_fail_closed(self):
        with mock.patch.object(mod, "command") as runner:
            runner.return_value = subprocess.CompletedProcess([], 0, "failed\n", "")
            self.assertEqual(mod.systemd_active_state("example"), "failed")
            runner.return_value = subprocess.CompletedProcess([], 0, "secret-token\n", "")
            self.assertEqual(mod.systemd_active_state("example"), "unknown")
            runner.return_value = subprocess.CompletedProcess([], 2, "inactive\n", "")
            self.assertEqual(mod.systemd_active_state("example"), "unknown")
        for marker in (
            "CLEANUP_STOP_",
            "CLEANUP_AWG_INTERFACE_PRESENT",
            "CLEANUP_PEER_LEDGER_PRESENT",
            "CLEANUP_LEDGER_NOT_EXACT_TEST_ENTITLEMENT",
            "CLEANUP_TIMER_STATE_",
        ):
            self.assertIn(marker, self.src)
        self.assertIn('phase("CLEANUP_"+label+"_STATE_"+state.upper())', self.src)
        self.assertIn('return timer.returncode==0 and state=="inactive"', self.src)

    def test_postcanary_residual_inventory_remains_read_only(self):
        with mock.patch.object(mod, "LEDGER") as ledger:
            ledger.is_symlink.return_value = False
            ledger.exists.return_value = False
            self.assertEqual(mod.residual_ledger_status(), "ABSENT")
            ledger.read_bytes.assert_not_called()
            ledger.unlink.assert_not_called()
        self.assertIn('phase("PREFLIGHT_LEDGER_"+ledger_status)', self.src)
        self.assertIn('phase("PREFLIGHT_INTERFACE_"+', self.src)
        self.assertIn('states[label]=systemd_active_state(unit)', self.src)
        self.assertIn('return "ONLY_REVOKED_DISPOSABLE"', self.src)
        self.assertIn('return "OTHER_ENTITLEMENTS_PRESENT"', self.src)
        self.assertIn('block("existing_awg_or_expiry_timer")', self.src)

    def test_previous_revoked_disposable_is_archived_before_systemd_reset(self):
        grant = self.build("grant", 1)
        state = {"schema_version": 1, "node_id": issuer.NODE_ID,
                 "grants": {grant["entitlementId"]: {
                     "revision": 2, "peerPublicKey": grant["peerPublicKey"],
                     "clientIpv4": issuer.IP, "enabled": False, "expiresAt": None}}}
        with tempfile.TemporaryDirectory() as folder:
            ledger = Path(folder) / "peer-grants.json"
            ledger.write_text(json.dumps(state))
            original = ledger.read_bytes()
            reset = {"done": False}
            def state_of(unit):
                return ("inactive" if reset["done"] else "failed") if unit == mod.UNIT else "inactive"
            def run(args, timeout=9):
                if "reset-failed" in args:
                    reset["done"] = True
                return subprocess.CompletedProcess(args, 0, "", "")
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(mod, "LEDGER", ledger))
                stack.enter_context(mock.patch.object(issuer, "is_host", return_value=True))
                stack.enter_context(mock.patch.object(issuer, "protected",
                    side_effect=lambda path, maximum=50000: path.read_bytes()))
                stack.enter_context(mock.patch.object(mod, "systemd_active_state",
                    side_effect=state_of))
                stack.enter_context(mock.patch.object(mod, "command", side_effect=run))
                stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                self.assertFalse(mod.recover_revoked_previous_canary(
                    {"AWG":"active","WATCHDOG":"inactive","TIMER":"inactive"},
                    False, "ONLY_REVOKED_DISPOSABLE"))
                self.assertTrue(ledger.exists())
                self.assertTrue(mod.recover_revoked_previous_canary(
                    {"AWG":"failed","WATCHDOG":"inactive","TIMER":"inactive"},
                    False, "ONLY_REVOKED_DISPOSABLE"))
                self.assertFalse(ledger.exists())
                backups=list(Path(folder).glob(".peer-grants.fi217-revoked-*.bak"))
                self.assertEqual(len(backups), 1)
                self.assertEqual(backups[0].read_bytes(), original)

    def test_safe_cleanup_resets_failed_unit_only_after_exact_revoked_ledger(self):
        grant = self.build("grant", 1)
        state = {"schema_version": 1, "node_id": issuer.NODE_ID,
                 "grants": {grant["entitlementId"]: {
                     "revision": 2, "peerPublicKey": grant["peerPublicKey"],
                     "clientIpv4": issuer.IP, "enabled": False, "expiresAt": None}}}
        with tempfile.TemporaryDirectory() as folder:
            ledger = Path(folder) / "peer-grants.json"
            ledger.write_text(json.dumps(state))
            command_args=[]
            def run(args, timeout=20):
                command_args.append(args)
                return subprocess.CompletedProcess(args,0,"","")
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(mod,"LEDGER",ledger))
                stack.enter_context(mock.patch.object(issuer,"protected",
                    side_effect=lambda path, maximum=50000: path.read_bytes()))
                stack.enter_context(mock.patch.object(mod,"systemd_active_state",
                    side_effect=["inactive","failed","inactive","inactive"]))
                stack.enter_context(mock.patch.object(mod,"command",side_effect=run))
                stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                self.assertTrue(mod.safe_cleanup(grant))
            self.assertFalse(ledger.exists())
            self.assertTrue(any("reset-failed" in cmd for cmd in command_args))
            self.assertTrue(any(mod.TIMER+".timer" in cmd for cmd in command_args))

    def test_verified_node_receipts_are_real_applied_domain(self):
        with tempfile.TemporaryDirectory() as folder:
            tmp=Path(folder)
            private,pub=tmp/"private.pk8",tmp/"public.spki"
            for args in (
                ["openssl","genpkey","-algorithm","Ed25519","-outform","DER","-out",str(private)],
                ["openssl","pkey","-inform","DER","-in",str(private),
                 "-pubout","-outform","DER","-out",str(pub)]
            ):
                subprocess.run(args,check=True,capture_output=True,timeout=8)
            signed={"version":1,"nodeId":issuer.NODE_ID,
                    "grant":self.build("grant",1),"revoke":self.build("revoke",2)}
            bundle=tmp/"signed.json"
            bundle.write_text(json.dumps(signed))
            receipts={}
            for op in ("grant","revoke"):
                cmd=signed[op]
                receipt=dict(nodeId=issuer.NODE_ID,op=op,entitlementId=cmd["entitlementId"],
                             revision=cmd["revision"],
                             commandSha256=hashlib.sha256(issuer.message(cmd)).hexdigest(),
                             appliedAt=issuer.iso(dt.datetime.now(dt.timezone.utc)),
                             nonce=("c" if op=="grant" else "d")*64)
                raw=json.dumps(["MNEBYVPN_AWG_APPLIED_V1",issuer.NODE_ID,op,
                  receipt["entitlementId"],receipt["revision"],receipt["commandSha256"],
                  receipt["appliedAt"],receipt["nonce"]],separators=(",",":"),ensure_ascii=False).encode()
                payload,sig=tmp/(op+"-payload"),tmp/(op+"-signature")
                payload.write_bytes(raw)
                subprocess.run(["openssl","pkeyutl","-sign","-inkey",str(private),
                    "-keyform","DER","-rawin","-in",str(payload),"-out",str(sig)],
                    check=True,capture_output=True,timeout=8)
                receipt["signature"]=base64.urlsafe_b64encode(sig.read_bytes()).rstrip(b"=").decode()
                receipts[op+"Receipt"]=receipt
            report={"version":1,"nodeId":issuer.NODE_ID,
                    "publicCustomerRelease":False,"realGrantApplied":True,
                    "realRevokeApplied":True,"peersLeft":0,**receipts}
            receipt_file=tmp/"receipts.json"
            receipt_file.write_text(json.dumps(report))
            sha=hashlib.sha256(pub.read_bytes()).hexdigest()
            with mock.patch.object(issuer,"NODE_SHA",sha):
                with contextlib.redirect_stdout(io.StringIO()) as buffer:
                    mod.verify_output(bundle,receipt_file,pub)
                self.assertIn("SIGNED_REVOKE_ACK=true",buffer.getvalue())
                bad=json.loads(json.dumps(report))
                bad["grantReceipt"]["nonce"]="f"*64
                receipt_file.write_text(json.dumps(bad))
                with self.assertRaises(mod.CanaryBlocked):
                    mod.verify_output(bundle,receipt_file,pub)
                bad=json.loads(json.dumps(report))
                bad["publicCustomerRelease"]=True
                receipt_file.write_text(json.dumps(bad))
                with self.assertRaises(mod.CanaryBlocked):
                    mod.verify_output(bundle,receipt_file,pub)
if __name__=="__main__":unittest.main()
