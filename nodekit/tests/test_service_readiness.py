import hashlib
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import service_readiness as audit

PUBLIC = bytes.fromhex("302a300506032b6570032100") + bytes(range(32))
IDENTITY_SHA = hashlib.sha256(PUBLIC).hexdigest()
DATA = b"verified staged candidate"
DIGEST = hashlib.sha256(DATA).hexdigest()

class TestServiceReadiness(unittest.TestCase):
    def test_missing_dns_and_tls_are_not_implicitly_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            node = pathlib.Path(tmp) / audit.NODE_REVIEWED
            node.mkdir()
            self.assertFalse(audit.dns_proxy_stage(node)["ready"])
            self.assertFalse(audit.tls_stage(node, audit.HOST_REVIEWED)["staged"])

    def test_valid_staged_dns_proxy_is_still_closed_to_customers(self):
        with tempfile.TemporaryDirectory() as tmp:
            node = pathlib.Path(tmp) / audit.NODE_REVIEWED
            stage = node / "dns-proxy"
            stage.mkdir(parents=True)
            meta = {
                "node_id": node.name, "state": "staged",
                "activation_enabled": False,
                "personal_dns_enabled": False,
                "open_proxy_enabled": False, "open_resolver_enabled": False,
                "external_e2e_verified": False, "route_count": 0,
                "config_sha256": {"Corefile": DIGEST, "nginx.conf": DIGEST},
            }
            with patch.object(audit, "safe_dir"), \
                 patch.object(audit, "safe_manifest", return_value=meta), \
                 patch.object(audit, "protected_file", return_value=DATA):
                report = audit.dns_proxy_stage(node)
                self.assertTrue(report["staged"])
                self.assertFalse(report["ready"])
                self.assertFalse(report["personal_access_verified"])
                for invalid in ({"open_resolver_enabled": True},
                                {"personal_dns_enabled": True},
                                {"external_e2e_verified": True},
                                {"route_count": 500}):
                    changed = {**meta, **invalid}
                    with patch.object(audit, "safe_manifest", return_value=changed):
                        with self.assertRaises(audit.ServiceReadinessError):
                            audit.dns_proxy_stage(node)

    def test_tampered_staged_dns_hash_is_hard_error(self):
        with patch.object(audit, "protected_file", return_value=b"tampered"):
            with self.assertRaises(audit.ServiceReadinessError):
                audit.checked_file(pathlib.Path("Corefile"), DIGEST)

    def test_staged_fi_certificate_does_not_prove_personal_wildcard(self):
        with tempfile.TemporaryDirectory() as tmp:
            node = pathlib.Path(tmp) / audit.NODE_REVIEWED
            (node / "tls").mkdir(parents=True)
            meta = {
                "node_id": node.name, "hostname": audit.HOST_REVIEWED,
                "state": "certificate_staged", "activation_enabled": False,
                "personal_dns_enabled": False, "published": False,
                "certificate_sha256": DIGEST,
            }
            with patch.object(audit, "safe_dir"), \
                 patch.object(audit, "safe_manifest", return_value=meta), \
                 patch.object(audit, "protected_file", return_value=DATA):
                out = audit.tls_stage(node, audit.HOST_REVIEWED)
                self.assertTrue(out["staged"])
                self.assertFalse(out["personal_fqdn_tls_verified"])
                with patch.object(audit, "safe_manifest",
                                  return_value={**meta, "published": True}):
                    with self.assertRaises(audit.ServiceReadinessError):
                        audit.tls_stage(node, audit.HOST_REVIEWED)

    def test_all_local_components_present_never_self_authorize_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            node = pathlib.Path(tmp) / audit.NODE_REVIEWED
            node.mkdir()
            manifest = {
                "node_id": node.name, "advertise_host": audit.HOST_REVIEWED,
                "activation_enabled": False, "registration_enabled": False,
            }
            awg = {
                "control_plane_prerequisites_met": True,
                "watchdog_unit_installed": True,
                "egress_unit_installed": True,
                "controller_public_key_independently_pinned": True,
            }
            candidate = {"staged": True, "route_count": 10, "blockers": []}
            tls = {"staged": True, "personal_fqdn_tls_verified": False,
                   "blockers": []}
            with patch.object(audit.os, "geteuid", return_value=0), \
                 patch.object(audit, "safe_manifest", return_value=manifest), \
                 patch.object(audit, "protected_file", return_value=PUBLIC), \
                 patch.object(audit, "dns_proxy_stage", return_value=candidate), \
                 patch.object(audit, "tls_stage", return_value=tls), \
                 patch.object(audit, "awg_controller_inspect", return_value=awg):
                report = audit.assess(node, audit.HOST_REVIEWED, IDENTITY_SHA,
                                      "c" * 64)
                self.assertTrue(report["controller_enrollment_candidate"])
                self.assertFalse(report["controller_enrollment_verified"])
                self.assertFalse(report["automatic_publication_authorized"])
                self.assertFalse(report["existing_clients_changed"])
                self.assertEqual(set(report["services"]),
                                 {"personal_dns", "dns_sni_transport", "telegram_proxy", "amneziawg"})
                self.assertEqual(report["schema_version"], 2)
                self.assertEqual(report["controller_host"], "188.120.254.223")
                self.assertEqual(report["services"]["telegram_proxy"]["implementation"],
                                 "telemt_mtproto")
                self.assertFalse(report["services"]["telegram_proxy"]["telemt_installed_verified"])
                self.assertNotEqual(report["services"]["telegram_proxy"]["blockers"],
                                    report["services"]["dns_sni_transport"]["blockers"])
                self.assertTrue(all(not service["ready"] for service in
                                    report["services"].values()))
                with self.assertRaises(audit.ServiceReadinessError):
                    audit.assess(node, audit.HOST_REVIEWED, "f" * 64)

    def test_active_awg_node_cannot_implicitly_enable_dns_or_telemt(self):
        with tempfile.TemporaryDirectory() as tmp:
            node = pathlib.Path(tmp) / audit.NODE_REVIEWED
            node.mkdir()
            manifest = {
                "state": "active",
                "node_id": node.name,
                "advertise_host": audit.HOST_REVIEWED,
                "activation_enabled": True,
                "registration_enabled": True,
            }
            awg = {
                "control_plane_prerequisites_met": False,
                "watchdog_unit_installed": True,
                "egress_unit_installed": True,
                "controller_public_key_independently_pinned": True,
            }
            candidate = {"staged": True, "route_count": 0,
                         "blockers": ["personal_dns_authorization_missing"]}
            tls = {"staged": False, "personal_fqdn_tls_verified": False,
                   "blockers": ["tls_stage_missing"]}
            with patch.object(audit.os, "geteuid", return_value=0), \
                 patch.object(audit, "safe_manifest", return_value=manifest), \
                 patch.object(audit, "protected_file", return_value=PUBLIC), \
                 patch.object(audit, "dns_proxy_stage", return_value=candidate), \
                 patch.object(audit, "tls_stage", return_value=tls), \
                 patch.object(audit, "awg_controller_inspect", return_value=awg):
                report = audit.assess(
                    node, audit.HOST_REVIEWED, IDENTITY_SHA)
            self.assertFalse(report["automatic_publication_authorized"])
            self.assertFalse(report["existing_clients_changed"])
            self.assertFalse(report["services"]["personal_dns"]["ready"])
            self.assertFalse(report["services"]["telegram_proxy"]["ready"])
            self.assertFalse(report["services"]["dns_sni_transport"]["ready"])
            self.assertFalse(report["services"]["personal_dns"]["local_candidate_verified"])

    def test_active_awg_manifest_with_false_flags_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            node = pathlib.Path(tmp) / audit.NODE_REVIEWED
            node.mkdir()
            invalid = {
                "state": "active", "node_id": node.name,
                "advertise_host": audit.HOST_REVIEWED,
                "activation_enabled": False,
                "registration_enabled": False,
            }
            with patch.object(audit.os, "geteuid", return_value=0), \
                 patch.object(audit, "safe_manifest", return_value=invalid):
                with self.assertRaises(audit.ServiceReadinessError):
                    audit.assess(node, audit.HOST_REVIEWED, IDENTITY_SHA)

    def test_unexpected_vps_is_never_a_release_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            node = pathlib.Path(tmp) / "de-test-01"
            node.mkdir()
            with patch.object(audit.os, "geteuid", return_value=0):
                with self.assertRaises(audit.ServiceReadinessError):
                    audit.assess(node, "de.mnebyvpn.site", IDENTITY_SHA)

if __name__ == "__main__":
    unittest.main()
