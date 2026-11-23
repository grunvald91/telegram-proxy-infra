import copy
import importlib.util
import pathlib
import unittest
from unittest.mock import Mock, patch

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "scripts/mnebyvpn-vpn-provisioner.py"
spec = importlib.util.spec_from_file_location("de89_provisioner_under_test", SOURCE)
provisioner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provisioner)


class FakeChild:
    def __init__(self, alive=True):
        self.alive = alive

    def poll(self):
        return None if self.alive else 12


class NonDisruptiveProvisioningTests(unittest.TestCase):
    @staticmethod
    def item(enabled=True, revision=1, expiry="2026-12-30T00:00:00+00:00"):
        return {
            "credential": "123e4567-e89b-42d3-a456-426614174000",
            "enabled": enabled,
            "revision": revision,
            "expiresAt": expiry if enabled else None,
        }

    def agent(self, before, *, alive=True):
        agent = provisioner.Agent.__new__(provisioner.Agent)
        agent.state = copy.deepcopy(before)
        agent.child = FakeChild(alive)
        agent._shutdown_child = Mock()
        agent._rewrite = Mock()
        agent._spawn = Mock()
        return agent

    def test_renewal_only_persists_without_interrupting_existing_sessions(self):
        before = {"customer": self.item()}
        after = {"customer": self.item(revision=2, expiry="2027-01-15T00:00:00+00:00")}
        agent = self.agent(before)
        with patch.object(provisioner, "atomic_json") as save:
            agent._commit(after)
        save.assert_called_once_with(provisioner.STATE, after)
        agent._shutdown_child.assert_not_called()
        agent._rewrite.assert_not_called()
        agent._spawn.assert_not_called()
        self.assertEqual(agent.state, after)

    def test_no_enabled_clients_changing_revision_does_not_restart(self):
        before = {"customer": self.item(enabled=False)}
        after = {"customer": self.item(enabled=False, revision=3)}
        agent = self.agent(before)
        with patch.object(provisioner, "atomic_json") as save:
            agent._commit(after)
        save.assert_called_once()
        agent._shutdown_child.assert_not_called()
        agent._spawn.assert_not_called()

    def test_expiry_sweep_revocation_still_restarts_to_remove_credentials(self):
        before = {"customer": self.item(enabled=True, expiry="2020-01-01T00:00:00+00:00")}
        after = {"customer": self.item(enabled=False)}
        agent = self.agent(before)
        with patch.object(provisioner, "atomic_json") as save:
            agent._commit(after)
        agent._shutdown_child.assert_called_once()
        agent._rewrite.assert_called_once_with(after)
        agent._spawn.assert_called_once()
        save.assert_called_once_with(provisioner.STATE, after)

    def test_new_active_client_still_updates_live_xray_configuration(self):
        before = {"existing": self.item(enabled=False)}
        after = {"existing": self.item(enabled=False),
                 "new": dict(self.item(), credential="123e4567-e89b-42d3-a456-426614174001")}
        agent = self.agent(before)
        with patch.object(provisioner, "atomic_json") as save:
            agent._commit(after)
        agent._shutdown_child.assert_called_once()
        agent._rewrite.assert_called_once_with(after)
        agent._spawn.assert_called_once()
        save.assert_called_once()

    def test_dead_xray_child_is_not_treated_as_safe_noop(self):
        before = {"customer": self.item()}
        after = {"customer": self.item(revision=2)}
        agent = self.agent(before, alive=False)
        with patch.object(provisioner, "atomic_json"):
            agent._commit(after)
        agent._shutdown_child.assert_called_once()
        agent._spawn.assert_called_once()

    def test_failed_persistence_does_not_acknowledge_renewal(self):
        before = {"customer": self.item()}
        after = {"customer": self.item(revision=2)}
        agent = self.agent(before)
        with patch.object(provisioner, "atomic_json", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                agent._commit(after)
        self.assertEqual(agent.state, before)
        agent._shutdown_child.assert_not_called()
        agent._spawn.assert_not_called()

    def test_xray_log_redaction_strips_uuids_and_ips_with_bounded_length(self):
        line = (
            "2026/11/23 [Warning] failed client 123e4567-e89b-42d3-a456-426614174000 "
            "from 95.165.10.20:54321 -> 89.125.90.101:8443 " + ("x" * 400)
        )
        redacted = provisioner.redact_xray_log_line(line)
        self.assertNotIn("123e4567-e89b-42d3-a456-426614174000", redacted)
        self.assertNotIn("95.165.10.20", redacted)
        self.assertNotIn("89.125.90.101", redacted)
        self.assertIn("[redacted-uuid]", redacted)
        self.assertIn("[redacted-ip]", redacted)
        self.assertLessEqual(len(redacted), 300)


if __name__ == "__main__":
    unittest.main()
