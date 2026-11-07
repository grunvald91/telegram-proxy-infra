"""Pure agent contract tests: no Xray, network, customer files or VPS changes."""
import datetime as dt
import importlib.util
from pathlib import Path
import threading
import unittest
from unittest.mock import Mock

spec = importlib.util.spec_from_file_location('agent', Path(__file__).parents[1] / 'scripts/mnebyvpn-vpn-provisioner.py')
agent_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent_module)

class RenewalTests(unittest.TestCase):
    def setUp(self):
        self.agent = agent_module.Agent.__new__(agent_module.Agent)
        self.agent.lock = threading.RLock()
        self.agent.sweep = Mock()
        self.identifier = '11111111-1111-4111-8111-111111111111'
        self.credential = '22222222-2222-4222-8222-222222222222'
        self.agent.state = {self.identifier: {
            'enabled': True, 'revision': 1, 'credential': self.credential,
            'expiresAt': (agent_module.utcnow() + dt.timedelta(days=30)).isoformat(),
        }}
        self.agent._commit = lambda candidate: setattr(self.agent, 'state', candidate)

    def test_90_day_renewal_with_30_days_remaining_keeps_credential(self):
        deadline = (agent_module.utcnow() + dt.timedelta(days=120)).isoformat()
        request = dict(op='apply', id=self.identifier, enabled=True, revision=2, expiresAt=deadline)
        self.assertEqual(self.agent.operation(request), {'status': 'applied', 'revision': 2})
        self.assertEqual(self.agent.state[self.identifier]['credential'], self.credential)
        self.assertEqual(self.agent.state[self.identifier]['expiresAt'], deadline)
        self.assertEqual(self.agent.operation(request), {'status': 'applied', 'revision': 2})

    def test_unbounded_or_elapsed_deadlines_still_rejected(self):
        for days in [-1, 4000]:
            request = dict(op='apply', id=self.identifier, enabled=True, revision=2,
                           expiresAt=(agent_module.utcnow() + dt.timedelta(days=days)).isoformat())
            with self.assertRaises(ValueError):
                self.agent.operation(request)
        self.assertEqual(self.agent.state[self.identifier]['revision'], 1)

if __name__ == '__main__':
    unittest.main()
