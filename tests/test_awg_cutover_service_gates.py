import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('gate', ROOT / 'scripts/mnebydns-awg-data-health-20261116.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

class Gates(unittest.TestCase):
    def test_actual_public_dns_listener(self):
        self.assertIn(('89.125.90.101', 853, 'dns.mnebyvpn.site'), gate.targets('RU'))
        self.assertNotIn(('10.66.77.1', 853, 'dns.mnebyvpn.site'), gate.targets('RU'))

    def test_every_required_service_failure_blocks(self):
        for role in ('RU', 'DE'):
            for target in gate.targets(role):
                def probe(*actual):
                    if actual == target:
                        raise ConnectionRefusedError()
                self.assertFalse(gate.check(role, probe))
            self.assertTrue(gate.check(role, lambda *args: None))

    def test_no_push_cutover_and_baseline_precedes_mutations(self):
        s = (ROOT / '.github/workflows/mnebydns-awg-production-cutover-20261116.yml').read_text()
        self.assertNotIn('  push:', s)
        self.assertIn('default: verify', s)
        self.assertIn("if: inputs.operation == 'cutover'", s)
        self.assertLess(s.index('AWG_BASELINE_SERVICES_OK=true'), s.index('manage.sh arm DE'))
        self.assertEqual(s.count("'python3 - RU' < scripts/mnebydns-awg-data-health-20261116.py"), 2)
        self.assertEqual(s.count("'python3 - DE' < scripts/mnebydns-awg-data-health-20261116.py"), 2)

if __name__ == '__main__': unittest.main()
