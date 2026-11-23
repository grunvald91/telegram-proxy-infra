"""Guard the one-shot FI service-audit copy list against import regressions.

The runner copies Python scripts to a temporary directory on FI217. The
dependency list must include the recently added Telemt and its helper
without activating any public service on the host.
"""
from pathlib import Path
import ast
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/nodekit-fi-service-readiness-once.yml"

class FiServiceReadinessWorkflowTests(unittest.TestCase):
    def test_copies_transitive_local_dependencies(self):
        content = WORKFLOW.read_text(encoding="utf-8")
        block = re.search(r"files=\((.*?)\)", content, re.DOTALL)
        self.assertIsNotNone(block, "FI remote copy list missing")
        copied = set(re.findall(r"nodekit/([a-z_]+\.py)", block.group(1)))
        self.assertIn("service_readiness.py", copied)
        self.assertIn("telemt_stage.py", copied)
        self.assertIn("nodekit.py", copied)
        self.assertIn("install_components.py", copied)
        self.assertIn("awg_controller_readiness.py", copied)
        self.assertIn("awg_peer_grants.py", copied)
        for filename in copied:
            self.assertTrue((ROOT / "nodekit" / filename).is_file(), filename)
        # A static dependency guard: directly imported Nodekit modules must
        # be shipped too. Any future module import requires list update.
        required = set()
        for filename in copied:
            tree = ast.parse((ROOT / "nodekit" / filename).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    candidate = node.module + ".py"
                    if (ROOT / "nodekit" / candidate).is_file():
                        required.add(candidate)
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        candidate = alias.name + ".py"
                        if (ROOT / "nodekit" / candidate).is_file():
                            required.add(candidate)
        self.assertFalse(required - copied,
            "FI audit missing local imported files: " + repr(required - copied))

    def test_diagnostic_only_not_release(self):
        src = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("CHECK_COMPLETED=read-only", src)
        self.assertIn("CUSTOMER_RELEASE_UNCHANGED=true", src)
        self.assertNotIn("systemctl start", src)
        self.assertNotIn("systemctl enable", src)
        self.assertNotIn("iptables ", src)

if __name__ == "__main__":
    unittest.main()
