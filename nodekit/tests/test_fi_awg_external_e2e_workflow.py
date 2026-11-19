"""Offline safety contract for FI217 ephemeral external AWG E2E workflow.

Never runs SSH, touches a node, starts AWG or obtains credentials.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

WORKFLOW=Path(__file__).resolve().parents[2]/".github/workflows/nodekit-fi-awg-external-e2e.yml"


class FiAwgExternalE2ePinnedHostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text=WORKFLOW.read_text(encoding="utf-8")

    def test_exact_pinned_fi_host_not_tofu(self):
        self.assertNotIn("StrictHostKeyChecking=accept-new",self.text)
        self.assertNotIn("StrictHostKeyChecking=no",self.text)
        self.assertNotIn("ssh-keyscan",self.text)
        self.assertIn("HostKeyAlias=fi.mnebyvpn.site",self.text)
        self.assertIn("StrictHostKeyChecking=yes",self.text)
        self.assertIn("HostKeyAlgorithms=ssh-ed25519",self.text)
        self.assertIn("UpdateHostKeys=no",self.text)
        self.assertIn("GlobalKnownHostsFile=/dev/null",self.text)
        self.assertIn('test "$(stat -c "%u:%a" "$p")" = "0:600"',self.text)
        self.assertIn('name,kind,key=raw.decode("ascii").strip().split()',self.text)
        self.assertIn('base64.b64decode(key,validate=True)',self.text)
        self.assertIn('base64.b64encode(decoded).decode()==key',self.text)

    def test_fi_pin_origin_is_existing_pinned_controller(self):
        self.assertIn('RU_PASSWORD: \${{ secrets.SERVER188_SSH_PASSWORD }}',self.text)
        self.assertIn('ops/mnebydns-owner-ssh-known_hosts',self.text)
        self.assertIn('root@188.120.254.223',self.text)
        self.assertIn('/root/mnebyvpn-controller/fi-known_hosts',self.text)
        self.assertIn('root@217.11.167.91',self.text)
        self.assertIn('AWG_CLIENT_PROFILE_PUBLISHED=false',self.text)

    def test_all_live_shell_blocks_pass_bash_syntax(self):
        lines=self.text.splitlines()
        scripts=[]
        for i,line in enumerate(lines):
            if line=="        run: |":
                block=[]
                for rest in lines[i+1:]:
                    if rest and not rest.startswith("          "):
                        break
                    block.append(rest[10:] if rest else "")
                scripts.append("\n".join(block)+"\n")
        self.assertGreaterEqual(len(scripts),2)
        for index,script in enumerate(scripts):
            with self.subTest(script=index):
                with tempfile.TemporaryDirectory() as folder:
                    sh=Path(folder)/"script.sh"
                    sh.write_text(script,encoding="utf-8")
                    result=subprocess.run(
                        ["bash","-n",str(sh)],capture_output=True,text=True,
                        timeout=5,check=False,
                    )
                    self.assertEqual(result.returncode,0,result.stderr)

if __name__=="__main__":
    unittest.main()
