import pathlib
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import awg_upgrade as m


class TestApprovedInactiveUpgrade(unittest.TestCase):
    def test_hashes_use_same_git_blob_algorithm_as_repository(self):
        # Famous git hash of the one-line empty file is not a plain SHA1.
        self.assertEqual(m.blob_sha1(b""),"e69de29bb2d1d6434b8b29ae775ad8c2e48c5391")
        self.assertIn("awg_peer_grants.py",m.BASELINE)
        self.assertIn("awg_egress.py",m.BASELINE)

    def test_exact_two_file_atomic_upgrade_and_idempotence(self):
        with tempfile.TemporaryDirectory() as temp:
            root=pathlib.Path(temp)
            names=list(m.BASELINE)
            planned={}
            for i,name in enumerate(names):
                previous=f"x={i}\n".encode()
                desired=f"x={i+10}\n".encode()
                (root/name).write_bytes(previous)
                planned[name]={"old":m.blob_sha1(previous),
                               "new":m.blob_sha1(desired),
                               "old_source":previous,"new_source":desired,
                               "needed":True}
            with patch.object(m,"APP",root),\
                 patch.object(m,"prepare",return_value=planned),\
                 patch.object(m,"services_idle",return_value=None),\
                 patch.object(m,"safe_bytes",side_effect=lambda p:p.read_bytes()):
                first=m.execute(pathlib.Path("/tmp/fi-test-01"),root)
                self.assertEqual(set(first["changed"]),set(names))
                self.assertEqual((root/names[0]).read_bytes(),planned[names[0]]["new_source"])
                # After a successful rollout, another bootstrap is a no-op.
                no_change={n:dict(v,needed=False) for n,v in planned.items()}
                with patch.object(m,"prepare",return_value=no_change):
                    second=m.execute(pathlib.Path("/tmp/fi-test-01"),root)
                    self.assertEqual(second["changed"],[])

    def test_rollback_when_second_file_upgrade_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            root=pathlib.Path(temp)
            names=list(m.BASELINE)
            plans={}
            for i,name in enumerate(names):
                original=f"old={i}\n".encode()
                (root/name).write_bytes(original)
                desired=f"new={i}\n".encode()
                plans[name]={"old":m.blob_sha1(original),
                             "new":m.blob_sha1(desired),
                             "old_source":original,"new_source":desired,
                             "needed":True}
            actual=m.atomic_bytes
            steps=[0]
            def faulty(path,content,mode=0o600):
                if path.name==names[1] and content==plans[names[1]]["new_source"]:
                    raise RuntimeError("simulated disk failure")
                steps[0]+=1
                return actual(path,content,mode)
            with patch.object(m,"APP",root),\
                 patch.object(m,"prepare",return_value=plans),\
                 patch.object(m,"services_idle",return_value=None),\
                 patch.object(m,"safe_bytes",side_effect=lambda p:p.read_bytes()),\
                 patch.object(m,"atomic_bytes",side_effect=faulty):
                with self.assertRaises(RuntimeError):
                    m.execute(pathlib.Path("/tmp/fi-test-01"),root)
                self.assertEqual((root/names[0]).read_bytes(),plans[names[0]]["old_source"])
                self.assertEqual((root/names[1]).read_bytes(),plans[names[1]]["old_source"])
                self.assertEqual(steps[0],2)


if __name__=="__main__":
    unittest.main()
