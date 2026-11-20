"""Guarded RU188 subscriber-worker promotion never changes entitlement owners."""
import importlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import fi_awg_unified_subscription_activate as rollout

class UnifiedSubscriptionReleaseTests(unittest.TestCase):
    def test_source_pins_cover_complete_eight_module_closure(self):
        self.assertEqual(len(rollout.SOURCE),8)
        self.assertEqual(len(set(rollout.SOURCE)),8)
        self.assertIn("packages/provisioning/src/awg-in-subscription.ts",rollout.SOURCE)
        self.assertIn("packages/provisioning/src/awg-device-registration-worker.ts",rollout.SOURCE)
        self.assertIn("packages/provisioning/src/awg-subscriber-material.ts",rollout.SOURCE)
        self.assertEqual(rollout.CURRENT,"446c331249085adb6536e3d9913fb4b68abf6cd7")
        self.assertEqual(rollout.NEW,"eec5b86c62b6c58bdbda8735c7e75fd9f38fd859")

    def test_seed_is_never_silently_rotated(self):
        old=b"AWG_CONTROLLER_PUBLIC_SHA256=test\nMNEBYVPN_ENV=production\n"
        seed="ab"*32
        new=rollout.replace_env(old,{"AWG_INCY_SUBSCRIPTION_SEED":seed})
        self.assertEqual(new.count(seed.encode()),1)
        self.assertEqual(rollout.replace_env(new,{"AWG_INCY_SUBSCRIPTION_SEED":seed}),new)
        with self.assertRaises(rollout.Blocked):
            rollout.replace_env(new,{"AWG_INCY_SUBSCRIPTION_SEED":"cd"*32})
        with self.assertRaises(rollout.Blocked):
            rollout.replace_env(new+b"AWG_INCY_SUBSCRIPTION_SEED=other\n",
                {"AWG_INCY_SUBSCRIPTION_SEED":seed})

    def test_existing_worker_and_website_rollback_are_explicit(self):
        src=Path(rollout.__file__).read_text()
        self.assertIn("web.write_atomic(OVERRIDE,old_override)",src)
        self.assertIn("web.write_atomic(WORKER_ENV,old_worker)",src)
        self.assertIn("web.write_atomic(PUBLIC_ENV,old_web)",src)
        self.assertIn("web.launch(image,web.WEB_NAME,8792,PUBLIC_ENV",src)
        self.assertIn("cmd([\"systemctl\",\"restart\",UNIT]",src)
        self.assertNotIn("UPDATE vpn_release_flags",src)
        self.assertNotIn("DELETE FROM entitlements",src)
        self.assertNotIn("rm -rf /",src)

    def test_pinned_git_object_is_independent_of_manifest(self):
        raw=b"test signed release\n"
        import hashlib
        expected=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
        self.assertEqual(rollout.git_blob(raw),expected)

if __name__=="__main__":unittest.main()
