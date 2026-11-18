"""Disposable root-owned fixtures for FI public-only enrollment staging."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import fi_public_enrollment_stage as m


def protected_write(path: Path, value: bytes):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(value)
    path.chmod(0o600)


class FiPublicStageTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() != 0:
            self.skipTest("requires disposable root-owned fixtures")
        self.base = Path(tempfile.mkdtemp(prefix="fi-pub-stage-", dir="/root"))
        self.addCleanup(lambda: shutil.rmtree(self.base, ignore_errors=True))
        self.node_root = self.base / "nodekit"
        self.node = self.node_root / m.NODE_ID
        self.identity = self.node / "identity"
        for p in (self.node_root, self.node, self.identity):
            p.mkdir(mode=0o700)
        self.app = self.base / "app"
        self.ssh = self.base / "ssh"
        self.inputs = self.base / "inputs"
        self.inputs.mkdir(mode=0o700)
        self.controller = m.ED25519_SPKI + bytes(range(32))
        self.node_pub = m.ED25519_SPKI + bytes(range(32,64))
        self.controller_sha = m.sha(self.controller)
        self.node_sha = m.sha(self.node_pub)
        self.host_ssh = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + bytes([42])*32
        self.pub_b64 = base64.b64encode(self.host_ssh).decode()
        self.keys = self.inputs / "fi-enrollment-ssh.pub"
        self.spki = self.inputs / "controller.spki"
        self.handler = self.inputs / "fi_enrollment_ssh.py"
        self.node_file = self.inputs / "fi-node-public.spki"
        self.pin = self.inputs / "fi-known_hosts"
        self.handler_bytes = b"#!/usr/bin/env python3\n# deliberately inert test fixture\n"
        protected_write(self.handler,self.handler_bytes)
        protected_write(self.spki,self.controller)
        protected_write(self.keys,("ssh-ed25519 "+self.pub_b64+" reviewed\n").encode())
        protected_write(self.node_file,self.node_pub)
        protected_write(self.pin,(m.FI_IP+" ssh-ed25519 "+self.pub_b64+"\n").encode())
        protected_write(self.identity/"node-public.spki",self.node_pub)
        protected_write(self.identity/"node-private.pk8",b"private-placeholder")
        manifest={
            "node_id":m.NODE_ID,"advertise_host":m.FI_HOST,"state":"testing",
            "registration_enabled":False,"activation_enabled":False,
        }
        protected_write(self.node/"manifest.json",json.dumps(manifest).encode())

    def fi(self, install=True):
        m.stage_fi(self.node,self.app,self.ssh,self.spki,self.keys,self.handler,
                   m.sha(self.handler_bytes),install=install,
                   controller_sha=self.controller_sha,node_sha=self.node_sha)

    def test_fi_installs_only_public_key_and_restrictive_authorized_key(self):
        self.fi()
        self.fi()
        self.fi(install=False)
        self.assertEqual((self.node/"controller-access.spki").read_bytes(),self.controller)
        self.assertEqual((self.app/"fi_enrollment_ssh.py").read_bytes(),self.handler_bytes)
        auth=(self.ssh/"authorized_keys").read_text()
        self.assertEqual(auth.count(self.pub_b64),1)
        self.assertIn('restrict,command="/usr/bin/python3 ',auth)
        self.assertIn('--node-id fi-test-01',auth)
        self.assertEqual((self.ssh/"authorized_keys").stat().st_mode & 0o077,0)

    def test_wrong_controller_or_node_identity_cannot_create_access(self):
        protected_write(self.spki,m.ED25519_SPKI+b"\x52"*32)
        with self.assertRaises(m.StageError):
            self.fi()
        self.assertFalse((self.ssh/"authorized_keys").exists())
        protected_write(self.spki,self.controller)
        protected_write(self.identity/"node-public.spki",m.ED25519_SPKI+b"\x43"*32)
        with self.assertRaises(m.StageError):
            self.fi()
        self.assertFalse((self.node/"controller-access.spki").exists())

    def test_unsafe_existing_authorized_key_blocks_forced_command(self):
        self.ssh.mkdir(mode=0o700)
        protected_write(self.ssh/"authorized_keys",
                        ("ssh-ed25519 "+self.pub_b64+" unrestricted\n").encode())
        with self.assertRaisesRegex(m.StageError,"unsafe existing rights"):
            self.fi()
        self.assertEqual((self.ssh/"authorized_keys").read_text(),
                         "ssh-ed25519 "+self.pub_b64+" unrestricted\n")

    def test_other_root_ssh_keys_are_preserved(self):
        self.ssh.mkdir(mode=0o700)
        protected_write(self.ssh/"authorized_keys",
                        b"ssh-ed25519 AAAAnot-an-enrollment-key owner\n")
        self.fi()
        text=(self.ssh/"authorized_keys").read_text()
        self.assertIn("AAAAnot-an-enrollment-key",text)
        self.assertEqual(text.count(self.pub_b64),1)

    def test_controller_stages_only_existing_fi_pin_and_public_identity(self):
        ctl=self.base/"controller"
        ctl.mkdir(mode=0o700)
        protected_write(ctl/"controller-public.spki",self.controller)
        trust=ctl/"fleet-ssh-host-keys"
        trust.mkdir(mode=0o700)
        protected_write(trust/"fi-fi-test-01.known_hosts",self.pin.read_bytes())
        def stage(install):
            m.stage_controller(ctl,self.node_file,self.pin,install=install,
                               node_sha=self.node_sha,controller_sha=self.controller_sha)
        stage(True)
        stage(True)
        stage(False)
        self.assertEqual((ctl/"fi-node-public.spki").read_bytes(),self.node_pub)
        self.assertEqual((ctl/"fi-known_hosts").read_text(),
                         m.FI_HOST+" ssh-ed25519 "+self.pub_b64+"\n")
        protected_write(self.pin,(m.FI_IP+" ssh-ed25519 "+
                        base64.b64encode(self.host_ssh[:-1]+b"\x55").decode()+"\n").encode())
        with self.assertRaisesRegex(m.StageError,"differs"):
            stage(True)
        self.assertEqual((ctl/"fi-node-public.spki").read_bytes(),self.node_pub)

    def test_no_unattested_stage_on_unexpected_host_or_nonroot(self):
        with patch.object(m.os,"geteuid",return_value=1):
            with self.assertRaises(m.StageError):
                m.check_host(m.FI_IP)
        with patch.object(m.os,"geteuid",return_value=0), \
             patch.object(m.socket,"if_nameindex",return_value=[]):
            with self.assertRaises(m.StageError):
                m.check_host(m.FI_IP)


if __name__ == "__main__":
    unittest.main()
