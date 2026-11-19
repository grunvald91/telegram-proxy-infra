"""Offline negative-auth probe tests, no SSH network used."""
import importlib.util
from pathlib import Path
from unittest import TestCase, mock
from io import StringIO
from contextlib import redirect_stdout

p=Path(__file__).resolve().parents[1]/"fi_enroll_negative_probe.py"
s=importlib.util.spec_from_file_location("fi_enroll_negative_probe",p)
m=importlib.util.module_from_spec(s)
s.loader.exec_module(m)


class NegativeProbe(TestCase):
    def test_expected_handler_refusal_is_success_without_sensitive_output(self):
        result=mock.Mock(returncode=2,stdout="",stderr="NODEKIT_ENROLLMENT_ERROR=EnrollmentSshError\n")
        with (mock.patch.object(m,"on_ru188",return_value=True),
              mock.patch.object(m,"trusted",side_effect=[
                  "fi.mnebyvpn.site ssh-ed25519 QQ==\n", "key"
              ]),
              mock.patch.object(m.subprocess,"run",return_value=result) as ssh,
              redirect_stdout(StringIO()) as stdout):
            m.run()
        self.assertIn("INVALID_CHALLENGE_REJECTED=true",stdout.getvalue())
        self.assertEqual(ssh.call_args.kwargs["input"],"{}\n")
        self.assertNotIn("password",stdout.getvalue().lower())

    def test_password_authentication_never_enabled(self):
        args=m.forced_ssh_args()
        self.assertIn("PasswordAuthentication=no",args)
        self.assertIn("BatchMode=yes",args)
        self.assertIn("StrictHostKeyChecking=yes",args)
        self.assertIn("HostKeyAlias=fi.mnebyvpn.site",args)
        self.assertEqual(args[-1],"false")

    def test_access_denied_does_not_report_success(self):
        result=mock.Mock(returncode=255,stdout="",stderr="Permission denied (publickey).\n")
        with (mock.patch.object(m,"on_ru188",return_value=True),
              mock.patch.object(m,"trusted",side_effect=[
                  "fi.mnebyvpn.site ssh-ed25519 QQ==\n", "key"
              ]),
              mock.patch.object(m.subprocess,"run",return_value=result)):
            with self.assertRaises(m.ValueError):
                m.run()

    def test_invalid_challenge_must_not_be_accepted(self):
        result=mock.Mock(returncode=0,stdout="unexpected",stderr="")
        with (mock.patch.object(m,"on_ru188",return_value=True),
              mock.patch.object(m,"trusted",side_effect=[
                  "fi.mnebyvpn.site ssh-ed25519 QQ==\n", "key"
              ]),
              mock.patch.object(m.subprocess,"run",return_value=result)):
            with self.assertRaises(m.ValueError):
                m.run()
