#!/usr/bin/env python3
"""Offline unit tests for multi-domain WEB proxy profile & mtproxy-ru management."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MANAGE_PY = ROOT / "scripts/mnebyvpn-webproxy-ru-manage-20261128.py"
UNIT_FILE = ROOT / "ops/tproxy-server-ru2.service"

SPEC = importlib.util.spec_from_file_location("webproxy_manage", str(MANAGE_PY))
assert SPEC and SPEC.loader
mgr = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mgr
SPEC.loader.exec_module(mgr)


def _write_instance(
    base_dir: Path,
    *,
    hostname: str,
    base_path: str,
    listen: str,
    admin_listen: str,
    profiles: list[dict],
) -> None:
    base_dir.mkdir(parents=True, exist_ok=True)
    cfg = {
        "public_hostname": hostname,
        "base_path": base_path,
        "listen": listen,
        "admin_listen": admin_listen,
        "public_upstream": "http://127.0.0.1:3002",
        "token_key_file": str(base_dir / "token.key"),
        "static_routes": "exact",
        "profiles_file": str(base_dir / "profiles.json"),
        "limits": {"max_profiles": 32, "max_sessions_global": 512},
    }
    (base_dir / "config.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    (base_dir / "profiles.json").write_text(json.dumps({"profiles": profiles}, indent=2), encoding="utf-8")


class WebProxyManageTests(unittest.TestCase):
    def test_encode_secret_and_link_known_vector(self) -> None:
        # Canonical 0x70-prefixed RFC wire test vector (profiles.example.json secret)
        self.assertEqual(
            mgr.encode_webproxy_secret("000102030405060708090a0b0c0d0e0f"),
            "cAABAgMEBQYHCAkKCwwNDg8",
        )
        self.assertEqual(
            mgr.build_webproxy_link("proxy.example.com", "demopath12345678", "000102030405060708090a0b0c0d0e0f"),
            "tg://webproxy?server=proxy.example.com%2Fdemopath12345678&secret=cAABAgMEBQYHCAkKCwwNDg8",
        )

    def test_service_unit_hardening_directives(self) -> None:
        text = UNIT_FILE.read_text(encoding="utf-8")
        for req in (
            "User=tproxy",
            "Group=tproxy",
            "LoadCredential=profiles.json:/etc/tproxy-server-ru2/profiles.json",
            "ExecStart=/usr/local/bin/tproxy-server -config /etc/tproxy-server-ru2/config.json",
            "MemoryMax=320M",
            "IPAddressDeny=any",
            "IPAddressAllow=localhost",
        ):
            self.assertIn(req, text)

    def test_validate_rejects_bad_carrier_and_over_16_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ru1 = root / "ru1"
            _write_instance(
                ru1,
                hostname="bandbook.site",
                base_path="pathone",
                listen="127.0.0.1:8084",
                admin_listen="127.0.0.1:8085",
                profiles=[{"name": "p1", "secret": "a" * 32, "backend": "127.0.0.1:2399", "carrier_mode": "bad"}],
            )
            insts = mgr.parse_instances(f"ru1:{ru1}")
            with self.assertRaises(ValueError):
                mgr.validate_instances(insts)

            profs = [
                {
                    "name": f"u{i}",
                    "secret": f"{i:032x}",
                    "backend": "127.0.0.1:2399",
                    "carrier_mode": "websocket",
                }
                for i in range(17)
            ]
            _write_instance(
                ru1,
                hostname="bandbook.site",
                base_path="pathone",
                listen="127.0.0.1:8084",
                admin_listen="127.0.0.1:8085",
                profiles=profs,
            )
            with self.assertRaises(ValueError):
                mgr.validate_instances(insts)

    def test_sync_and_profile_lifecycle_with_mock_check(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ru1 = root / "ru1"
            ru2 = root / "ru2"
            s1 = "11" * 16
            s2 = "22" * 16
            _write_instance(
                ru1,
                hostname="bandbook.site",
                base_path="alpha123",
                listen="127.0.0.1:8084",
                admin_listen="127.0.0.1:8085",
                profiles=[{"name": "ru-wireguard", "secret": s1, "backend": "127.0.0.1:2399", "carrier_mode": "https"}],
            )
            _write_instance(
                ru2,
                hostname="servgo.bandbook.site",
                base_path="beta4567",
                listen="127.0.0.1:8088",
                admin_listen="127.0.0.1:8089",
                profiles=[{"name": "owner-servgo-ws", "secret": s2, "backend": "127.0.0.1:2399", "carrier_mode": "websocket"}],
            )

            mt_env = root / "mtproxy.env"
            mt_env.write_text(f"MTPROXY_WORKERS=1\nMTPROXY_MAX_CONNECTIONS=4096\nMTPROXY_SECRET={s1}\n", encoding="utf-8")

            bin_check_log = root / "tproxy.log"
            mock_tproxy = root / "tproxy-server"
            mock_tproxy.write_text(
                f"#!/bin/sh\necho \"$*\" >> {str(bin_check_log)!r}\nexit 0\n",
                encoding="utf-8",
            )
            mock_tproxy.chmod(0o755)

            sys_log = root / "sys.log"
            mock_sys = root / "systemctl"
            mock_sys.write_text(
                f"#!/bin/sh\necho \"$*\" >> {str(sys_log)!r}\nexit 0\n",
                encoding="utf-8",
            )
            mock_sys.chmod(0o755)

            insts = mgr.parse_instances(f"ru1:{ru1},ru2:{ru2}")
            add_res = mgr.mutate_profile(
                action="add",
                instances=insts,
                instance_name="ru1",
                profile_name="clients-ws",
                carrier_mode="websocket",
                max_sessions=300,
                max_streams=4096,
                mtproxy_env_path=mt_env,
                tproxy_bin=str(mock_tproxy),
                run_binary_check=True,
                apply_restarts=True,
                systemctl_bin=str(mock_sys),
            )
            self.assertEqual(add_res["mtproxy_secrets_total"], 3)
            self.assertTrue(add_res["link"].startswith("tg://webproxy?server=bandbook.site%2Falpha123&secret="))

            env_text = mt_env.read_text(encoding="utf-8")
            self.assertIn("MTPROXY_WORKERS=1", env_text)
            self.assertIn("MTPROXY_MAX_CONNECTIONS=4096", env_text)
            self.assertEqual(env_text.count(" -S "), 2)  # "-S a -S b -S c"
            self.assertIn(s1, env_text)
            self.assertIn(s2, env_text)

            sys_actions = sys_log.read_text(encoding="utf-8")
            self.assertIn("restart mtproxy-ru.service", sys_actions)
            self.assertIn("restart tproxy-server-ru.service", sys_actions)

            old_links = {r["name"]: r["link"] for r in mgr.export_links(insts)}
            self.assertEqual(len(old_links), 3)

            rot_res = mgr.mutate_profile(
                action="rotate",
                instances=insts,
                instance_name="ru2",
                profile_name="owner-servgo-ws",
                mtproxy_env_path=mt_env,
                run_binary_check=False,
                apply_restarts=False,
            )
            self.assertNotEqual(rot_res["link"], old_links["owner-servgo-ws"])

            rem_res = mgr.mutate_profile(
                action="remove",
                instances=insts,
                instance_name="ru1",
                profile_name="clients-ws",
                mtproxy_env_path=mt_env,
                run_binary_check=False,
                apply_restarts=False,
            )
            self.assertEqual(rem_res["mtproxy_secrets_total"], 2)

            p_cli = subprocess.run(
                [
                    sys.executable,
                    str(MANAGE_PY),
                    "--instances",
                    f"ru1:{ru1},ru2:{ru2}",
                    "--mtproxy-env",
                    str(mt_env),
                    "validate",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertTrue(json.loads(p_cli.stdout)["valid"])


if __name__ == "__main__":
    unittest.main()
