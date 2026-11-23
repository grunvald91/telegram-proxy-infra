import base64
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import shared_vpn_admission_preflight as audit


def key(seed: int) -> str:
    return base64.b64encode(bytes([seed]) * 32).decode()


def vless_config(api: bool = True) -> dict:
    d = {
        "stats": {},
        "policy": {"levels": {"0": {"statsUserOnline": True}}},
        "inbounds": [{"tag": "vpn", "protocol": "vless",
                      "settings": {"clients": [
                          {"id": "not-shown", "email": "opaque-test@example.invalid"}]}}],
    }
    if api:
        d["api"] = {"tag": "stats", "services": ["StatsService"]}
        d["inbounds"].append({"tag": "stats", "listen": "127.0.0.1",
                              "port": 10085, "protocol": "dokodemo-door"})
        d["routing"] = {"rules": [{"inboundTag": ["stats"],
                                   "outboundTag": "stats"}]}
    return d


class TestPreflight(unittest.TestCase):
    def test_xray_good_static_config_is_not_an_admission_hook(self):
        report = audit.inspect_xray_config(vless_config())
        self.assertTrue(report["stats_online_configured"])
        self.assertFalse(report["enforcement_ready"])
        self.assertFalse(report["running_process_config_verified"])
        self.assertFalse(report["pre_connection_admission_hook_verified"])
        self.assertNotIn("not-shown", str(report))
        self.assertNotIn("@example.invalid", str(report))

    def test_xray_no_api_missing_email_or_misrouted_does_not_pass(self):
        bad = []
        a = vless_config(False)
        bad.append(a)
        b = vless_config()
        b["inbounds"][1]["listen"] = "0.0.0.0"
        bad.append(b)
        c = vless_config()
        c["inbounds"][0]["settings"]["clients"][0].pop("email")
        bad.append(c)
        d = vless_config()
        d["policy"]["levels"]["0"]["statsUserOnline"] = False
        bad.append(d)
        e = vless_config()
        e["routing"]["rules"] = []
        bad.append(e)
        for case in bad:
            self.assertFalse(audit.inspect_xray_config(case)["stats_online_configured"])

    def test_xray_invalid_config_is_rejected_and_never_printed(self):
        with self.assertRaises(audit.ObservationError):
            audit.inspect_xray_config({"inbounds": []})
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "config"
            path.write_text("private-configuration is not JSON")
            with self.assertRaises(audit.ObservationError):
                audit.observe_de(path)
            path.unlink()
            path.symlink_to("/etc/passwd")
            with self.assertRaises(audit.ObservationError):
                audit.observe_de(path)

    def test_awg_recent_handshake_is_not_an_active_session_count(self):
        now = 1900000000
        header = ["(hidden)", key(9), "51821"] + ["0"] * 25 + ["off"]
        one = [key(1), "(none)", "(none)", "10.0.0.2/32",
               str(now - 20), "100", "200", "off"]
        two = [key(2), "(none)", "(none)", "10.0.0.3/32",
               str(now - 600), "10", "20", "off"]
        raw = "\n".join("\t".join(s) for s in (header, one, two)) + "\n"
        result = audit.inspect_awg_dump(raw, now=now)
        self.assertEqual(result["recent_handshake_peers_not_sessions"], 1)
        self.assertEqual(result["stale_or_never_handshaken_peers"], 1)
        self.assertFalse(result["enforcement_ready"])
        self.assertNotIn(key(1), str(result))
        self.assertNotIn("10.0.0.2", str(result))
        with self.assertRaises(audit.ObservationError):
            audit.inspect_awg_dump(raw + "\t".join(one) + "\n", now=now)
        # Raw standard WireGuard 4-field header must not masquerade as AWG 3.1.
        with self.assertRaises(audit.ObservationError):
            audit.inspect_awg_dump("\t".join(["(hidden)", key(9), "51821", "off"]) + "\n", now=now)
        with self.assertRaises(audit.ObservationError):
            audit.inspect_awg_dump(raw.replace(str(now - 20), str(now + 120)),
                                   now=now)

    def test_awg_runner_only_reads_and_cannot_activate_peer(self):
        calls = []
        def runner(args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0,
                "\t".join(["(hidden)", key(9), "51821"] + ["0"] * 25 + ["off"]) + "\n", "")
        out = audit.observe_fi(now=1900000000, runner=runner)
        self.assertEqual(out["configured_peer_count"], 0)
        self.assertEqual(calls, [[audit.FI_AWG, "show", "awg0", "dump"]])
        self.assertFalse(out["enforcement_ready"])


if __name__ == "__main__":
    unittest.main()
