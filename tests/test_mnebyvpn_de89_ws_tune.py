import importlib.util
import pathlib
import tempfile
import unittest

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "scripts/mnebyvpn-de89-ws-tune.py"
spec = importlib.util.spec_from_file_location("de89_ws_tune_under_test", SOURCE)
ws_tune = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ws_tune)

SAMPLE_CONF = """server {
    listen 89.125.90.101:8443 ssl;
    server_name cdn.servgo.ru;
    location = /mnebyvpn-vpn/ws {
        access_log off;
        proxy_pass http://127.0.0.1:18943;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
    }
    location = /mnebyvpn-telegram/webhook {
        proxy_pass http://10.66.77.2:8794/webhooks/telegram;
        proxy_buffering off;
    }
}
"""


class De89WsTuneTests(unittest.TestCase):
    def test_adds_unbuffered_and_keepalive_directives_only_inside_ws_location(self):
        updated, changed = ws_tune.render_ws_tune(SAMPLE_CONF)
        self.assertTrue(changed)
        for directive in (
            "proxy_buffering off;",
            "proxy_request_buffering off;",
            "tcp_nodelay on;",
            "proxy_socket_keepalive on;",
        ):
            self.assertIn(directive, updated)

        # Idempotent on second pass.
        second, changed_again = ws_tune.render_ws_tune(updated)
        self.assertFalse(changed_again)
        self.assertEqual(second, updated)

        # Does not touch webhook block.
        webhook_section = updated.split("location = /mnebyvpn-telegram/webhook")[1]
        self.assertNotIn("tcp_nodelay on;", webhook_section)

    def test_refuses_missing_or_unexpected_ws_block(self):
        with self.assertRaises(ws_tune.TuneError):
            ws_tune.render_ws_tune("server { location / { return 404; } }")
        with self.assertRaises(ws_tune.TuneError):
            ws_tune.render_ws_tune(
                SAMPLE_CONF.replace("127.0.0.1:18943", "127.0.0.1:9999")
            )
        with self.assertRaises(ws_tune.TuneError):
            ws_tune.render_ws_tune(
                SAMPLE_CONF.replace("proxy_send_timeout 600s;", "proxy_buffering on;\n        proxy_send_timeout 600s;")
            )

    def test_extract_listen_ip_8443(self):
        self.assertEqual(ws_tune.extract_listen_ip_8443(SAMPLE_CONF), "89.125.90.101")
        with self.assertRaises(ws_tune.TuneError):
            ws_tune.extract_listen_ip_8443("server { listen 8443 ssl; }")

    def test_dry_run_cli_does_not_mutate_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = pathlib.Path(tmp) / "site.conf"
            cfg.write_text(SAMPLE_CONF, encoding="utf-8")
            rc = ws_tune.main(["--mode", "dry-run", "--site", str(cfg)])
            self.assertEqual(rc, 0)
            self.assertEqual(cfg.read_text(encoding="utf-8"), SAMPLE_CONF)


if __name__ == "__main__":
    unittest.main()
