#!/usr/bin/env python3
"""Offline regression gates for the reviewed v8 Meta Wi-Fi trial.

Only local fake Nginx/CoreDNS configs and static owner-specific nft rules.
NO SSH, DNS/network access, server or host nftables changes.
"""
import importlib.util
import inspect
import pathlib
import re
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parents[1]


def load(filename, name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    if spec is None or spec.loader is None:
        raise AssertionError("Cannot load script")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MultiMetaReview(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tested = load("mnebydns_iglite_wifi_multi_meta_v8_review.py", "meta_v8")
        cls.renderer = load("mnebydns-owner-domain-render-20261110.py", "route_renderer")

    def sample_configs(self):
        renderer = self.renderer
        core = (
            "tls://.:853 {\n"
            "    template IN A gemini.google.com { match ^gemini[.]google[.]com[.]$ }\n"
            + renderer.CACHE_ANCHOR
            + "}\n"
        )
        nginx = (
            "stream {\n" + renderer.NGINX_ANCHOR + "\n"
            "  default 127.0.0.1:9443;\n"
            "  gemini.google.com 127.0.0.1:15443;\n"
            "}\n  server { proxy_pass $direct_mtproxy_backend; }\n}\n"
        )
        return core, nginx

    def test_hostnames_unique_and_relevant(self):
        hosts = self.tested.HOSTS
        self.assertEqual(len(hosts), len(set(hosts)))
        self.assertIn("iglite-z.instagram.com", hosts)
        self.assertIn("i.instagram.com", hosts)
        self.assertIn("graph.facebook.com", hosts)
        self.assertIn("z-m-gateway.facebook.com", hosts)
        self.assertGreaterEqual(len(hosts), 7)
        for host in hosts:
            self.assertTrue(
                host.endswith((".instagram.com", ".facebook.com", ".fbcdn.net")),
                msg=f"Unexpected non-Meta hostname: {host}",
            )
            self.assertEqual(self.renderer.validate_domain(host), host)

    def test_all_routes_add_reverse_remove_byte_for_byte(self):
        core_original, nginx_original = self.sample_configs()
        core, nginx = core_original, nginx_original
        for hostname in self.tested.HOSTS:
            core = self.renderer.core_add(core, hostname)
            nginx = self.renderer.nginx_add(nginx, hostname, "93.184.215.14")
        for hostname in self.tested.HOSTS:
            self.assertEqual(core.count(self.renderer.mark(hostname)), 2)
            self.assertEqual(nginx.count(self.renderer.mark(hostname)), 2)
            self.assertEqual(core.count(f"match ^{re.escape(hostname).replace(chr(92) + '.', '[.]')}[.]$"), 5)
        for hostname in reversed(self.tested.HOSTS):
            core = self.renderer.core_remove(core, hostname)
            nginx = self.renderer.nginx_remove(nginx, hostname)
        self.assertEqual(core, core_original)
        self.assertEqual(nginx, nginx_original)

    def test_no_silent_missing_meta_host(self):
        source = inspect.getsource(self.tested.live)
        self.assertIn("len(accepted) != len(HOSTS)", source)
        self.assertIn("iglite_meta_full_coverage=FAIL_BEFORE_LIVE_MUTATION", source)
        self.assertIn("iglite_meta_full_coverage=PASS_EXACT_HOSTS_ONLY", source)
        self.assertIn("m.origin_ip(hostname)", source)

    def test_nft_change_is_explicitly_global_to_tcp443_not_all_meta_only(self):
        rules = self.tested.nft_rules()
        self.assertIn('oifname "eth0" ip saddr 89.125.90.101 tcp sport 443', rules)
        self.assertIn("tcp flags & (syn | ack) == (syn | ack)", rules)
        self.assertIn("counter tcp window set 4", rules)
        self.assertIn("type filter hook postrouting priority 100", rules)
        self.assertIn("meta mark set meta mark | 0x40000000", rules)
        self.assertNotIn("flush ruleset", rules)
        audit = inspect.getsource(self.tested.observe_wifi_tcp_headers)
        self.assertIn("iglite_wifi_window4_and_mark_change_global_tcp443=true", audit)

    def test_watchdog_more_than_live_window_and_late_preflight_guard(self):
        trial = self.tested
        self.assertEqual(trial.TRIAL_SECONDS, 900)
        self.assertGreaterEqual(trial.WATCHDOG_SECONDS,
                                trial.TRIAL_SECONDS + trial.MIN_ROLLBACK_MARGIN + 60)
        source = inspect.getsource(trial.live)
        self.assertIn("remaining_watchdog < TRIAL_SECONDS + MIN_ROLLBACK_MARGIN", source)
        self.assertIn("rollback()", source)

    def test_ready_signal_after_capture_started_not_after_nft_only(self):
        audit = inspect.getsource(self.tested.observe_wifi_tcp_headers)
        started = audit.index('proc = subprocess.Popen(')
        if_ready = audit.index('if proc.poll() is not None:')
        ready = audit.index('iglite_wifi_15min_window=READY')
        self.assertLess(started, if_ready)
        self.assertLess(if_ready, ready)
        live = inspect.getsource(self.tested.live)
        self.assertNotIn('print("iglite_wifi_15min_window=READY"', live)

    def test_no_false_sni_split_or_phone_identification(self):
        audit = inspect.getsource(self.tested.observe_wifi_tcp_headers)
        self.assertIn("iglite_wifi_sni_byte_split=NOT_PROVEN_BY_HEADER_CAPTURE", audit)
        self.assertIn("iglite_wifi_header_metric_cannot_identify_phone=true", audit)
        self.assertIn("iglite_wifi_android_peer_identified=false", audit)
        self.assertIn("iglite_wifi_pcap_persisted=false", audit)


if __name__ == "__main__":
    unittest.main()
