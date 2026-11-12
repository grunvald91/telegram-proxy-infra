"""Offline reproducible contract for Russian 188 -> private WG -> German 89."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import meta_v23_ru_firsthop_preview as p

CORE=("tls://.:853 {\n"
      "    template IN A gemini.google.com { match ^gemini[.]google[.]com[.]$ }\n"
      "    cache 30\n"
      "}\n")
NGINX=("stream {\n"
       "map $ssl_preread_server_name $direct_mtproxy_backend {\n"
       "  default 127.0.0.1:9443;\n"
       "  gemini.google.com 127.0.0.1:15443;\n"
       "}\n"
       "  server { proxy_pass $direct_mtproxy_backend; }\n"
       "}\n")
ORIGINS={host:"93.184.215.14" for host in p.HOSTS}

def verified_fixture(hostname, ip):
    if hostname not in ORIGINS or ip != ORIGINS[hostname]:
        raise ValueError("fixture TLS origin verification failed")
    return ip


class RussianIngressTests(unittest.TestCase):
    def test_round_trip_all_meta_names_and_preserve_unrelated_services(self):
        core,nginx=p.render_existing_servers(original_core=CORE,original_de_nginx=NGINX,origins=ORIGINS,verify_origin=verified_fixture)
        self.assertEqual(len(p.HOSTS),11)
        self.assertEqual(core.count('answer "{{ .Name }} 20 IN A '+p.RU_EDGE+'"'),11)
        self.assertEqual(core.count('rcode NOERROR'),44)
        self.assertEqual(nginx.count(" 93.184.215.14:443;"),11)
        self.assertIn("  gemini.google.com 127.0.0.1:15443;",nginx)
        self.assertIn("    template IN A gemini.google.com",core)
        self.assertEqual(core.count("    cache 30\n"),1)
        renderer=p.load_renderer()
        for hostname in reversed(p.HOSTS):
            core=renderer.core_remove(core,hostname)
            nginx=renderer.nginx_remove(nginx,hostname)
        self.assertEqual(core,CORE)
        self.assertEqual(nginx,NGINX)

    def test_ru_not_de_default_and_explicit_ingress_required(self):
        renderer=p.load_renderer()
        default=renderer.core_add(CORE,"i.instagram.com")
        firsthop=renderer.core_add(CORE,"i.instagram.com",route_edge=p.RU_EDGE)
        self.assertIn("IN A "+p.DE_EDGE,default)
        self.assertIn("IN A "+p.RU_EDGE,firsthop)
        self.assertNotIn("IN A "+p.DE_EDGE,firsthop)
        for bad in ("0.0.0.0","127.0.0.1","10.66.77.1","8.8.8.8"):
            with self.subTest(route=bad),self.assertRaises(ValueError):
                renderer.core_add(CORE,"i.instagram.com",route_edge=bad)

    def test_no_partial_or_unverified_domain_mapping(self):
        with self.assertRaises(ValueError):
            p.render_existing_servers(original_core=CORE,original_de_nginx=NGINX,
                                      origins=dict(list(ORIGINS.items())[:-1]),verify_origin=verified_fixture)
        with self.assertRaises(ValueError):
            p.render_existing_servers(original_core=CORE,original_de_nginx=NGINX,
                                      origins=dict(ORIGINS,**{"other.example.com":"93.184.215.14"}),verify_origin=verified_fixture)
        wrong=dict(ORIGINS);wrong["i.instagram.com"]="127.0.0.1"
        with self.assertRaises(ValueError):
            p.render_existing_servers(original_core=CORE,original_de_nginx=NGINX,origins=wrong,verify_origin=verified_fixture)

    def test_pinned_origin_must_be_verified_for_each_meta_hostname(self):
        with self.assertRaisesRegex(ValueError,"pinned Meta origin"):
            p.render_existing_servers(original_core=CORE,original_de_nginx=NGINX,
                                      origins=ORIGINS,verify_origin=lambda _host,_ip:"8.8.8.8")
        calls=[]
        def trusted(host,ip):
            calls.append(host)
            return verified_fixture(host,ip)
        p.render_existing_servers(original_core=CORE,original_de_nginx=NGINX,
                                  origins=ORIGINS,verify_origin=trusted)
        self.assertEqual(set(calls),set(p.HOSTS))
        renderer=p.load_renderer()
        from unittest.mock import patch
        with patch.object(renderer.socket, "create_connection", side_effect=OSError("unreachable")):
            with self.assertRaises(OSError):
                renderer.verify_pinned_origin_ip("i.instagram.com","93.184.215.14")

    def test_only_test_peer_natted_on_ru_ens3_and_only_443(self):
        rules=p.ru_peer_rules("8.8.8.8")
        self.assertIn('iifname "ens3" ip saddr 8.8.8.8 ip daddr '+p.RU_EDGE+' tcp dport 443',rules)
        self.assertIn('dnat ip to '+p.RU_EDGE+':18443',rules)
        self.assertIn('ip saddr '+p.RU_EDGE+' ip daddr 8.8.8.8 tcp sport 18443',rules)
        self.assertNotIn('ip daddr '+p.DE_EDGE+' tcp dport 443',rules)
        for invalid in ("8.8.8.8/0","0.0.0.0/0","evil;flush ruleset",
                        "127.0.0.1","0.0.0.0","192.168.1.22",p.RU_EDGE,p.DE_EDGE):
            with self.assertRaises(ValueError):
                p.ru_peer_rules(invalid)

    def test_worker_only_routes_to_owner_private_wg(self):
        argv=p.worker_arguments("8.8.8.8")
        self.assertIn(("--backend-address",p.WG_BACKEND),tuple(zip(argv,argv[1:])))
        self.assertIn(("--non-meta-backend-address",p.RU_EDGE),
                      tuple(zip(argv,argv[1:])))
        self.assertEqual(argv[-2:],("--max-lifetime","2700"))
        self.assertEqual(p.worker_arguments("8.8.8.8",trial_seconds=900)[-2:],
                         ("--max-lifetime","1500"))
        with self.assertRaises(ValueError):
            p.worker_arguments("8.8.8.8",trial_seconds=3600)
        self.assertIn("--edge",argv)
        self.assertIn(p.RU_EDGE,argv)
        from meta_v15_receive_window import WindowProxy
        proxy=WindowProxy(p.RU_EDGE,"8.8.8.8",backend=(p.WG_BACKEND,443))
        self.assertEqual(proxy.backend,(p.WG_BACKEND,443))
        self.assertNotEqual(proxy.backend[0],p.DE_EDGE)

    def test_ru_observer_reads_actual_client_443_on_ens3(self):
        from mnebydns_iglite_sni_observer import capture_command
        ru=capture_command(edge=p.RU_EDGE,peer="8.8.8.8")
        self.assertEqual(ru[1:3],["-i","ens3"])
        self.assertIn("dst host "+p.RU_EDGE+" and dst port 443",ru[-1])
        self.assertIn("src host 8.8.8.8",ru[-1])
        de=capture_command(edge=p.DE_EDGE,peer="8.8.8.8")
        self.assertEqual(de[1:3],["-i","eth0"])
        self.assertIn("dst host "+p.DE_EDGE+" and dst port 443",de[-1])
        with self.assertRaises(ValueError):
            capture_command(edge=p.RU_EDGE,interface="eth0",peer="8.8.8.8")
        with self.assertRaises(ValueError):
            capture_command(edge=p.RU_EDGE,peer="127.0.0.1")
        with self.assertRaises(ValueError):
            capture_command(edge="1.2.3.4",peer="8.8.8.8")

    def test_ru_receiver_routes_only_target_sni_over_wireguard(self):
        from meta_v15_receive_window import WindowProxy,HOSTS
        self.assertEqual(set(HOSTS),set(p.HOSTS), "proxy and DNS host lists must match")
        ru=(p.RU_EDGE,443)
        de=(p.WG_BACKEND,443)
        proxy=WindowProxy(p.RU_EDGE,"8.8.8.8",backend=de,non_meta_backend=ru)
        for target in HOSTS:
            with self.subTest(host=target):
                self.assertEqual(proxy.destination_for(target),de)
        for not_meta in (None,"www.youtube.com","mnebyvpn.site",
                         "claude.ai","unlisted.instagram.com"):
            with self.subTest(host=not_meta):
                self.assertEqual(proxy.destination_for(not_meta),ru)
        with self.assertRaises(ValueError):
            WindowProxy(p.DE_EDGE,"8.8.8.8",backend=de,non_meta_backend=ru)
        with self.assertRaises(ValueError):
            WindowProxy(p.RU_EDGE,"8.8.8.8",backend=ru,non_meta_backend=ru)

if __name__=="__main__": unittest.main()
