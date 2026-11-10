#!/usr/bin/env python3
"""Offline tests for optional persistent per-peer NFQUEUE210 SYN-ACK exemption."""
from pathlib import Path
import importlib.util
import subprocess
from unittest import TestCase, main

ROOT=Path(__file__).resolve().parents[2]
GENERATOR=ROOT/"legacy-mtproxy/live-snapshot/server188/usr/local/sbin/telegram-nfqws-rules"
RENDERER=ROOT/"scripts/mnebydns_nfqws_synack_guard_render.py"
spec=importlib.util.spec_from_file_location("guard_render",RENDERER)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class GuardRendererTests(TestCase):
    def setUp(self):
        self.source=GENERATOR.read_text()

    def test_opt_in_guard_before_original_queue(self):
        out=m.render(self.source)
        self.assertIn(m.TAG,out)
        self.assertLess(out.index(m.TAG),out.index(m.QUEUE_LINE))
        self.assertIn("SYNACK_CLIENT=",out)
        self.assertIn("ip daddr $SYNACK_CLIENT tcp sport 443",out)
        self.assertIn("tcp flags & (syn | ack) == (syn | ack)",out)
        self.assertIn("ct reply packets 1-20 meta mark and 0x40000000 == 0",out)
        self.assertEqual(out.count(m.QUEUE_LINE),1)
        self.assertLess(out.index("Invalid SYN-ACK canary peer:"),out.index("        remove_all"))
        self.assertIn('python3 - "$SYNACK_CLIENT"',out)
        self.assertEqual(subprocess.run(["sh","-n"],input=out,text=True,capture_output=True).returncode,0)

    def test_idempotent(self):
        once=m.render(self.source)
        self.assertEqual(m.render(once),once)

    def test_refuse_changed_or_duplicated_generators(self):
        samples=[
            self.source.replace("QUEUE=210","QUEUE=211"),
            self.source.replace("WAN_IF=ens3","WAN_IF=eth0"),
            self.source.replace(m.QUEUE_LINE,m.QUEUE_LINE+"\n"+m.QUEUE_LINE),
            self.source.replace("        remove_all\n","        :\n",1),
            self.source.replace("nft add table inet telegram_nfqws","nft add table inet other"),
            self.source+"\nSYNACK_FILE=/tmp/unsafe\n",
        ]
        for candidate in samples:
            with self.subTest(candidate=candidate[-100:]):
                with self.assertRaises(ValueError):
                    m.render(candidate)

    def test_no_change_when_opt_in_file_absent(self):
        out=m.render(self.source)
        self.assertIn('if [ -e "$SYNACK_FILE" ]; then',out)
        self.assertIn('if [ -n "$SYNACK_CLIENT" ]; then',out)
        self.assertIn('fi\n'+m.QUEUE_LINE,out)

if __name__=="__main__":
    main()
