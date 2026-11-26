#!/usr/bin/env python3
import struct
import socket
import unittest
from unittest.mock import patch
import fi_external_customer_e2e as m

RU_READY="mnebyvpn-fi-dns-meter.service=active\nmnebyvpn-fi-dns-publisher.service=active\nbot=active\nissuance=closed"

class CanaryTest(unittest.TestCase):
    def test_a_record(self):
        q=m.question("www.youtube.com")
        answer=struct.pack("!6H",0x71ac,0x8180,1,1,0,0)+q[12:]+b"\xc0\x0c"+struct.pack("!HHIH",1,1,30,4)+socket.inet_aton(m.FI)
        self.assertEqual(m.a_addresses(answer,"www.youtube.com"),{m.FI})
        with self.assertRaises(m.Blocked):
            m.a_addresses(answer[:-1],"www.youtube.com")
    def test_denial_not_timeout(self):
        with patch.object(m,"dot",side_effect=EOFError):
            self.assertTrue(m.denied("x","example.com"))
        with patch.object(m,"dot",side_effect=TimeoutError):
            with self.assertRaises(TimeoutError):m.denied("x","example.com")
        with patch.object(m,"dot",return_value=(0,1,b"")):
            self.assertFalse(m.denied("x","example.com"))
    def test_fixture_and_gate_cleanup_on_failed_wire_probe(self):
        sql_calls=[]
        ssh_calls=[]
        def sql(s):
            sql_calls.append(s)
            if "has_function_privilege" in s:return "|".join(["true"]*7)
            if "INSERT INTO accounts" in s:return "READY"
            if "DELETE FROM accounts" in s:return "true"
            if "UPDATE fi_dns_meter_gate SET enabled=false" in s:return "true"
            raise AssertionError("Unexpected database call")
        def ssh(host,command,*args,**kwargs):
            ssh_calls.append((host,command))
            if kwargs.get("phase")=="BOT_DB_IDENTITY":return "mnebyvpn_stage"
            return RU_READY if kwargs.get("phase")=="PREFLIGHT" and host==m.RU else ""
        with patch.object(m,"sql",side_effect=sql),patch.object(m,"ssh",side_effect=ssh),patch.object(m,"denied",return_value=True),patch.object(m,"await_positive",side_effect=m.Blocked("WIRE_FAIL")):
            with self.assertRaisesRegex(m.Blocked,"WIRE_FAIL"):m.main()
        self.assertTrue(any("UPDATE fi_dns_meter_gate SET enabled=false" in s for s in sql_calls))
        self.assertTrue(any("DELETE FROM accounts" in s for s in sql_calls))
        self.assertTrue(any(h==m.FI and c.startswith("rm -f "+m.MARKER) for h,c in ssh_calls))
        self.assertTrue(any(h==m.RU and c.startswith("systemctl stop ") for h,c in ssh_calls))
    def test_preflight_refuses_open_gate(self):
        with patch.object(m,"ssh",side_effect=[RU_READY,"mnebyvpn_stage"]),patch.object(m,"sql",return_value="false|"+"|".join(["true"]*6)) as sql:
            with self.assertRaisesRegex(m.Blocked,"RU_DB_CHECK_FAILED_GATE_CLOSED"):m.main()
            self.assertEqual(sql.call_count,1)

    def test_preflight_uses_actual_bot_login(self):
        for role in ("mnebyvpn_stage","mnebyvpn_bot"):
            with patch.object(m,"ssh",return_value=role),patch.object(m,"sql",return_value="|".join(["true"]*7)) as sql:
                m.verify_ru_database()
                self.assertIn("to_regrole('"+role+"')",sql.call_args.args[0])
        with patch.object(m,"ssh",return_value="unknown"),patch.object(m,"sql") as sql:
            with self.assertRaisesRegex(m.Blocked,"RU_UNKNOWN_BOT_DB_ROLE"):m.verify_ru_database()
            sql.assert_not_called()

if __name__=="__main__":unittest.main()
