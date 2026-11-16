from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from control_plane import ContractError, Incident, route_incident
from incident_gateway import validate_envelope
from monitor_policy import detect_incident, sign_event

NOW = datetime.now(timezone.utc).replace(microsecond=0)
KEY = b"1" * 32


def observations(node="de-node-01", service="vpn", down=True):
    point = "external_" + ("proxy" if service == "sni-proxy" else service) + "_e2e"
    records = [
        {
            "node_id": node, "service": service,
            "observer": observer, "probe": point,
            "observed_at": (NOW-timedelta(minutes=minute)).isoformat(),
            "ok": False
        }
        for observer in ("external-wifi", "external-cellular")
        for minute in (1, 2)
    ]
    if down:
        records.append({
            "node_id": node, "service": service, "observer": "nodekit-local",
            "probe": "owned_sidecar_process", "observed_at": NOW.isoformat(),
            "ok": False
        })
    return records


class MonitorContract(unittest.TestCase):
    def test_one_observer_not_enough(self):
        data = observations()
        data = [r for r in data if r["observer"] != "external-cellular"]
        self.assertIsNone(detect_incident(data, {"de-node-01"}, NOW))

    def test_two_failures_and_local_process_down_propose_owned_repair(self):
        event = detect_incident(observations(), {"de-node-01"}, NOW)
        self.assertEqual(event["kind"], "owned_sidecar_down")
        decision = route_incident(Incident.parse(event), {"de-node-01"})
        self.assertEqual(decision["action"], "restart-owned-sidecar")
        self.assertFalse(decision["auto_execute"])
        signed = sign_event(event, KEY, NOW)
        self.assertEqual(validate_envelope(signed, KEY, NOW).incident_id,
                         event["incident_id"])
        self.assertEqual(detect_incident(observations(), {"de-node-01"}, NOW)["incident_id"],
                         event["incident_id"])

    def test_flow_broken_but_process_up_escalates(self):
        ev = detect_incident(observations(down=False), {"de-node-01"}, NOW)
        self.assertEqual(ev["kind"], "data_path_broken")
        self.assertEqual(route_incident(Incident.parse(ev), {"de-node-01"})["action"],
                         "escalate_read_only")

    def test_two_nodes_escalate_as_global(self):
        batch = observations("de-node-01") + observations("nl-node-02")
        ev = detect_incident(batch, {"de-node-01", "nl-node-02"}, NOW)
        self.assertEqual(ev["kind"], "cross_node_outage")
        self.assertFalse(route_incident(Incident.parse(ev),
                                        {"de-node-01", "nl-node-02"})["auto_execute"])

    def test_successful_latest_probes_prevent_false_incident(self):
        batch = observations()
        batch.extend({
            "node_id": "de-node-01", "service": "vpn",
            "observer": observer, "probe": "external_vpn_e2e",
            "observed_at": NOW.isoformat(), "ok": True
        } for observer in ("external-wifi", "external-cellular"))
        self.assertIsNone(detect_incident(batch, {"de-node-01"}, NOW))

    def test_unknown_or_stale_probe_is_rejected(self):
        with self.assertRaises(ContractError):
            detect_incident(observations(), {"nl-node-02"}, NOW)
        batch = observations()
        batch[0]["observed_at"] = (NOW-timedelta(days=1)).isoformat()
        with self.assertRaises(ContractError):
            detect_incident(batch, {"de-node-01"}, NOW)


if __name__ == "__main__":
    unittest.main()
