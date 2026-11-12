"""Automated Backend & End-to-End Workflow Test Suite for SENTINEL SOC."""
import io
import json
import os
import tempfile
import unittest

# Configure isolated test database before importing app
TEST_DB_FD, TEST_DB_PATH = tempfile.mkstemp(suffix="_sentinel_test.db")
os.close(TEST_DB_FD)
os.environ["SENTINEL_DB_PATH"] = TEST_DB_PATH

from fastapi.testclient import TestClient
from app.main import app
from app.core.database import init_db, get_db

class SentinelSocBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(TEST_DB_PATH):
            os.remove(TEST_DB_PATH)

    def test_01_health_and_developer_profile(self):
        r = self.client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["timezone_display"], "Asia/Dhaka")

        dev = self.client.get("/api/developer").json()
        self.assertEqual(dev["name"], "Wasif Karim")
        self.assertEqual(dev["email"], "wasifkarim.work@gmail.com")
        self.assertEqual(dev["whatsapp"], "+8801783734911")
        self.assertIn("DU PMICS — 7th Batch", dev["education"])
        self.assertIn("Daffodil International University", dev["education"])

    def test_02_upload_validation_and_malformed_handling(self):
        # Reject path traversal / bad extension
        bad_resp = self.client.post(
            "/api/logs/ingest-text",
            json={"dataset_name": "Bad", "filename": "../evil.exe", "content": "test"},
        )
        self.assertEqual(bad_resp.status_code, 400)

        # Mixed valid + malformed syslog lines
        mixed_log = (
            "Nov 12 02:15:10 bastion sshd[101]: Failed password for invalid user admin from 192.0.2.10 port 41111 ssh2\n"
            "THIS IS A CORRUPTED MALFORMED LOG LINE WITHOUT TIMESTAMP\n"
            "Nov 12 02:15:20 bastion sshd[102]: Accepted publickey for wasif from 198.51.100.25 port 42222 ssh2\n"
        )
        res = self.client.post(
            "/api/logs/ingest-text",
            json={"dataset_name": "Mixed Test Log", "filename": "mixed.log", "content": mixed_log, "auto_detect": False},
        )
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["imported_records"], 2)
        self.assertEqual(body["rejected_records"], 1)
        self.assertEqual(len(body["rejection_reasons"]), 1)

    def test_03_load_sample_data_and_all_10_detection_rules(self):
        res = self.client.post("/api/sample-data/load")
        self.assertEqual(res.status_code, 200)
        payload = res.json()
        self.assertGreaterEqual(len(payload["loaded_datasets"]), 3)
        det = payload["detection_summary"]
        self.assertEqual(det["rules_evaluated"], 10)
        self.assertGreaterEqual(det["alerts_generated"], 8)

        # Verify duplicate alert prevention on re-run
        rerun = self.client.post("/api/detection/run").json()
        self.assertEqual(rerun["alerts_generated"], 0)

        # Verify rules triggered across our 10 rules
        alerts = self.client.get("/api/alerts").json()["alerts"]
        triggered_rules = {a["rule_id"] for a in alerts}
        for expected_rule in ["RULE-001", "RULE-002", "RULE-003", "RULE-004", "RULE-005", "RULE-006", "RULE-007", "RULE-008", "RULE-009", "RULE-010"]:
            self.assertIn(expected_rule, triggered_rules, f"Expected {expected_rule} to trigger on sample datasets")

    def test_04_log_explorer_parameterized_search(self):
        r = self.client.get('/api/events', params={"advanced_query": 'source_ip = "192.0.2.55" event_type = "authentication_failure"'})
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertGreaterEqual(data["total"], 5)
        for ev in data["events"]:
            self.assertEqual(ev["source_ip"], "192.0.2.55")
            self.assertEqual(ev["event_type"], "authentication_failure")

    def test_05_alert_acknowledgment_and_incident_lifecycle_e2e(self):
        alerts = self.client.get("/api/alerts").json()["alerts"]
        self.assertTrue(len(alerts) > 0)
        target_alert = alerts[0]
        aid = target_alert["alert_id"]

        # Acknowledge alert & add note
        patch_al = self.client.patch(
            f"/api/alerts/{aid}",
            json={"status": "Acknowledged", "assigned_analyst": "Wasif Karim", "note": "Confirmed brute-force pattern; escalating to incident."},
        )
        self.assertEqual(patch_al.status_code, 200)
        self.assertEqual(patch_al.json()["status"], "Acknowledged")
        self.assertEqual(len(patch_al.json()["investigation_notes"]), 1)

        # Create incident from alert
        inc_resp = self.client.post(
            "/api/incidents",
            json={
                "title": f"Incident for {target_alert['title']}",
                "description": "Escalated from alert during E2E automated verification.",
                "severity": "High",
                "assigned_analyst": "Wasif Karim",
                "related_alerts": [aid],
                "iocs": [target_alert.get("source_ip") or "192.0.2.55"],
            },
        )
        self.assertEqual(inc_resp.status_code, 200)
        inc = inc_resp.json()
        inc_id = inc["incident_id"]

        # Progress through Triage -> Containment -> Resolved
        upd1 = self.client.patch(
            f"/api/incidents/{inc_id}",
            json={"status": "Investigation", "note": "Blocked source IP at perimeter firewall and rotated SSH keys."},
        )
        self.assertEqual(upd1.status_code, 200)
        self.assertEqual(upd1.json()["status"], "Investigation")

        upd2 = self.client.patch(
            f"/api/incidents/{inc_id}",
            json={"status": "Resolved", "resolution_summary": "Source IP blocked; unauthorized session terminated."},
        )
        self.assertEqual(upd2.status_code, 200)
        self.assertEqual(upd2.json()["status"], "Resolved")
        self.assertIsNotNone(upd2.json()["closed_at"])

    def test_06_threat_intelligence_ioc_validation(self):
        # Reserved documentation IP check
        r_ip = self.client.post("/api/threat-intel/lookup", json={"ioc_value": "192.0.2.55", "analyst_notes": "Brute force source"}).json()
        self.assertEqual(r_ip["ioc_type"], "ipv4")
        self.assertEqual(r_ip["is_private_or_reserved"], 1)
        self.assertIn("Reserved Documentation IPv4", r_ip["external_intel_summary"])

        # SHA-256 hash check
        sample_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        r_hash = self.client.post("/api/threat-intel/lookup", json={"ioc_value": sample_sha256}).json()
        self.assertEqual(r_hash["ioc_type"], "sha256")
        self.assertIn("Offline Mode", r_hash["external_intel_status"])

        # Invalid IOC rejected
        bad_ioc = self.client.post("/api/threat-intel/lookup", json={"ioc_value": "not_an_ioc_$$$"})
        self.assertEqual(bad_ioc.status_code, 400)

    def test_07_reports_pdf_csv_json_export(self):
        pdf_res = self.client.get("/api/reports/export", params={"format": "pdf", "report_type": "executive_soc_summary"})
        self.assertEqual(pdf_res.status_code, 200)
        self.assertEqual(pdf_res.headers["content-type"], "application/pdf")
        self.assertTrue(pdf_res.content.startswith(b"%PDF"))

        csv_res = self.client.get("/api/reports/export", params={"format": "csv"})
        self.assertEqual(csv_res.status_code, 200)
        self.assertIn("Wasif Karim", csv_res.text)

        json_res = self.client.get("/api/reports/export", params={"format": "json"})
        self.assertEqual(json_res.status_code, 200)
        self.assertEqual(json_res.json()["developer"]["name"], "Wasif Karim")

    def test_08_simulation_and_rule_management(self):
        sim = self.client.post("/api/live/simulate", json={"count": 3}).json()
        self.assertTrue(sim["simulation_mode"])
        self.assertEqual(sim["ingested"]["origin_type"], "simulated")

        rule_upd = self.client.patch("/api/rules/RULE-001", json={"threshold_count": 6, "enabled": True})
        self.assertEqual(rule_upd.status_code, 200)
        self.assertEqual(rule_upd.json()["threshold_count"], 6)

if __name__ == "__main__":
    unittest.main(verbosity=2)
