"""Phase 4 audit-system tests: trusted access, filters, paging, exports and integrity."""
import csv, io, json, os, tempfile, unittest
from fastapi.testclient import TestClient
from security_engine import Authenticator, SecurityEngine, SQLiteSecurityStore, ToolProposal, ActionType
from file_security import FileSecurity
from api_auth import APIAuthenticator
from gateway_api import create_app
from audit_system import AuditService, AuditAccessError

class AuditServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteSecurityStore(os.path.join(self.tmp.name, "audit.db"), audit_key="test-audit-secret-key-32-bytes-minimum")
        self.auth = Authenticator("test-auth-secret-key-32-bytes-minimum")
        self.store.set_session("session-1", "admin-user")
        self.engine = SecurityEngine(store=self.store, authenticator=self.auth)
        self.engine.evaluate(ToolProposal(action_type=ActionType.READ, principal="report-agent", target_resource="public-guide"), self.auth.issue_context("admin-user", "session-1"))
        self.service = AuditService(self.store, {"admin-user"})

    def tearDown(self): self.store.close(); self.tmp.cleanup()

    def test_reader_allowlist_fails_closed(self):
        with self.assertRaises(AuditAccessError): AuditService(self.store).list_events("admin-user")
        with self.assertRaises(AuditAccessError): self.service.list_events("guest-user")

    def test_list_pagination_and_filter(self):
        self.engine.evaluate(ToolProposal(action_type=ActionType.READ, principal="report-agent", target_resource="team-notes"), self.auth.issue_context("admin-user", "session-1"))
        page = self.service.list_events("admin-user", limit=1, offset=0)
        self.assertEqual(page["total"], 2); self.assertEqual(len(page["events"]), 1); self.assertTrue(page["has_more"])
        filtered = self.service.list_events("admin-user", filters={"resource": "team-notes"})
        self.assertEqual(filtered["total"], 1)

    def test_integrity_verification(self):
        report = self.service.verify_integrity("admin-user")
        self.assertTrue(report["valid"]); self.assertEqual(report["events_checked"], 1)

    def test_json_and_csv_exports(self):
        data = json.loads(self.service.export_json("admin-user"))
        self.assertEqual(data["count"], 1); self.assertTrue(data["integrity"])
        rows = list(csv.DictReader(io.StringIO(self.service.export_csv("admin-user"))))
        self.assertEqual(len(rows), 1); self.assertIn("event_hash", rows[0])

    def test_bad_pagination_and_filter_rejected(self):
        with self.assertRaises(ValueError): self.service.list_events("admin-user", limit=501)
        with self.assertRaises(ValueError): self.service.list_events("admin-user", filters={"sql": "x"})

class AuditAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.auth = Authenticator("test-auth-secret-key-32-bytes-minimum")
        self.store = SQLiteSecurityStore(os.path.join(self.tmp.name, "api.db"), audit_key="test-audit-secret-key-32-bytes-minimum")
        self.store.set_session("session-1", "admin-user")
        self.engine = SecurityEngine(store=self.store, authenticator=self.auth)
        self.files = FileSecurity(self.engine, os.path.join(self.tmp.name, "protected"), allowed_extensions={"txt", "md", "json"})
        api_auth = APIAuthenticator(self.auth, {"test-api-key": {"user_id":"admin-user", "session_id":"session-1"}})
        self.client = TestClient(create_app(self.engine, self.files, api_auth, audit_readers={"admin-user"}))
        self.headers = {"Authorization": "Bearer test-api-key"}
        self.engine.evaluate(ToolProposal(action_type=ActionType.READ, principal="report-agent", target_resource="public-guide"), self.auth.issue_context("admin-user", "session-1"))

    def tearDown(self): self.files.close(); self.engine.store.close(); self.tmp.cleanup()

    def test_audit_list_verify_and_exports(self):
        r = self.client.get("/v1/audit", headers=self.headers)
        self.assertEqual(r.status_code, 200, r.text); self.assertEqual(r.json()["total"], 1)
        r = self.client.get("/v1/audit/verify", headers=self.headers)
        self.assertEqual(r.status_code, 200); self.assertTrue(r.json()["valid"])
        self.assertEqual(self.client.get("/v1/audit/export?format=json", headers=self.headers).status_code, 200)
        self.assertEqual(self.client.get("/v1/audit/export?format=csv", headers=self.headers).headers["content-type"].split(";")[0], "text/csv")

    def test_audit_endpoints_deny_non_reader(self):
        # Same valid credential but app configured with no audit readers.
        app = create_app(self.engine, self.files, APIAuthenticator(self.auth, {"test-api-key": {"user_id":"admin-user", "session_id":"session-1"}}), audit_readers=set())
        client = TestClient(app)
        self.assertEqual(client.get("/v1/audit", headers=self.headers).status_code, 403)
        self.assertEqual(client.get("/v1/audit/verify", headers=self.headers).status_code, 403)

    def test_audit_paging_validation(self):
        self.assertEqual(self.client.get("/v1/audit?limit=0", headers=self.headers).status_code, 400)

if __name__ == "__main__": unittest.main()
