"""Phase 3 REST gateway tests; use only temporary databases and directories."""
import os, tempfile, unittest
from fastapi.testclient import TestClient
from security_engine import Authenticator, SecurityEngine, SQLiteSecurityStore
from file_security import FileSecurity
from api_auth import APIAuthenticator
from gateway_api import create_app

class GatewayAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.auth = Authenticator("test-auth-secret-key-32-bytes-minimum")
        self.store = SQLiteSecurityStore(os.path.join(self.tmp.name, "test.db"), audit_key="test-audit-secret-key-32-bytes-minimum")
        self.store.set_session("session-1", "admin-user")
        self.engine = SecurityEngine(store=self.store, authenticator=self.auth)
        self.files = FileSecurity(self.engine, os.path.join(self.tmp.name, "protected"), allowed_extensions={"txt", "md", "json"})
        self.api_auth = APIAuthenticator(self.auth, {"test-api-key": {"user_id":"admin-user", "session_id":"session-1"}})
        self.client = TestClient(create_app(self.engine, self.files, self.api_auth))
        self.headers = {"Authorization":"Bearer test-api-key"}

    def tearDown(self):
        self.files.close(); self.engine.store.close(); self.tmp.cleanup()

    def test_health_is_public(self):
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200); self.assertEqual(r.json()["status"], "ok")

    def test_protected_endpoint_requires_auth(self):
        r = self.client.post("/v1/authorize", json={"action_type":"READ", "principal":"report-agent", "resource_id":"public-guide"})
        self.assertEqual(r.status_code, 401)

    def test_authorize_allowed_with_server_issued_context(self):
        r = self.client.post("/v1/authorize", headers=self.headers, json={"action_type":"READ", "principal":"report-agent", "resource_id":"public-guide"})
        self.assertEqual(r.status_code, 200, r.text); self.assertTrue(r.json()["allowed"])

    def test_client_cannot_supply_identity_or_clearance(self):
        payload = {"action_type":"READ", "principal":"report-agent", "resource_id":"public-guide", "user_id":"root", "clearance":"RESTRICTED"}
        r = self.client.post("/v1/authorize", headers=self.headers, json=payload)
        self.assertEqual(r.status_code, 422)

    def test_invalid_api_key_rejected(self):
        r = self.client.get("/v1/resources/public-guide", headers={"Authorization":"Bearer wrong"})
        self.assertEqual(r.status_code, 401)

    def test_missing_and_forged_credentials_are_401(self):
        self.assertEqual(self.client.get("/v1/resources/public-guide").status_code, 401)
        self.assertEqual(self.client.get("/v1/resources/public-guide", headers={"Authorization":"Bearer forged"}).status_code, 401)

    def test_bola_cross_user_resource_is_forbidden(self):
        app = create_app(self.engine, self.files, self.api_auth, resource_owners={"alice-private": "alice"})
        client = TestClient(app)
        r = client.get("/v1/resources/alice-private", headers=self.headers)
        self.assertEqual(r.status_code, 403)

    def test_rate_limit_returns_429(self):
        app = create_app(self.engine, self.files, self.api_auth, rate_limit_requests=2, rate_limit_window_seconds=60)
        client = TestClient(app)
        self.assertEqual(client.get("/v1/resources/public-guide", headers=self.headers).status_code, 200)
        self.assertEqual(client.get("/v1/resources/public-guide", headers=self.headers).status_code, 200)
        self.assertEqual(client.get("/v1/resources/public-guide", headers=self.headers).status_code, 429)

    def test_oversized_json_returns_413(self):
        app = create_app(self.engine, self.files, self.api_auth, max_request_body_bytes=1024)
        client = TestClient(app)
        payload = {"action_type":"READ", "principal":"report-agent", "resource_id":"public-guide", "extra":"x" * 1500}
        r = client.post("/v1/authorize", headers=self.headers, json=payload)
        self.assertEqual(r.status_code, 413)

    def test_path_traversal_rejected(self):
        r = self.client.post("/v1/files/read", headers=self.headers, json={"principal":"report-agent", "resource_id":"x", "path":"../../etc/passwd"})
        self.assertIn(r.status_code, (400, 403, 422))

    def test_sql_injection_and_script_inputs_rejected(self):
        sql = self.client.post("/v1/authorize", headers=self.headers, json={"action_type":"READ", "principal":"report-agent", "resource_id":"x OR 1=1 --"})
        script = self.client.post("/v1/files/read", headers=self.headers, json={"principal":"report-agent", "resource_id":"x", "path":"<script>alert(1)</script>.txt"})
        self.assertEqual(sql.status_code, 422)
        self.assertEqual(script.status_code, 422)

    def test_backend_failure_returns_503_and_opens_breaker(self):
        app = create_app(self.engine, self.files, self.api_auth, circuit_breaker_threshold=1, circuit_breaker_reset_seconds=60)
        client = TestClient(app)
        original_read = self.files.read
        def broken_read(*args, **kwargs):
            raise TimeoutError("internal details must not leak")
        self.files.read = broken_read
        payload = {"principal":"report-agent", "resource_id":"public-guide", "path":"guide.txt"}
        try:
            r = client.post("/v1/files/read", headers=self.headers, json=payload)
            self.assertEqual(r.status_code, 503)
            self.assertNotIn("internal details", r.text)
            r2 = client.post("/v1/files/read", headers=self.headers, json=payload)
            self.assertEqual(r2.status_code, 503)
        finally:
            self.files.read = original_read

if __name__ == "__main__": unittest.main()
