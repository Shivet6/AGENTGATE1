"""Unit tests for the AGENTGATE Phase 1 security engine."""
import os
import tempfile
import unittest

from security_engine import (
    ActionType, Authenticator, DecisionStatus, RequestContext, SecureToolGateway,
    SecurityEngine, SecurityLabel, SQLiteSecurityStore,
)


class SecurityEngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp.name, "test.db")
        self.auth = Authenticator("test-auth-secret-key-32-bytes-minimum")
        self.store = SQLiteSecurityStore(self.db_path, audit_key="test-audit-secret-key-32-bytes-minimum")
        self.store.set_session("session-1", "admin-user")
        self.context = self.auth.issue_context("admin-user", "session-1")
        self.engine = SecurityEngine(store=self.store, authenticator=self.auth)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def check(self, payload, allowed, code=None, context=None):
        result = self.engine.evaluate_untrusted(payload, context or self.context)
        self.assertEqual(result.allowed, allowed, result.model_dump())
        self.assertEqual(result.status, DecisionStatus.ALLOW if allowed else DecisionStatus.BLOCK)
        self.assertIsNotNone(result.audit_id)
        if code:
            self.assertEqual(result.code, code)
        return result

    def payload(self, **overrides):
        data = {"action_type": "READ", "principal": "report-agent", "target_resource": "public-guide"}
        data.update(overrides)
        return data

    def test_authorized_confidential_delivery(self):
        self.check(self.payload(action_type="DELIVER", target_resource="payroll-summary",
                    recipient="finance@example.com", tool_name="email", destination_domain="example.com"), True)

    def test_low_clearance_recipient_blocked(self):
        self.check(self.payload(action_type="DELIVER", target_resource="payroll-summary",
                    recipient="public@example.com", tool_name="email", destination_domain="example.com"), False,
                   "RECIPIENT_CLEARANCE_TOO_LOW")

    def test_unknown_recipient_blocked(self):
        self.check(self.payload(action_type="DELIVER", target_resource="payroll-summary",
                    recipient="attacker@example.com", tool_name="email", destination_domain="example.com"), False,
                   "RECIPIENT_NOT_AUTHORIZED")

    def test_low_clearance_principal_blocked(self):
        self.check(self.payload(principal="intern-agent", target_resource="payroll-master"), False,
                   "INSUFFICIENT_PRINCIPAL_CLEARANCE")

    def test_unknown_resource_blocked(self):
        self.check(self.payload(target_resource="missing-resource"), False, "UNKNOWN_RESOURCE")

    def test_path_like_resource_rejected(self):
        self.check(self.payload(target_resource="../../etc/passwd"), False, "INVALID_PROPOSAL")

    def test_untrusted_clearance_cannot_be_supplied(self):
        self.check(self.payload(principal_clearance="RESTRICTED"), False, "INVALID_PROPOSAL")

    def test_unknown_principal_blocked(self):
        self.check(self.payload(principal="unknown-agent"), False, "UNKNOWN_PRINCIPAL")

    def test_user_cannot_invoke_unapproved_principal(self):
        self.store.set_session("guest-session", "guest-user")
        guest_context = self.auth.issue_context("guest-user", "guest-session")
        self.check(self.payload(), False, "USER_NOT_AUTHORIZED", guest_context)

    def test_context_required(self):
        result = self.engine.evaluate_untrusted(self.payload(), None)
        self.assertFalse(result.allowed)
        self.assertEqual(result.code, "INVALID_SESSION")

    def test_session_user_mismatch_blocked(self):
        bad_context = self.auth.issue_context("analyst-user", "session-1")
        self.check(self.payload(), False, "INVALID_SESSION", bad_context)

    def test_invalid_workflow_state_blocked(self):
        ctx = self.auth.issue_context("admin-user", "session-1", "PAUSED", "PAUSED")
        self.check(self.payload(), False, "WORKFLOW_STATE_INVALID", ctx)

    def test_payload_limit(self):
        self.check(self.payload(payload_size_bytes=1_000_001), False, "PAYLOAD_TOO_LARGE")

    def test_tool_allowlist(self):
        self.check(self.payload(tool_name="shell"), False, "TOOL_NOT_ALLOWED")

    def test_domain_allowlist(self):
        self.check(self.payload(action_type="DELIVER", recipient="finance@example.com", tool_name="email",
                    destination_domain="evil.example"), False, "DOMAIN_NOT_ALLOWED")

    def test_recipient_domain_checked_even_when_destination_omitted(self):
        self.check(self.payload(action_type="DELIVER", recipient="finance@evil.example", tool_name="email"),
                   False, "RECIPIENT_NOT_AUTHORIZED")

    def test_save_requires_write_permission(self):
        self.check(self.payload(action_type="SAVE", principal="intern-agent", target_resource="payroll-summary"),
                   False, "INSUFFICIENT_PRINCIPAL_CLEARANCE")

    def test_recipient_not_allowed_for_read(self):
        self.check(self.payload(recipient="finance@example.com"), False, "RECIPIENT_NOT_ALLOWED_FOR_ACTION")

    def test_extra_fields_fail_closed(self):
        self.check(self.payload(execute_now=True), False, "INVALID_PROPOSAL")

    def test_label_inheritance_and_persistence(self):
        self.store.set_artifact_label("source-confidential", SecurityLabel.CONFIDENTIAL)
        inherited = self.store.inherit_label("derived-note", ["source-confidential"])
        self.assertEqual(inherited, SecurityLabel.CONFIDENTIAL)
        self.assertEqual(self.store.get_artifact_label("derived-note"), SecurityLabel.CONFIDENTIAL)
        # A derived artifact cannot be assigned a lower label than its parent.
        self.assertEqual(self.store.inherit_label("derived-again", ["derived-note"], SecurityLabel.PUBLIC),
                         SecurityLabel.CONFIDENTIAL)

    def test_stored_label_can_only_raise_classification(self):
        self.store.set_artifact_label("public-guide", SecurityLabel.RESTRICTED)
        self.check(self.payload(principal="intern-agent"), False, "INSUFFICIENT_PRINCIPAL_CLEARANCE")

    def test_audit_chain_valid(self):
        self.check(self.payload(), True)
        self.assertTrue(self.store.verify_audit_chain())

    def test_read_rejects_destination_domain(self):
        self.check(self.payload(destination_domain="example.com"), False, "RECIPIENT_NOT_ALLOWED_FOR_ACTION")


    def test_unsigned_context_blocked(self):
        unsigned = RequestContext("admin-user", "session-1")
        self.check(self.payload(), False, "AUTHENTICATION_FAILED", unsigned)

    def test_context_tampering_blocked(self):
        signed = self.auth.issue_context("admin-user", "session-1")
        tampered = RequestContext("guest-user", signed.session_id, signed.workflow_state,
                                  signed.expected_workflow_state, signed.signature)
        self.check(self.payload(), False, "AUTHENTICATION_FAILED", tampered)

    def test_gateway_checks_actual_payload_size_and_does_not_execute(self):
        calls = []
        gateway = SecureToolGateway(self.engine, {"resource": lambda proposal, payload: calls.append(payload) or "ok"})
        proposal = self.payload(payload_size_bytes=0)
        decision, result = gateway.execute(proposal, self.context, b"x" * 1_000_001)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "PAYLOAD_TOO_LARGE")
        self.assertIsNone(result)
        self.assertEqual(calls, [])

    def test_gateway_executes_only_after_approval(self):
        calls = []
        gateway = SecureToolGateway(self.engine, {"resource": lambda proposal, payload: calls.append(payload) or "ok"})
        decision, result = gateway.execute(self.payload(), self.context, b"hello")
        self.assertTrue(decision.allowed)
        self.assertEqual(result, "ok")
        self.assertEqual(calls, [b"hello"])

    def test_gateway_non_bytes_payload_is_audited(self):
        gateway = SecureToolGateway(self.engine, {"resource": lambda proposal, payload: "should not run"})
        decision, result = gateway.execute(self.payload(), self.context, "not-bytes")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "INVALID_PROPOSAL")
        self.assertIsNotNone(decision.audit_id)
        self.assertIsNone(result)
        self.assertTrue(self.store.verify_audit_chain())
        events = self.store.get_audit_events()
        self.assertEqual(events[-1]["code"], "INVALID_PROPOSAL")

    def test_gateway_missing_handler_has_specific_audited_denial(self):
        gateway = SecureToolGateway(self.engine, {})
        decision, result = gateway.execute(self.payload(), self.context, b"hello")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "TOOL_HANDLER_NOT_REGISTERED")
        self.assertIsNotNone(decision.audit_id)
        self.assertIsNone(result)
        self.assertTrue(self.store.verify_audit_chain())
        events = self.store.get_audit_events()
        self.assertEqual(events[-1]["code"], "TOOL_HANDLER_NOT_REGISTERED")
        self.assertEqual(events[-1]["decision"], "BLOCK")

    def test_gateway_handler_failure_is_audited(self):
        def failing_handler(proposal, payload):
            raise RuntimeError("private implementation details")
        gateway = SecureToolGateway(self.engine, {"resource": failing_handler})
        decision, result = gateway.execute(self.payload(), self.context, b"hello")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "EXECUTION_FAILED")
        self.assertNotIn("private implementation details", decision.reason)
        self.assertIsNotNone(decision.audit_id)
        self.assertIsNone(result)
        self.assertTrue(self.store.verify_audit_chain())
        events = self.store.get_audit_events()
        self.assertEqual(events[-1]["code"], "EXECUTION_FAILED")
        self.assertEqual(events[-1]["decision"], "BLOCK")

    def test_audit_storage_rejects_update_and_delete(self):
        self.check(self.payload(), True)
        self.assertTrue(self.store.verify_audit_chain())
        import sqlite3
        with sqlite3.connect(self.db_path) as con:
            with self.assertRaises(sqlite3.IntegrityError):
                con.execute("UPDATE audit_events SET rule='rewritten' WHERE id=1")
            with self.assertRaises(sqlite3.IntegrityError):
                con.execute("DELETE FROM audit_events WHERE id=1")
        self.assertTrue(self.store.verify_audit_chain())

    def test_malformed_request_audit_has_required_fields(self):
        self.engine.evaluate_untrusted({"bad": "payload"}, None)
        event = self.store.get_audit_events()[-1]
        for field in ("timestamp", "user_id", "principal", "action", "resource", "recipient",
                      "data_label", "decision", "code", "rule", "previous_hash", "event_hash"):
            self.assertIsNotNone(event[field], field)
        self.assertEqual(event["action"], "UNKNOWN")
        self.assertEqual(event["resource"], "UNKNOWN")

    def test_allow_and_block_decisions_are_both_audited_with_complete_fields(self):
        self.check(self.payload(), True)
        self.check(self.payload(principal="unknown-agent"), False, "UNKNOWN_PRINCIPAL")
        events = self.store.get_audit_events()
        self.assertEqual([event["decision"] for event in events[-2:]], ["ALLOW", "BLOCK"])
        required = ("timestamp", "user_id", "principal", "action", "resource", "recipient",
                    "data_label", "decision", "code", "rule", "previous_hash", "event_hash")
        for event in events:
            for field in required:
                self.assertIsNotNone(event[field], f"event={event['id']} field={field}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
