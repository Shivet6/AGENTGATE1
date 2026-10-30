"""AGENTGATE Phase 1: deterministic policy engine with IFC, guardrails and SQLite audit.

Python 3.10+, Pydantic 2.x. This module evaluates actions only; it never executes tools.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from contextlib import contextmanager
from enum import Enum, IntEnum
import hashlib
import queue
import threading
import hmac
import json
import os
import re
import secrets
import sqlite3
from pathlib import Path
from typing import Callable, Mapping, Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


class SecurityLabel(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3


class ActionType(str, Enum):
    READ = "READ"
    SAVE = "SAVE"
    DELIVER = "DELIVER"


class DecisionStatus(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


class DenialCode(str, Enum):
    INVALID_PROPOSAL = "INVALID_PROPOSAL"
    UNKNOWN_PRINCIPAL = "UNKNOWN_PRINCIPAL"
    UNKNOWN_RESOURCE = "UNKNOWN_RESOURCE"
    ACTION_NOT_PERMITTED = "ACTION_NOT_PERMITTED"
    INSUFFICIENT_PRINCIPAL_CLEARANCE = "INSUFFICIENT_PRINCIPAL_CLEARANCE"
    RECIPIENT_REQUIRED = "RECIPIENT_REQUIRED"
    RECIPIENT_NOT_AUTHORIZED = "RECIPIENT_NOT_AUTHORIZED"
    RECIPIENT_CLEARANCE_TOO_LOW = "RECIPIENT_CLEARANCE_TOO_LOW"
    RECIPIENT_NOT_ALLOWED_FOR_ACTION = "RECIPIENT_NOT_ALLOWED_FOR_ACTION"
    USER_NOT_AUTHORIZED = "USER_NOT_AUTHORIZED"
    INVALID_SESSION = "INVALID_SESSION"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    DOMAIN_NOT_ALLOWED = "DOMAIN_NOT_ALLOWED"
    TOOL_NOT_ALLOWED = "TOOL_NOT_ALLOWED"
    WORKFLOW_STATE_INVALID = "WORKFLOW_STATE_INVALID"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    TOOL_HANDLER_NOT_REGISTERED = "TOOL_HANDLER_NOT_REGISTERED"
    EXECUTION_FAILED = "EXECUTION_FAILED"


_RESOURCE_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$")
_PRINCIPAL_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,63}$")
_USER_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,63}$")
_EMAIL = re.compile(r"^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$")


class ToolProposal(BaseModel):
    """Untrusted tool request. Identity, role, labels and clearance cannot be asserted here."""
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)
    action_type: ActionType
    principal: str = Field(min_length=1, max_length=64)
    target_resource: str = Field(min_length=1, max_length=128)
    recipient: str | None = Field(default=None, min_length=3, max_length=254)
    tool_name: str = Field(default="resource", min_length=1, max_length=64)
    payload_size_bytes: int = Field(default=0, ge=0)
    destination_domain: str | None = Field(default=None, min_length=1, max_length=253)

    @field_validator("principal")
    @classmethod
    def valid_principal(cls, value: str) -> str:
        if not _PRINCIPAL_ID.fullmatch(value):
            raise ValueError("principal must be a logical identifier")
        return value

    @field_validator("target_resource")
    @classmethod
    def valid_resource(cls, value: str) -> str:
        if not _RESOURCE_ID.fullmatch(value):
            raise ValueError("resource must be a logical identifier, not a path")
        return value

    @field_validator("tool_name")
    @classmethod
    def valid_tool(cls, value: str) -> str:
        if not _PRINCIPAL_ID.fullmatch(value):
            raise ValueError("tool_name must be a logical identifier")
        return value.casefold()

    @field_validator("recipient")
    @classmethod
    def valid_recipient(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip().casefold()
        if not _EMAIL.fullmatch(value):
            raise ValueError("recipient must be a valid email address")
        return value

    @field_validator("destination_domain")
    @classmethod
    def normalize_domain(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip().casefold().rstrip(".")
        if not value or "/" in value or "@" in value or " " in value:
            raise ValueError("destination_domain must be a domain name only")
        return value


class PolicyDecision(BaseModel):
    model_config = ConfigDict(frozen=True)
    status: DecisionStatus
    allowed: bool
    code: str
    reason: str
    action_type: ActionType | None = None
    principal: str | None = None
    target_resource: str | None = None
    data_label: SecurityLabel | None = None
    audit_id: int | None = None


@dataclass(frozen=True, slots=True)
class PrincipalPolicy:
    clearance: SecurityLabel
    allowed_actions: frozenset[ActionType]


@dataclass(frozen=True, slots=True)
class ResourcePolicy:
    label: SecurityLabel
    writable_by: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class RecipientPolicy:
    clearance: SecurityLabel


@dataclass(frozen=True, slots=True)
class UserPolicy:
    role: str
    allowed_principals: frozenset[str]


@dataclass(frozen=True, slots=True)
class PolicyStore:
    principals: Mapping[str, PrincipalPolicy]
    resources: Mapping[str, ResourcePolicy]
    recipients: Mapping[str, RecipientPolicy]
    users: Mapping[str, UserPolicy]
    allowed_tools: frozenset[str]
    allowed_domains: frozenset[str]
    max_payload_bytes: int = 1_000_000


DEFAULT_POLICIES = PolicyStore(
    principals={
        "report-agent": PrincipalPolicy(SecurityLabel.RESTRICTED, frozenset({ActionType.READ, ActionType.SAVE, ActionType.DELIVER})),
        "intern-agent": PrincipalPolicy(SecurityLabel.INTERNAL, frozenset({ActionType.READ, ActionType.SAVE})),
    },
    resources={
        "public-guide": ResourcePolicy(SecurityLabel.PUBLIC, frozenset({"report-agent", "intern-agent"})),
        "team-notes": ResourcePolicy(SecurityLabel.INTERNAL, frozenset({"report-agent", "intern-agent"})),
        "payroll-summary": ResourcePolicy(SecurityLabel.CONFIDENTIAL, frozenset({"report-agent"})),
        "payroll-master": ResourcePolicy(SecurityLabel.RESTRICTED, frozenset({"report-agent"})),
    },
    recipients={
        "finance@example.com": RecipientPolicy(SecurityLabel.CONFIDENTIAL),
        "auditor@example.com": RecipientPolicy(SecurityLabel.RESTRICTED),
        "public@example.com": RecipientPolicy(SecurityLabel.PUBLIC),
    },
    users={
        "admin-user": UserPolicy("Admin", frozenset({"report-agent", "intern-agent"})),
        "analyst-user": UserPolicy("Analyst", frozenset({"report-agent", "intern-agent"})),
        "guest-user": UserPolicy("Guest", frozenset({"intern-agent"})),
    },
    allowed_tools=frozenset({"resource", "email", "document", "database"}),
    allowed_domains=frozenset({"example.com"}),
    max_payload_bytes=1_000_000,
)


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Signed identity context. Do not construct from untrusted request JSON."""
    user_id: str
    session_id: str
    workflow_state: str = "ACTIVE"
    expected_workflow_state: str = "ACTIVE"
    signature: str = ""


class Authenticator:
    """HMAC-signed context issuer/verifier. Keep its secret outside agent-controlled code."""
    def __init__(self, secret: str | bytes | None = None) -> None:
        configured = secret if secret is not None else os.environ.get("AGENTGATE_AUTH_KEY")
        self.persistent_secret_configured = configured is not None
        if configured is None:
            configured = secrets.token_bytes(32)
        self._secret = configured.encode("utf-8") if isinstance(configured, str) else configured
        if len(self._secret) < 32:
            raise ValueError("Authentication secret must be at least 32 bytes")

    @staticmethod
    def _body(user_id: str, session_id: str, workflow_state: str, expected_workflow_state: str) -> bytes:
        return json.dumps({"user_id": user_id, "session_id": session_id,
                           "workflow_state": workflow_state,
                           "expected_workflow_state": expected_workflow_state},
                          sort_keys=True, separators=(",", ":")).encode("utf-8")

    def issue_context(self, user_id: str, session_id: str, workflow_state: str = "ACTIVE",
                      expected_workflow_state: str = "ACTIVE") -> RequestContext:
        if not _USER_ID.fullmatch(user_id) or not session_id or len(session_id) > 128:
            raise ValueError("Invalid user or session identifier")
        body = self._body(user_id, session_id, workflow_state, expected_workflow_state)
        signature = hmac.new(self._secret, body, hashlib.sha256).hexdigest()
        return RequestContext(user_id, session_id, workflow_state, expected_workflow_state, signature)

    def verify(self, context: RequestContext | None) -> bool:
        if context is None or not context.signature:
            return False
        body = self._body(context.user_id, context.session_id, context.workflow_state,
                          context.expected_workflow_state)
        expected = hmac.new(self._secret, body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(context.signature, expected)


def _decision(allowed: bool, code: str, reason: str, proposal: ToolProposal | None = None,
              label: SecurityLabel | None = None, audit_id: int | None = None) -> PolicyDecision:
    return PolicyDecision(
        status=DecisionStatus.ALLOW if allowed else DecisionStatus.BLOCK,
        allowed=allowed, code=code, reason=reason,
        action_type=proposal.action_type if proposal else None,
        principal=proposal.principal if proposal else None,
        target_resource=proposal.target_resource if proposal else None,
        data_label=label, audit_id=audit_id,
    )


class SQLiteSecurityStore:
    """SQLite persistence for labels, provenance, workflow state and hash-chained audit events."""
    def __init__(self, db_path: str | Path = "agentgate_security.db", audit_key: str | bytes | None = None) -> None:
        self.db_path = str(db_path)
        configured = audit_key if audit_key is not None else os.environ.get("AGENTGATE_AUDIT_KEY")
        self.persistent_audit_key_configured = configured is not None
        if configured is None:
            configured = secrets.token_bytes(32)
        self._audit_key = configured.encode("utf-8") if isinstance(configured, str) else configured
        if len(self._audit_key) < 32:
            raise ValueError("Audit key must be at least 32 bytes")
        self._audit_queue = queue.Queue()
        self._audit_queue_init_lock = threading.Lock()
        self._audit_worker = None
        self._initialize()
        self._audit_worker = threading.Thread(target=self._audit_worker_loop, daemon=True,
                                              name="agentgate-audit-writer")
        self._audit_worker.start()
        with self._connect() as con:
            pending_ids = [row[0] for row in con.execute("SELECT id FROM audit_write_queue ORDER BY id").fetchall()]
        for pending_id in pending_ids:
            self._audit_queue.put(pending_id)

    @contextmanager
    def _connect(self):
        con = sqlite3.connect(self.db_path, timeout=5.0)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def _initialize(self) -> None:
        with self._connect() as con:
            con.execute("PRAGMA journal_mode=WAL")
            con.executescript("""
                CREATE TABLE IF NOT EXISTS artifact_labels (
                    artifact_id TEXT PRIMARY KEY,
                    label INTEGER NOT NULL CHECK(label BETWEEN 0 AND 3),
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS provenance (
                    artifact_id TEXT NOT NULL,
                    parent_artifact_id TEXT NOT NULL,
                    PRIMARY KEY (artifact_id, parent_artifact_id)
                );
                CREATE TABLE IF NOT EXISTS file_resource_map (
                    resource_id TEXT PRIMARY KEY,
                    relative_path TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS workflow_sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    principal TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    data_label TEXT NOT NULL,
                    decision TEXT NOT NULL CHECK(decision IN ('ALLOW','BLOCK')),
                    code TEXT NOT NULL,
                    rule TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_write_queue (
                    id INTEGER PRIMARY KEY,
                    event_json TEXT NOT NULL,
                    queued_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_id_sequence (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    next_id INTEGER NOT NULL
                );
                INSERT OR IGNORE INTO audit_id_sequence(singleton, next_id)
                    VALUES (1, COALESCE((SELECT MAX(id) + 1 FROM audit_events), 1));
                CREATE TRIGGER IF NOT EXISTS audit_events_no_update
                BEFORE UPDATE ON audit_events BEGIN
                    SELECT RAISE(ABORT, 'audit_events is append-only: UPDATE denied');
                END;
                CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
                BEFORE DELETE ON audit_events BEGIN
                    SELECT RAISE(ABORT, 'audit_events is append-only: DELETE denied');
                END;
                CREATE TRIGGER IF NOT EXISTS audit_events_validate_insert
                BEFORE INSERT ON audit_events
                WHEN NEW.timestamp IS NULL OR NEW.session_id IS NULL OR NEW.user_id IS NULL
                  OR NEW.principal IS NULL OR NEW.action IS NULL OR NEW.resource IS NULL
                  OR NEW.recipient IS NULL OR NEW.data_label IS NULL OR NEW.decision IS NULL
                  OR NEW.code IS NULL OR NEW.rule IS NULL OR NEW.previous_hash IS NULL
                  OR NEW.event_hash IS NULL
                BEGIN
                    SELECT RAISE(ABORT, 'required audit fields must be non-null');
                END;
            """)

    def set_session(self, session_id: str, user_id: str, state: str = "ACTIVE") -> None:
        now = _utc_now()
        with self._connect() as con:
            con.execute("INSERT INTO workflow_sessions VALUES (?, ?, ?, ?) ON CONFLICT(session_id) DO UPDATE SET user_id=excluded.user_id, state=excluded.state, updated_at=excluded.updated_at",
                        (session_id, user_id, state, now))

    def session_matches(self, session_id: str, user_id: str, expected_state: str) -> bool:
        with self._connect() as con:
            row = con.execute("SELECT user_id, state FROM workflow_sessions WHERE session_id=?", (session_id,)).fetchone()
        return bool(row and row["user_id"] == user_id and row["state"] == expected_state)

    def register_file_resource(self, resource_id: str, relative_path: str) -> None:
        """Register a trusted resource-to-relative-path binding (admin/setup operation)."""
        if not _RESOURCE_ID.fullmatch(resource_id):
            raise ValueError("resource_id must be a logical identifier")
        if not isinstance(relative_path, str) or not relative_path or relative_path.startswith(("/", "\\")) or "\x00" in relative_path:
            raise ValueError("relative_path must be a clean relative path")
        normalized = relative_path.replace("\\", "/")
        parts = normalized.split("/")
        if any(part in ("", ".", "..") for part in parts) or (parts and ":" in parts[0]):
            raise ValueError("relative_path must be a clean relative path")
        with self._connect() as con:
            row = con.execute("SELECT relative_path FROM file_resource_map WHERE resource_id=?", (resource_id,)).fetchone()
            if row and row["relative_path"] != normalized:
                raise ValueError("resource is already bound to a different path")
            con.execute("INSERT OR IGNORE INTO file_resource_map VALUES (?, ?, ?)", (resource_id, normalized, _utc_now()))

    def get_file_resource_path(self, resource_id: str) -> str | None:
        with self._connect() as con:
            row = con.execute("SELECT relative_path FROM file_resource_map WHERE resource_id=?", (resource_id,)).fetchone()
        return row["relative_path"] if row else None

    def set_artifact_label(self, artifact_id: str, label: SecurityLabel) -> None:
        if not _RESOURCE_ID.fullmatch(artifact_id):
            raise ValueError("artifact_id must be a logical identifier")
        with self._connect() as con:
            con.execute("INSERT INTO artifact_labels VALUES (?, ?, ?) ON CONFLICT(artifact_id) DO UPDATE SET label=excluded.label, updated_at=excluded.updated_at",
                        (artifact_id, int(label), _utc_now()))

    def get_artifact_label(self, artifact_id: str) -> SecurityLabel | None:
        with self._connect() as con:
            row = con.execute("SELECT label FROM artifact_labels WHERE artifact_id=?", (artifact_id,)).fetchone()
        return SecurityLabel(row["label"]) if row else None

    def calculate_inherited_label(self, parent_ids: list[str], declared_label: SecurityLabel | None = None) -> SecurityLabel:
        """Calculate a derived label without mutating persistence; commit it only at write time."""
        if not parent_ids:
            if declared_label is None:
                raise ValueError("new artifact needs a parent or an explicit trusted label")
            return declared_label
        parent_labels = [self.get_artifact_label(parent_id) for parent_id in parent_ids]
        if any(label is None for label in parent_labels):
            raise ValueError("all parent artifacts must have trusted stored labels")
        return max([*parent_labels, *([declared_label] if declared_label is not None else [])])

    def inherit_label(self, artifact_id: str, parent_ids: list[str], declared_label: SecurityLabel | None = None) -> SecurityLabel:
        """Derived artifact label is at least as sensitive as every parent and declared label."""
        if not parent_ids:
            if declared_label is None:
                raise ValueError("new artifact needs a parent or an explicit trusted label")
            final_label = declared_label
        else:
            parent_labels = [self.get_artifact_label(parent_id) for parent_id in parent_ids]
            if any(label is None for label in parent_labels):
                raise ValueError("all parent artifacts must have trusted stored labels")
            final_label = max([*parent_labels, *([declared_label] if declared_label is not None else [])])
        self.set_artifact_label(artifact_id, final_label)
        with self._connect() as con:
            con.executemany("INSERT OR IGNORE INTO provenance VALUES (?, ?)", [(artifact_id, parent) for parent in parent_ids])
        return final_label

    def append_audit(self, event: dict[str, object]) -> int:
        """Durably enqueue an audit event; a background worker hashes and appends it.

        The queue row is committed before returning, so process restart recovery does not
        depend on an in-memory queue. Audit reads flush pending writes before returning.
        """
        normalized = dict(event)
        defaults = {
            "session_id": "UNKNOWN", "user_id": "UNKNOWN", "principal": "UNKNOWN",
            "action": "UNKNOWN", "resource": "UNKNOWN", "recipient": "NOT_APPLICABLE",
            "data_label": "UNKNOWN", "decision": "BLOCK", "code": "AUDIT_INPUT_INVALID",
            "rule": "Unavailable request fields were normalized for audit integrity.",
        }
        for key, default in defaults.items():
            value = normalized.get(key)
            if value is None or (isinstance(value, str) and not value.strip()):
                normalized[key] = default
        normalized["timestamp"] = _utc_now()
        with self._connect() as con:
            row = con.execute("SELECT next_id FROM audit_id_sequence WHERE singleton=1").fetchone()
            event_id = int(row["next_id"])
            con.execute("UPDATE audit_id_sequence SET next_id=? WHERE singleton=1", (event_id + 1,))
            con.execute("INSERT INTO audit_write_queue(id, event_json, queued_at) VALUES (?, ?, ?)",
                        (event_id, json.dumps(normalized, sort_keys=True, separators=(",", ":"), default=str), _utc_now()))
        self._audit_queue.put(event_id)
        return event_id

    def _audit_worker_loop(self) -> None:
        while True:
            event_id = self._audit_queue.get()
            if event_id is None:
                self._audit_queue.task_done()
                return
            try:
                with self._connect() as con:
                    queued = con.execute("SELECT id, event_json FROM audit_write_queue ORDER BY id LIMIT 1").fetchone()
                    if queued is None:
                        continue
                    event_id = int(queued["id"])
                    event = json.loads(queued["event_json"])
                    existing = con.execute("SELECT 1 FROM audit_events WHERE id=?", (event_id,)).fetchone()
                    if existing is None:
                        last = con.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
                        previous_hash = last["event_hash"] if last else "GENESIS"
                        body = {"timestamp": event["timestamp"], **{k: v for k, v in event.items() if k != "timestamp"},
                                "previous_hash": previous_hash}
                        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
                        event_hash = hmac.new(self._audit_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
                        con.execute("""INSERT INTO audit_events
                            (id, timestamp, session_id, user_id, principal, action, resource, recipient, data_label,
                             decision, code, rule, previous_hash, event_hash)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (event_id, event["timestamp"], event["session_id"], event["user_id"], event["principal"],
                             event["action"], event["resource"], event["recipient"], event["data_label"],
                             event["decision"], event["code"], event["rule"], previous_hash, event_hash))
                    con.execute("DELETE FROM audit_write_queue WHERE id=?", (event_id,))
            except Exception:
                # Keep the durable queue row for recovery; do not silently discard it.
                pass
            finally:
                self._audit_queue.task_done()

    def flush_audit_queue(self) -> None:
        """Wait for queued events and fail if any durable queue entries remain."""
        self._audit_queue.join()
        with self._connect() as con:
            pending = con.execute("SELECT COUNT(*) FROM audit_write_queue").fetchone()[0]
        if pending:
            raise RuntimeError(f"{pending} audit event(s) remain queued after a write failure")

    def close(self) -> None:
        """Flush durable audit events and stop the background writer cleanly."""
        if self._audit_worker is not None and self._audit_worker.is_alive():
            self.flush_audit_queue()
            self._audit_queue.put(None)
            self._audit_queue.join()
            self._audit_worker.join(timeout=5)
            self._audit_worker = None

    def get_audit_events(self) -> list[dict[str, object]]:
        """Return committed audit events after flushing the durable write queue."""
        self.flush_audit_queue()
        with self._connect() as con:
            rows = con.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    def verify_audit_chain(self) -> bool:
        self.flush_audit_queue()
        previous_hash = "GENESIS"
        with self._connect() as con:
            rows = con.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        for row in rows:
            body = {"timestamp": row["timestamp"], "session_id": row["session_id"], "user_id": row["user_id"],
                    "principal": row["principal"], "action": row["action"], "resource": row["resource"],
                    "recipient": row["recipient"], "data_label": row["data_label"], "decision": row["decision"],
                    "code": row["code"], "rule": row["rule"], "previous_hash": previous_hash}
            expected = hmac.new(self._audit_key, json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8"), hashlib.sha256).hexdigest()
            if row["previous_hash"] != previous_hash or row["event_hash"] != expected:
                return False
            previous_hash = row["event_hash"]
        return True


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class SecurityEngine:
    """Deterministic policy evaluator with optional SQLite persistence and auditing."""
    def __init__(self, policies: PolicyStore = DEFAULT_POLICIES,
                 store: SQLiteSecurityStore | None = None,
                 authenticator: Authenticator | None = None) -> None:
        self._policies = policies
        self.store = store
        self.authenticator = authenticator or Authenticator()

    def evaluate(self, proposal: ToolProposal, context: RequestContext | None = None) -> PolicyDecision:
        label: SecurityLabel | None = None
        code, reason, allowed = "POLICY_PASSED", "All configured policy checks passed.", True
        user_id = context.user_id if context else None
        session_id = context.session_id if context else None

        principal = self._policies.principals.get(proposal.principal)
        resource = self._policies.resources.get(proposal.target_resource)
        if principal is None:
            allowed, code, reason = False, DenialCode.UNKNOWN_PRINCIPAL.value, "Principal is not registered."
        elif resource is None:
            allowed, code, reason = False, DenialCode.UNKNOWN_RESOURCE.value, "Resource is not registered; access denied by default."
        else:
            stored_label = self.store.get_artifact_label(proposal.target_resource) if self.store is not None else None
            label = max(resource.label, stored_label) if stored_label is not None else resource.label
            if context is None:
                allowed, code, reason = False, DenialCode.INVALID_SESSION.value, "Trusted user/session context is required."
            elif not self.authenticator.verify(context):
                allowed, code, reason = False, DenialCode.AUTHENTICATION_FAILED.value, "Identity context signature is missing or invalid."
            elif not _USER_ID.fullmatch(context.user_id) or not context.session_id or len(context.session_id) > 128:
                allowed, code, reason = False, DenialCode.INVALID_SESSION.value, "Trusted user/session context is malformed."
            elif context.workflow_state != context.expected_workflow_state or context.workflow_state != "ACTIVE":
                allowed, code, reason = False, DenialCode.WORKFLOW_STATE_INVALID.value, "Workflow is not in the expected active state."
            elif self.store is not None and not self.store.session_matches(context.session_id, context.user_id, context.expected_workflow_state):
                allowed, code, reason = False, DenialCode.INVALID_SESSION.value, "Session is not registered for this user/state."
            else:
                user = self._policies.users.get(context.user_id)
                if user is None or proposal.principal not in user.allowed_principals:
                    allowed, code, reason = False, DenialCode.USER_NOT_AUTHORIZED.value, "User role is not authorized to invoke this principal."
                elif proposal.tool_name not in self._policies.allowed_tools:
                    allowed, code, reason = False, DenialCode.TOOL_NOT_ALLOWED.value, "Tool is not in the trusted allowlist."
                elif proposal.payload_size_bytes > self._policies.max_payload_bytes:
                    allowed, code, reason = False, DenialCode.PAYLOAD_TOO_LARGE.value, "Payload exceeds the configured maximum size."
                elif proposal.destination_domain and proposal.destination_domain not in self._policies.allowed_domains:
                    allowed, code, reason = False, DenialCode.DOMAIN_NOT_ALLOWED.value, "Destination domain is not allowlisted."
                elif proposal.action_type not in principal.allowed_actions:
                    allowed, code, reason = False, DenialCode.ACTION_NOT_PERMITTED.value, "Principal is not permitted to perform this action."
                elif principal.clearance < label:
                    allowed, code, reason = False, DenialCode.INSUFFICIENT_PRINCIPAL_CLEARANCE.value, f"Principal clearance {principal.clearance.name} is below resource label {label.name}."
                elif proposal.action_type == ActionType.SAVE and proposal.recipient is not None:
                    allowed, code, reason = False, DenialCode.RECIPIENT_NOT_ALLOWED_FOR_ACTION.value, "Recipient is only valid for DELIVER actions."
                elif proposal.action_type == ActionType.SAVE and proposal.principal not in resource.writable_by:
                    allowed, code, reason = False, DenialCode.ACTION_NOT_PERMITTED.value, "Principal is not authorized to write this resource."
                elif proposal.action_type == ActionType.READ and (proposal.recipient is not None or proposal.destination_domain is not None):
                    allowed, code, reason = False, DenialCode.RECIPIENT_NOT_ALLOWED_FOR_ACTION.value, "Recipient/destination is only valid for delivery actions."
                elif proposal.action_type == ActionType.SAVE and proposal.destination_domain is not None:
                    allowed, code, reason = False, DenialCode.DOMAIN_NOT_ALLOWED.value, "Destination domain is not valid for SAVE actions."
                elif proposal.action_type == ActionType.DELIVER and proposal.recipient is None:
                    allowed, code, reason = False, DenialCode.RECIPIENT_REQUIRED.value, "Delivery requires a registered recipient."
                elif proposal.action_type == ActionType.DELIVER and proposal.recipient not in self._policies.recipients:
                    allowed, code, reason = False, DenialCode.RECIPIENT_NOT_AUTHORIZED.value, "Recipient is not in the trusted recipient directory."
                elif proposal.action_type == ActionType.DELIVER and self._policies.recipients[proposal.recipient].clearance < label:
                    allowed, code, reason = False, DenialCode.RECIPIENT_CLEARANCE_TOO_LOW.value, "Recipient clearance is below the resource label."
                elif proposal.action_type == ActionType.DELIVER:
                    recipient_domain = proposal.recipient.rsplit("@", 1)[1]
                    if recipient_domain not in self._policies.allowed_domains:
                        allowed, code, reason = False, DenialCode.DOMAIN_NOT_ALLOWED.value, "Recipient domain is not allowlisted."
                    elif proposal.destination_domain and recipient_domain != proposal.destination_domain:
                        allowed, code, reason = False, DenialCode.DOMAIN_NOT_ALLOWED.value, "Destination domain does not match recipient domain."

        result = _decision(allowed, code, reason, proposal, label)
        if self.store is not None:
            audit_id = self.store.append_audit({
                "session_id": session_id, "user_id": user_id, "principal": proposal.principal,
                "action": proposal.action_type.value, "resource": proposal.target_resource,
                "recipient": proposal.recipient, "data_label": label.name if label is not None else None,
                "decision": result.status.value, "code": result.code, "rule": result.reason,
            })
            result = result.model_copy(update={"audit_id": audit_id})
        return result

    def evaluate_untrusted(self, payload: object, context: RequestContext | None = None) -> PolicyDecision:
        try:
            proposal = ToolProposal.model_validate(payload)
        except (ValidationError, TypeError, ValueError):
            result = _decision(False, DenialCode.INVALID_PROPOSAL.value, "Proposal failed validation; denied by default.")
            if self.store is not None:
                audit_id = self.store.append_audit({"session_id": context.session_id if context else None,
                    "user_id": context.user_id if context else None, "principal": None, "action": None,
                    "resource": None, "recipient": None, "data_label": None, "decision": "BLOCK",
                    "code": result.code, "rule": result.reason})
                result = result.model_copy(update={"audit_id": audit_id})
            return result
        return self.evaluate(proposal, context)

    def record_gateway_event(self, code: str, reason: str,
                             proposal: ToolProposal | None = None,
                             context: RequestContext | None = None,
                             label: SecurityLabel | None = None) -> PolicyDecision:
        """Record a gateway-level block/failure and return its final audited decision."""
        result = _decision(False, code, reason, proposal, label)
        if self.store is not None:
            audit_id = self.store.append_audit({
                "session_id": context.session_id if context else None,
                "user_id": context.user_id if context else None,
                "principal": proposal.principal if proposal else None,
                "action": proposal.action_type.value if proposal else None,
                "resource": proposal.target_resource if proposal else None,
                "recipient": proposal.recipient if proposal else None,
                "data_label": label.name if label is not None else None,
                "decision": result.status.value,
                "code": result.code,
                "rule": result.reason,
            })
            result = result.model_copy(update={"audit_id": audit_id})
        return result


def _demo() -> None:
    store = SQLiteSecurityStore("agentgate_security.db")
    store.set_session("demo-session", "admin-user")
    engine = SecurityEngine(store=store)
    context = engine.authenticator.issue_context("admin-user", "demo-session")
    examples = [
        ("Authorized confidential delivery", {"action_type": "DELIVER", "principal": "report-agent", "target_resource": "payroll-summary", "recipient": "finance@example.com", "tool_name": "email", "destination_domain": "example.com"}),
        ("Blocked low-clearance recipient", {"action_type": "DELIVER", "principal": "report-agent", "target_resource": "payroll-summary", "recipient": "public@example.com", "tool_name": "email", "destination_domain": "example.com"}),
    ]
    for name, payload in examples:
        result = engine.evaluate_untrusted(payload, context)
        print(f"{result.status.value:5} | {name} | {result.code} | audit_id={result.audit_id}")


if __name__ == "__main__":
    _demo()


class SecureToolGateway:
    """Only executes registered handlers after policy approval and actual-byte-size checks.

    The handler must not expose a bypass path to the same protected resource. This gateway
    controls calls made through it; deployment must also restrict direct tool credentials.
    """
    def __init__(self, engine: SecurityEngine,
                 handlers: Mapping[str, Callable[[ToolProposal, bytes], Any]]) -> None:
        self.engine = engine
        self._handlers = {name.casefold(): handler for name, handler in handlers.items()}

    def execute(self, untrusted_proposal: object, context: RequestContext | None,
                payload: bytes = b"") -> tuple[PolicyDecision, Any | None]:
        try:
            proposal = ToolProposal.model_validate(untrusted_proposal)
        except (ValidationError, TypeError, ValueError):
            return self.engine.evaluate_untrusted(untrusted_proposal, context), None

        if not isinstance(payload, bytes):
            decision = self.engine.record_gateway_event(
                DenialCode.INVALID_PROPOSAL.value,
                "Execution payload must be bytes; denied by default.", proposal, context)
            return decision, None

        # The declared size from an agent is never trusted; use the real bytes.
        proposal = proposal.model_copy(update={"payload_size_bytes": len(payload)})
        handler = self._handlers.get(proposal.tool_name.casefold())

        # Evaluate policy first. A missing handler must not mask a policy denial.
        decision = self.engine.evaluate(proposal, context)
        if not decision.allowed:
            return decision, None
        if handler is None:
            final_decision = self.engine.record_gateway_event(
                DenialCode.TOOL_HANDLER_NOT_REGISTERED.value,
                "No protected handler is registered for this tool; execution was blocked.",
                proposal, context, decision.data_label)
            return final_decision, None

        try:
            return decision, handler(proposal, payload)
        except Exception:
            failure = self.engine.record_gateway_event(
                DenialCode.EXECUTION_FAILED.value,
                "Protected tool execution failed; details withheld.",
                proposal, context, decision.data_label)
            return failure, None
