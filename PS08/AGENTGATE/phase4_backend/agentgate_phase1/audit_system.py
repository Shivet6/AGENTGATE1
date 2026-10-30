"""AGENTGATE Phase 4: audit querying, integrity verification, and export.

This service builds on SQLiteSecurityStore's existing HMAC-authenticated hash chain.
It never returns the configured audit key and treats audit records as immutable.
"""
from __future__ import annotations

import csv
import io
import json
from typing import Any

from security_engine import SQLiteSecurityStore


class AuditAccessError(PermissionError):
    """Raised when an authenticated caller is not on the trusted audit-reader list."""


class AuditService:
    ALLOWED_FILTERS = {"user_id", "session_id", "principal", "action", "resource", "decision", "code"}

    def __init__(self, store: SQLiteSecurityStore, audit_readers: set[str] | frozenset[str] | None = None):
        if store is None:
            raise ValueError("AuditService requires a persistent SQLiteSecurityStore")
        self.store = store
        # Deliberately fail closed unless trusted startup code configures readers.
        self.audit_readers = frozenset(audit_readers or ())

    def require_reader(self, user_id: str) -> None:
        if not user_id or user_id not in self.audit_readers:
            raise AuditAccessError("Audit access denied")

    def list_events(self, user_id: str, *, limit: int = 100, offset: int = 0,
                    filters: dict[str, str] | None = None) -> dict[str, Any]:
        self.require_reader(user_id)
        if not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        if offset < 0:
            raise ValueError("offset must be non-negative")
        filters = filters or {}
        unknown = set(filters) - self.ALLOWED_FILTERS
        if unknown:
            raise ValueError("Unsupported audit filter")
        # Filter in Python because get_audit_events returns normalized, hash-verified source fields.
        # Values are exact matches; no user-provided SQL is ever constructed.
        events = self.store.get_audit_events()
        if filters:
            events = [e for e in events if all(str(e.get(k, "")) == v for k, v in filters.items())]
        total = len(events)
        page = events[offset:offset + limit]
        return {"events": page, "limit": limit, "offset": offset, "total": total,
                "has_more": offset + len(page) < total}

    def get_event(self, user_id: str, event_id: int) -> dict[str, Any] | None:
        self.require_reader(user_id)
        if event_id < 1:
            return None
        for event in self.store.get_audit_events():
            if event.get("id") == event_id:
                return event
        return None

    def verify_integrity(self, user_id: str) -> dict[str, Any]:
        self.require_reader(user_id)
        events = self.store.get_audit_events()
        valid = self.store.verify_audit_chain()
        return {"valid": bool(valid), "events_checked": len(events),
                "first_event_id": events[0]["id"] if events else None,
                "last_event_id": events[-1]["id"] if events else None,
                "algorithm": "HMAC-SHA256 hash chain"}

    def export_json(self, user_id: str, *, limit: int = 5000, filters: dict[str, str] | None = None) -> str:
        self.require_reader(user_id)
        if not 1 <= limit <= 5000:
            raise ValueError("export limit must be between 1 and 5000")
        result = self.list_events(user_id, limit=min(limit, 500), offset=0, filters=filters)
        events = list(result["events"])
        while result["has_more"] and len(events) < limit:
            result = self.list_events(user_id, limit=min(500, limit - len(events)), offset=len(events), filters=filters)
            events.extend(result["events"])
        return json.dumps({"count": len(events), "integrity": self.store.verify_audit_chain(), "events": events},
                          sort_keys=True, indent=2, default=str)

    def export_csv(self, user_id: str, *, limit: int = 5000, filters: dict[str, str] | None = None) -> str:
        self.require_reader(user_id)
        if not 1 <= limit <= 5000:
            raise ValueError("export limit must be between 1 and 5000")
        result = self.list_events(user_id, limit=min(limit, 500), offset=0, filters=filters)
        events = list(result["events"])
        while result["has_more"] and len(events) < limit:
            result = self.list_events(user_id, limit=min(500, limit - len(events)), offset=len(events), filters=filters)
            events.extend(result["events"])
        fields = list(events[0].keys()) if events else ["id", "timestamp", "user_id", "action", "resource", "decision", "code", "previous_hash", "event_hash"]
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(events)
        return output.getvalue()
