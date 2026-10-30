"""Server-side API-key authentication. Client-supplied user IDs/contexts are never trusted.

Set AGENTGATE_API_KEYS to JSON: {"secret-api-key": {"user_id":"alice","session_id":"sess-alice"}}.
The corresponding session must already be registered in the trusted SQLite store.
"""
from __future__ import annotations
import hmac, json, os
from fastapi import Header, HTTPException
from security_engine import RequestContext, Authenticator

class APIAuthenticator:
    def __init__(self, authenticator: Authenticator, key_map: dict[str, dict[str, str]] | None = None):
        self.authenticator = authenticator
        if key_map is None:
            try: key_map = json.loads(os.environ.get("AGENTGATE_API_KEYS", "{}"))
            except (TypeError, ValueError) as exc: raise RuntimeError("AGENTGATE_API_KEYS must be valid JSON") from exc
        if not isinstance(key_map, dict): raise RuntimeError("AGENTGATE_API_KEYS must be a JSON object")
        self.key_map = key_map

    def authenticate(self, authorization: str | None, store) -> RequestContext:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Authentication required")
        supplied = authorization[7:].strip()
        found = None
        # Compare every configured key to reduce obvious timing leakage.
        for key, identity in self.key_map.items():
            if isinstance(key, str) and hmac.compare_digest(supplied, key): found = identity
        if not isinstance(found, dict) or not isinstance(found.get("user_id"), str) or not isinstance(found.get("session_id"), str):
            raise HTTPException(status_code=401, detail="Invalid API credentials")
        user_id, session_id = found["user_id"], found["session_id"]
        if store is None or not store.session_matches(session_id, user_id, "ACTIVE"):
            raise HTTPException(status_code=401, detail="Invalid or inactive session")
        context = self.authenticator.issue_context(user_id, session_id)
        if not self.authenticator.verify(context):
            raise HTTPException(status_code=401, detail="Authentication failed")
        return context

def bearer_context(authorization: str | None = Header(default=None), *, api_auth: APIAuthenticator, store):
    return api_auth.authenticate(authorization, store)
