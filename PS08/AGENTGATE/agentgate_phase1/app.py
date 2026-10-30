"""Runnable AGENTGATE API application configured from trusted environment variables."""
from __future__ import annotations

import json
import os
from pathlib import Path

from api_auth import APIAuthenticator
from file_security import FileSecurity
from gateway_api import create_app
from security_engine import Authenticator, SecurityEngine, SQLiteSecurityStore


def _required_secret(name: str) -> str:
    value = os.environ.get(name, "")
    if len(value.encode("utf-8")) < 32:
        raise RuntimeError(f"{name} must be configured with at least 32 bytes")
    return value


authenticator = Authenticator(_required_secret("AGENTGATE_AUTH_KEY"))
audit_key = _required_secret("AGENTGATE_AUDIT_KEY")

try:
    key_map = json.loads(os.environ["AGENTGATE_API_KEYS"])
except (KeyError, json.JSONDecodeError) as exc:
    raise RuntimeError("AGENTGATE_API_KEYS must be a JSON object of API credentials") from exc
if not isinstance(key_map, dict) or not key_map:
    raise RuntimeError("AGENTGATE_API_KEYS must contain at least one API credential")

identities: dict[str, str] = {}
for api_key, identity in key_map.items():
    if not isinstance(api_key, str) or len(api_key.encode("utf-8")) < 32:
        raise RuntimeError("Each configured API key must be at least 32 bytes")
    if not isinstance(identity, dict):
        raise RuntimeError("Each API key must map to a user_id and session_id")
    user_id, session_id = identity.get("user_id"), identity.get("session_id")
    if not isinstance(user_id, str) or not isinstance(session_id, str):
        raise RuntimeError("Each API key must map to a user_id and session_id")
    authenticator.issue_context(user_id, session_id)
    if session_id in identities and identities[session_id] != user_id:
        raise RuntimeError("A session_id cannot be mapped to multiple users")
    identities[session_id] = user_id

audit_readers = {
    user_id.strip()
    for user_id in os.environ.get("AGENTGATE_AUDIT_READERS", "").split(",")
    if user_id.strip()
}
if not audit_readers:
    raise RuntimeError("AGENTGATE_AUDIT_READERS must list at least one trusted audit reader")
if not audit_readers.issubset(set(identities.values())):
    raise RuntimeError("Every audit reader must be mapped by AGENTGATE_API_KEYS")

database_path = Path(os.environ.get("AGENTGATE_DB_PATH", "agentgate_security.db"))
database_path.parent.mkdir(parents=True, exist_ok=True)
store = SQLiteSecurityStore(database_path, audit_key=audit_key)
for session_id, user_id in identities.items():
    store.set_session(session_id, user_id)

engine = SecurityEngine(store=store, authenticator=authenticator)
files = None
if os.name == "posix":
    files = FileSecurity(
        engine,
        Path(os.environ.get("AGENTGATE_FILE_ROOT", "protected_files")),
        allowed_extensions={"txt", "md", "json"},
    )

app = create_app(
    engine,
    files,
    APIAuthenticator(authenticator, key_map),
    audit_readers=audit_readers,
)


@app.on_event("shutdown")
def close_resources() -> None:
    if files is not None:
        files.close()
    store.close()
