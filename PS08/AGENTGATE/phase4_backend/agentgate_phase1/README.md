# AGENTGATE — Integrated Security Engine + File Security

This package combines the supplied Phase 1 `security_engine.py` with the File Security module (`file_security.py`) and both test suites.

## Requirements

- Python 3.10+
- Pydantic 2.x

Install and test:

```bash
python -m pip install -r requirements.txt
python -m unittest discover -v
```

## Modules

- `security_engine.py`: deterministic policy decisions, signed request context, trusted policy store, IFC labels/provenance, SQLite persistence, HMAC audit chain, and secure tool gateway.
- `file_security.py`: policy-gated local file reads/writes, relative-path validation, size/extension limits, symlink checks, SHA-256 reporting, and label inheritance through the existing engine/store.
- `test_security_engine.py`: Phase 1 engine tests.
- `test_file_security.py`: File Security integration tests.

## Integration design

`FileSecurity` accepts an existing `SecurityEngine` instance. It does not create a second policy database or independent permission system. Each read uses the engine's `READ` action; each write uses `SAVE`. Requests must use resource IDs already defined in the trusted engine policy and a valid signed `RequestContext`.

Example outline:

```python
from pathlib import Path
from security_engine import Authenticator, SecurityEngine, SQLiteSecurityStore
from file_security import FileSecurity

auth = Authenticator("load-a-long-secret-from-your-secret-manager")
store = SQLiteSecurityStore("agentgate.db", audit_key="load-a-separate-audit-secret")
# Configure trusted principals, resources, users, and permissions in the policy
# configuration in security_engine.py. Register sessions before issuing context.
engine = SecurityEngine(store=store, authenticator=auth)
store.set_session("your-session-id", "your-user-id")
context = auth.issue_context("your-user-id", "your-session-id")
files = FileSecurity(engine, Path("./protected_files"), max_file_bytes=5_000_000,
                     allowed_extensions={"txt", "md", "json"})

# IMPORTANT: resource/path bindings are trusted setup, not caller input.
store.register_file_resource("your-resource", "report.txt")
# result = files.read({"principal": "your-principal", "resource_id": "your-resource",
#                      "path": "report.txt"}, context)
# result.content contains the bytes; result.sha256 is the content digest.
```

Do not copy the example secrets into production. Load authentication and audit keys from a secret manager or environment configuration, and keep them separate from the SQLite database. Do not give agents direct filesystem access or alternate credentials that bypass this module.

## Security notes

- File paths are relative to the configured root. Only use a dedicated directory with restrictive OS permissions.
- Every file resource must be pre-registered using `store.register_file_resource(resource_id, relative_path)` during trusted setup. A caller cannot bind an allowed resource ID to an arbitrary path; existing bindings cannot be silently changed.
- On supported POSIX platforms, operations use a retained root directory descriptor, handle-relative component traversal, and no-follow flags. On platforms without these primitives, operations fail closed rather than silently using a race-prone fallback.
- Final file outcomes (`FILE_READ_SUCCEEDED`, `FILE_WRITE_SUCCEEDED`, and blocked/failed events) are recorded separately from the policy engine's authorization decision.
- Classification metadata is persisted before new file content is made visible. Since SQLite and filesystem replacement are not one atomic transaction, a crash can leave metadata for a file that was not ultimately replaced; recovery/reconciliation is still required for high-assurance deployments.
- SHA-256 identifies content; it does not establish authenticity unless compared with a trusted expected digest.
- This integration does not by itself eliminate all filesystem race conditions on every OS. Do not allow untrusted processes to modify the protected directory. For hostile multi-user environments, use directory-handle-based operations and platform-specific no-follow protections.
- Human-in-the-loop review queue logic is not included in this package.
- Tests provide regression coverage, not a proof of security.


## Phase 3 — REST Gateway API

`gateway_api.py` exposes the existing engine and file-security layer through FastAPI. It does not replace either security layer.

### Endpoints

- `GET /health` — non-sensitive liveness check.
- `POST /v1/authorize` — policy evaluation only; it does not execute a tool.
- `POST /v1/files/read` — authenticated, policy-gated read through `FileSecurity`.
- `POST /v1/files/write` — authenticated, policy-gated write through `FileSecurity`.
- `GET /v1/audit/{event_id}` — separately policy-gated audit lookup.
- `GET /v1/resources/{resource_id}` — policy-gated resource metadata lookup.

### Configure and run

Use strong, distinct secrets supplied through your deployment secret manager. The API key map is server-side configuration and must never be sent to clients:

```bash
export AGENTGATE_AUTH_KEY='replace-with-a-random-secret-at-least-32-bytes'
export AGENTGATE_API_KEYS='{"replace-with-client-api-key":{"user_id":"admin-user","session_id":"session-1"}}'
```

Provision the SQLite session in trusted startup/admin code before accepting requests. Construct `Authenticator`, `SQLiteSecurityStore`, `SecurityEngine`, and `FileSecurity`, then create the app with `create_app(engine, files)`. Example `app.py`:

```python
import os
from pathlib import Path
from security_engine import Authenticator, SecurityEngine, SQLiteSecurityStore
from file_security import FileSecurity
from gateway_api import create_app

auth = Authenticator(os.environ["AGENTGATE_AUTH_KEY"])
store = SQLiteSecurityStore("agentgate.db", audit_key=os.environ["AGENTGATE_AUDIT_KEY"])
# Trusted provisioning, not an API request:
# store.set_session("session-1", "admin-user")
engine = SecurityEngine(store=store, authenticator=auth)
files = FileSecurity(engine, Path("./protected_files"), allowed_extensions={"txt", "md", "json"})
app = create_app(engine, files)
```

Run with `uvicorn app:app --host 127.0.0.1 --port 8000`. Use TLS at the deployment edge; do not expose API keys in URLs or logs. The sample uses a static API-key-to-user/session map; production should use managed identity, rotation/revocation, rate limiting, and secret management. API key holders can act as the mapped user, so treat keys as credentials.

### Request examples

```http
POST /v1/authorize
Authorization: Bearer <configured-api-key>
Content-Type: application/json

{"action_type":"READ","principal":"report-agent","resource_id":"public-guide"}
```

File operations require trusted resource-to-path bindings registered by administrative code with `store.register_file_resource(resource_id, relative_path)`. The path is checked against that binding; never allow callers to register bindings.

### Phase 3 boundaries

- Client JSON cannot supply a trusted `RequestContext`, user identity, role, clearance, or decision.
- File content is only read/written through `FileSecurity`.
- Error responses avoid stack traces and internal exception details; server logs should be access-controlled.
- The audit/resource endpoints use the current engine policy model and are intentionally restrictive. Review principal/resource policy configuration before enabling them in production.
- This is a foundational API layer, not a production deployment certification. Add rate limiting, TLS, CORS policy if a browser client is used, API-key rotation/revocation, monitoring, and deployment-specific hardening.


## Phase 3 security hardening (repair update)

The gateway now includes:

- A per-Bearer-credential in-process sliding-window rate limit (`429`); configure `AGENTGATE_RATE_LIMIT_REQUESTS` or pass `rate_limit_requests` to `create_app`.
- A request-body cap with `413` responses; configure `max_request_body_bytes` in `create_app`. Also set the same or a lower cap at your reverse proxy.
- Optional explicit resource ownership checks for BOLA prevention. Pass a trusted mapping such as `resource_owners={"alice-private": "alice"}` to `create_app`; do not build this mapping from client requests.
- Validation rejecting common SQLi/XSS-like strings in identifiers and file paths.
- File-backend timeout/connection/OS failure mapping to `503` and a small circuit breaker that opens after consecutive failures. Tune `circuit_breaker_threshold` and `circuit_breaker_reset_seconds`.
- Regression tests for missing/forged credentials, BOLA, rate limiting, body limits, traversal, SQLi/XSS-like payloads, and circuit-breaker behavior.

Important operational limits: the rate limiter and circuit breaker are process-local, so they do not coordinate across multiple workers/instances. Use a shared limiter and edge-level body limits in production. Resource ownership is only enforced for resources present in the trusted `resource_owners` map; provide complete ownership data for every user-owned resource. The circuit breaker wraps local file-operation failures and is not a distributed backend-health monitor. These tests are regression checks, not a security certification.

## Phase 4 — Integrated Audit System (WORM archive excluded)

Phase 4 is integrated into the same project and database as Phases 1–3. The policy engine writes every evaluated decision to a durable SQLite queue; a background worker appends events to the HMAC-SHA256 hash chain. Required audit fields are normalized for malformed requests, and SQLite triggers reject ordinary UPDATE/DELETE statements against `audit_events`. Audit reads flush the durable queue before returning results.

### Audit endpoints

- `GET /v1/audit?limit=100&offset=0` — list audit events; supports exact-match filters `user_id`, `session_id`, `principal`, `action`, `resource`, `decision`, and `code`.
- `GET /v1/audit/verify` — verify the local HMAC hash chain.
- `GET /v1/audit/export?format=json&limit=5000` — export JSON.
- `GET /v1/audit/export?format=csv&limit=5000` — export CSV.
- `GET /v1/audit/{event_id}` — retrieve one event.

Audit endpoints fail closed unless trusted startup code passes an allowlist, for example `create_app(engine, files, api_auth, audit_readers={"admin-user"})`. The allowlist must come from trusted configuration, not a request. The API key must map to a user ID in that allowlist.

### Audit key and queue operations

Set a stable, separate audit key before starting the application:

```bash
export AGENTGATE_AUDIT_KEY='use-a-random-secret-at-least-32-bytes-from-a-secret-manager'
```

Do not rotate or replace this key without a documented key-rotation/migration procedure; changing it makes existing chain verification fail. Keep the key outside the database and backups that contain the database. The queue is durable in SQLite and is recovered on startup; call `store.flush_audit_queue()` in controlled maintenance/tests to wait until pending events have been appended. Close the store cleanly during shutdown with `store.close()`.

### Scope and limitations

- This unified ZIP includes Phase 4 audit query/verify/export endpoints, durable asynchronous local audit writes, required-field validation, SQLite append-only triggers, and tests.
- **The external WORM archive (`worm_archive.py`) is intentionally excluded**, as requested. No AWS account or AWS configuration is required for this package.
- SQLite triggers and a local HMAC chain do not provide true external WORM guarantees against an administrator who can replace the database or remove triggers. External immutable storage is not enabled in this build.
- The background queue reduces synchronous hash-chain work, but enqueuing the audit event still commits to the same local SQLite database. Benchmark in your own deployment before making latency claims.
- The tests are regression checks, not a security certification.
