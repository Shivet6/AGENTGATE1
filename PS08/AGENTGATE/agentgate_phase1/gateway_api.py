"""AGENTGATE Phase 3: FastAPI REST gateway over the existing security engine and file layer.

Create the application with create_app(engine, files, api_auth). No protected action is
executed without server-side API-key authentication and a valid signed request context.
"""
from __future__ import annotations
import logging
import json
import os
import time
import threading
from collections import deque
from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from pydantic import ValidationError
from api_auth import APIAuthenticator
from api_schemas import AuthorizeRequest, FileReadRequest, FileWriteRequest
from audit_system import AuditAccessError, AuditService
from file_security import FileRequest, FileSecurity, FileSecurityError
from security_engine import ActionType, SecurityEngine, SecurityLabel, ToolProposal, RequestContext

log = logging.getLogger("agentgate.gateway_api")


def _decision_dict(d):
    return {"allowed": d.allowed, "status": d.status.value, "code": d.code, "reason": d.reason,
            "action_type": d.action_type.value if d.action_type else None,
            "principal": d.principal, "resource_id": d.target_resource,
            "data_label": d.data_label.name if d.data_label is not None else None,
            "audit_id": d.audit_id}


class _GatewayLimitsMiddleware(BaseHTTPMiddleware):
    """Small in-process per-credential rate limiter and hard request-body cap.

    For multi-worker/production deployments, replace the in-memory limiter with a shared
    store (e.g. Redis) and enforce an equivalent cap at the reverse proxy too.
    """
    def __init__(self, app, max_requests: int, window_seconds: int, max_body_bytes: int):
        super().__init__(app)
        self.max_requests = max(1, max_requests)
        self.window_seconds = max(1, window_seconds)
        self.max_body_bytes = max(1024, max_body_bytes)
        self.hits = {}
        self.lock = threading.Lock()

    async def dispatch(self, request: Request, call_next):
        raw_len = request.headers.get("content-length")
        if raw_len:
            try:
                if int(raw_len) > self.max_body_bytes:
                    return JSONResponse(status_code=413, content={"detail": "Request body too large"})
            except ValueError:
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
        # Buffer body for replay through BaseHTTPMiddleware; Content-Length is checked first.
        body = await request.body()
        if len(body) > self.max_body_bytes:
            return JSONResponse(status_code=413, content={"detail": "Request body too large"})
        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}
        request._receive = receive
        if request.url.path != "/health":
            auth = request.headers.get("authorization", "")
            key = auth if auth else (request.client.host if request.client else "unknown")
            now = time.monotonic()
            with self.lock:
                bucket = self.hits.setdefault(key, deque())
                while bucket and now - bucket[0] >= self.window_seconds:
                    bucket.popleft()
                if len(bucket) >= self.max_requests:
                    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"}, headers={"Retry-After": str(self.window_seconds)})
                bucket.append(now)
        return await call_next(request)


def create_app(engine: SecurityEngine, files: FileSecurity | None, api_auth: APIAuthenticator | None = None,
               *, resource_owners: dict[str, str] | None = None, audit_readers: set[str] | None = None,
               rate_limit_requests: int | None = None, rate_limit_window_seconds: int = 60,
               max_request_body_bytes: int = 5_000_000, circuit_breaker_threshold: int = 3,
               circuit_breaker_reset_seconds: int = 30) -> FastAPI:
    if engine.store is None:
        raise ValueError("Gateway API requires a persistent security store")
    api_auth = api_auth or APIAuthenticator(engine.authenticator)
    app = FastAPI(title="AGENTGATE Security Gateway", version="3.0.0",
                  description="REST gateway for policy evaluation and protected file operations")
    app.state.security_engine, app.state.file_security, app.state.api_auth = engine, files, api_auth
    app.state.resource_owners = dict(resource_owners or {})
    app.state.audit_service = AuditService(engine.store, audit_readers=audit_readers)
    app.state.backend_failures = 0
    app.state.backend_open_until = 0.0
    app.state.backend_lock = threading.Lock()
    limit = rate_limit_requests if rate_limit_requests is not None else int(os.getenv("AGENTGATE_RATE_LIMIT_REQUESTS", "120"))
    app.add_middleware(_GatewayLimitsMiddleware, max_requests=limit,
                       window_seconds=rate_limit_window_seconds, max_body_bytes=max_request_body_bytes)
    # Dashboard development origins are allowed by default. Set AGENTGATE_CORS_ORIGINS
    # to a comma-separated allowlist for deployment; do not use "*" with authenticated APIs.
    cors_origins = [origin.strip() for origin in os.getenv(
        "AGENTGATE_CORS_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173"
    ).split(",") if origin.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
        max_age=600,
    )

    def check_resource_owner(resource_id: str, context: RequestContext):
        owner = app.state.resource_owners.get(resource_id)
        if owner is not None and owner != context.user_id:
            raise HTTPException(status_code=403, detail="Resource access denied")

    def check_backend():
        with app.state.backend_lock:
            if time.monotonic() < app.state.backend_open_until:
                raise HTTPException(status_code=503, detail="Security backend temporarily unavailable")

    def backend_success():
        with app.state.backend_lock:
            app.state.backend_failures = 0
            app.state.backend_open_until = 0.0

    def backend_failure():
        with app.state.backend_lock:
            app.state.backend_failures += 1
            if app.state.backend_failures >= max(1, circuit_breaker_threshold):
                app.state.backend_open_until = time.monotonic() + max(1, circuit_breaker_reset_seconds)

    def get_context(authorization: str | None = Header(default=None)) -> RequestContext:
        return api_auth.authenticate(authorization, engine.store)

    @app.get("/health", tags=["system"])
    def health():
        return {"status": "ok", "service": "agentgate-gateway", "version": "3.0.0"}

    @app.post("/v1/authorize", tags=["policy"])
    def authorize(payload: AuthorizeRequest, context: RequestContext = Depends(get_context)):
        try:
            action = ActionType(payload.action_type.upper())
            proposal = ToolProposal(action_type=action, principal=payload.principal,
                target_resource=payload.resource_id, recipient=payload.recipient,
                tool_name=payload.tool_name, payload_size_bytes=payload.payload_size_bytes,
                destination_domain=payload.destination_domain)
            decision = engine.evaluate(proposal, context)
            return _decision_dict(decision)
        except (ValueError, ValidationError):
            raise HTTPException(status_code=422, detail="Invalid authorization request")

    @app.post("/v1/files/read", tags=["files"])
    def read_file(payload: FileReadRequest, context: RequestContext = Depends(get_context)):
        if files is None:
            raise HTTPException(status_code=503, detail="File operations are unavailable on this platform")
        check_resource_owner(payload.resource_id, context)
        check_backend()
        try:
            result = files.read(FileRequest(principal=payload.principal, resource_id=payload.resource_id,
                path=payload.path, max_bytes=payload.max_bytes), context)
            try: content = result.content.decode("utf-8") if result.content is not None else None
            except UnicodeDecodeError: content = None
            backend_success()
            return {"path": result.path, "size_bytes": result.size_bytes, "sha256": result.sha256,
                    "label": result.label.name, "content": content,
                    "content_encoding": "utf-8" if content is not None else None}
        except FileSecurityError as exc:
            msg = str(exc)
            if "Invalid file request" in msg or "path" in msg.casefold() and ("unsafe" in msg.casefold() or "invalid" in msg.casefold()):
                raise HTTPException(status_code=400, detail="Invalid file request")
            raise HTTPException(status_code=403, detail="File operation denied")
        except (TimeoutError, ConnectionError, OSError) as exc:
            backend_failure()
            raise HTTPException(status_code=503, detail="Security backend temporarily unavailable")
        except (ValidationError, ValueError):
            raise HTTPException(status_code=400, detail="Invalid file request")

    @app.post("/v1/files/write", tags=["files"])
    def write_file(payload: FileWriteRequest, context: RequestContext = Depends(get_context)):
        if files is None:
            raise HTTPException(status_code=503, detail="File operations are unavailable on this platform")
        check_resource_owner(payload.resource_id, context)
        check_backend()
        try:
            try: raw = payload.content.encode(payload.encoding)
            except (LookupError, UnicodeEncodeError): raise HTTPException(status_code=422, detail="Unsupported content encoding")
            label = None
            if payload.declared_label is not None:
                try: label = SecurityLabel[payload.declared_label.upper()]
                except KeyError: raise HTTPException(status_code=422, detail="Invalid classification label")
            result = files.write(FileRequest(principal=payload.principal, resource_id=payload.resource_id,
                path=payload.path, max_bytes=payload.max_bytes), raw, context,
                parent_artifact_ids=payload.parent_artifact_ids, declared_label=label)
            backend_success()
            return {"path": result.path, "size_bytes": result.size_bytes, "sha256": result.sha256,
                    "label": result.label.name, "content": None}
        except FileSecurityError as exc:
            msg = str(exc)
            if "Invalid file request" in msg or "path" in msg.casefold() and ("unsafe" in msg.casefold() or "invalid" in msg.casefold()):
                raise HTTPException(status_code=400, detail="Invalid file request")
            raise HTTPException(status_code=403, detail="File operation denied")
        except (TimeoutError, ConnectionError, OSError):
            backend_failure()
            raise HTTPException(status_code=503, detail="Security backend temporarily unavailable")
        except (ValidationError, ValueError):
            raise HTTPException(status_code=400, detail="Invalid file request")

    def require_audit_reader(context: RequestContext):
        try:
            app.state.audit_service.require_reader(context.user_id)
        except AuditAccessError:
            raise HTTPException(status_code=403, detail="Audit access denied")

    @app.get("/v1/audit", tags=["audit"])
    def audit_list(limit: int = 100, offset: int = 0, user_id: str | None = None,
                   session_id: str | None = None, principal: str | None = None,
                   action: str | None = None, resource: str | None = None,
                   decision: str | None = None, code: str | None = None,
                   context: RequestContext = Depends(get_context)):
        require_audit_reader(context)
        filters = {k: v for k, v in {"user_id": user_id, "session_id": session_id, "principal": principal,
                    "action": action, "resource": resource, "decision": decision, "code": code}.items() if v is not None}
        try:
            return app.state.audit_service.list_events(context.user_id, limit=limit, offset=offset, filters=filters)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/v1/audit/verify", tags=["audit"])
    def audit_verify(context: RequestContext = Depends(get_context)):
        require_audit_reader(context)
        return app.state.audit_service.verify_integrity(context.user_id)

    @app.get("/v1/audit/export", tags=["audit"])
    def audit_export(format: str = "json", limit: int = 5000, context: RequestContext = Depends(get_context)):
        require_audit_reader(context)
        try:
            if format.casefold() == "json":
                return JSONResponse(content=json.loads(app.state.audit_service.export_json(context.user_id, limit=limit)))
            if format.casefold() == "csv":
                return Response(content=app.state.audit_service.export_csv(context.user_id, limit=limit),
                                media_type="text/csv", headers={"Content-Disposition": "attachment; filename=agentgate-audit.csv"})
            raise HTTPException(status_code=400, detail="format must be json or csv")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/v1/audit/{event_id}", tags=["audit"])
    def audit_event(event_id: int, context: RequestContext = Depends(get_context)):
        try:
            event = app.state.audit_service.get_event(context.user_id, event_id)
        except AuditAccessError:
            raise HTTPException(status_code=403, detail="Audit access denied")
        if event is None:
            raise HTTPException(status_code=404, detail="Audit event not found")
        return event

    @app.get("/v1/resources/{resource_id}", tags=["resources"])
    def resource_metadata(resource_id: str, context: RequestContext = Depends(get_context)):
        # Do not reveal resource existence/labels until engine authorization allows it.
        check_resource_owner(resource_id, context)
        decision = engine.evaluate(ToolProposal(action_type=ActionType.READ, principal="report-agent",
            target_resource=resource_id, tool_name="resource"), context)
        if not decision.allowed:
            raise HTTPException(status_code=403, detail="Resource access denied")
        label = engine.store.get_artifact_label(resource_id)
        return {"resource_id": resource_id, "label": label.name if label is not None else (decision.data_label.name if decision.data_label else None)}

    @app.exception_handler(Exception)
    async def safe_unhandled_error(request, exc):
        log.exception("Unhandled gateway error")
        return JSONResponse(status_code=500, content={"detail": "Internal gateway error"})

    return app
