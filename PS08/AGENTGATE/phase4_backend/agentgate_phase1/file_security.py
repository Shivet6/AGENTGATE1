"""AGENTGATE file security: policy-gated, root-confined file access.

Security assumptions: the root and its parent directories are provisioned by a trusted
administrator. POSIX systems use directory file descriptors and O_NOFOLLOW to reduce
path-swap races. Other platforms use conservative path checks but need OS ACLs for
hostile concurrent writers. A trusted resource-to-path binding must be registered before
an artifact can be accessed.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import os
from pathlib import Path, PurePosixPath
import secrets
import stat
from typing import Iterable

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from security_engine import ActionType, PolicyDecision, RequestContext, SecurityEngine, SecurityLabel, ToolProposal


class FileSecurityError(RuntimeError):
    """Safe, user-facing file-security failure."""


class FileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)
    principal: str = Field(min_length=1, max_length=64)
    resource_id: str = Field(min_length=1, max_length=128)
    path: str = Field(min_length=1, max_length=1024)
    max_bytes: int = Field(default=5_000_000, ge=1, le=50_000_000)

    @field_validator("path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        value = value.replace("\\", "/")
        parts = value.split("/")
        if (not value or value.startswith("/") or "\x00" in value or
                any(part in ("", ".", "..") for part in parts) or
                (parts and ":" in parts[0]) or PurePosixPath(value).is_absolute()):
            raise ValueError("path must be a clean relative path inside the configured root")
        return value


@dataclass(frozen=True, slots=True)
class FileResult:
    decision: PolicyDecision
    path: str
    size_bytes: int
    sha256: str
    label: SecurityLabel
    content: bytes | None = None


class FileSecurity:
    def __init__(self, engine: SecurityEngine, root: str | Path,
                 max_file_bytes: int = 5_000_000,
                 allowed_extensions: Iterable[str] | None = None) -> None:
        if not 1 <= max_file_bytes <= 50_000_000:
            raise ValueError("max_file_bytes must be between 1 and 50,000,000")
        self.engine = engine
        raw_root = Path(root).expanduser()
        # Check the configured final component before resolve() erases symlink identity.
        if raw_root.is_symlink():
            raise ValueError("file-security root cannot be a symbolic link")
        raw_root.mkdir(parents=True, exist_ok=True)
        if raw_root.is_symlink() or not raw_root.is_dir():
            raise ValueError("file-security root must be a real directory")
        self.root = raw_root.resolve(strict=True)
        self.max_file_bytes = max_file_bytes
        self.allowed_extensions = None if allowed_extensions is None else frozenset(
            (ext if ext.startswith(".") else "." + ext).casefold() for ext in allowed_extensions
        )
        self._root_fd: int | None = None
        if os.name == "posix" and hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd:
            self._root_fd = os.open(self.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW)
            if not stat.S_ISDIR(os.fstat(self._root_fd).st_mode):
                os.close(self._root_fd)
                self._root_fd = None
                raise ValueError("file-security root must be a real directory")
        else:
            raise RuntimeError("This platform lacks required directory-handle protections; FileSecurity fails closed")

    def close(self) -> None:
        if self._root_fd is not None:
            os.close(self._root_fd)
            self._root_fd = None

    def _validated_request(self, request: FileRequest | dict) -> FileRequest:
        try:
            return request if isinstance(request, FileRequest) else FileRequest.model_validate(request)
        except (ValidationError, TypeError, ValueError) as exc:
            raise FileSecurityError("Invalid file request") from exc

    def _check_extension(self, relative: str) -> None:
        if self.allowed_extensions is not None and Path(relative).suffix.casefold() not in self.allowed_extensions:
            raise FileSecurityError("File extension is not allowed")

    def _check_binding(self, req: FileRequest) -> None:
        # Fail closed: file identity is registered through a trusted setup/admin call.
        store = self.engine.store
        if store is None:
            raise FileSecurityError("Trusted file-resource mapping requires the security store")
        mapped = store.get_file_resource_path(req.resource_id)
        if mapped is None:
            raise FileSecurityError("File resource is not registered")
        if mapped != req.path:
            raise FileSecurityError("Requested path does not match the registered resource")

    def _audit_operation(self, req: FileRequest, action: str, outcome: str, code: str,
                         context: RequestContext | None, label: SecurityLabel | None = None) -> None:
        store = self.engine.store
        if store is None:
            return
        store.append_audit({
            "session_id": context.session_id if context else None,
            "user_id": context.user_id if context else None,
            "principal": req.principal, "action": action, "resource": req.resource_id,
            "recipient": None, "data_label": label.name if label is not None else None,
            "decision": outcome, "code": code, "rule": "File-operation outcome; distinct from policy authorization.",
        })

    def _authorize(self, action: ActionType, req: FileRequest, context: RequestContext | None,
                   size: int = 0) -> PolicyDecision:
        proposal = ToolProposal(action_type=action, principal=req.principal,
            target_resource=req.resource_id, tool_name="document", payload_size_bytes=size)
        return self.engine.evaluate(proposal, context)

    def _open_parent_fd(self, relative: str) -> tuple[int, str]:
        parts = PurePosixPath(relative).parts
        if not parts:
            raise FileSecurityError("Invalid file path")
        if self._root_fd is None:
            raise FileSecurityError("Secure directory-handle operations are unavailable on this platform; use OS ACL isolation")
        fd = os.dup(self._root_fd)
        try:
            for part in parts[:-1]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            return fd, parts[-1]
        except FileNotFoundError as exc:
            os.close(fd)
            raise FileSecurityError("Parent directory or file does not exist") from exc
        except OSError as exc:
            os.close(fd)
            raise FileSecurityError("Unsafe path component or inaccessible directory") from exc

    def read(self, request: FileRequest | dict, context: RequestContext | None) -> FileResult:
        req = self._validated_request(request)
        try:
            self._check_binding(req)
            self._check_extension(req.path)
            decision = self._authorize(ActionType.READ, req, context)
            if not decision.allowed:
                self._audit_operation(req, "READ", "BLOCK", "FILE_READ_BLOCKED_BY_POLICY", context)
                raise FileSecurityError(f"File read blocked: {decision.code}")
            limit = min(req.max_bytes, self.max_file_bytes)
            if self._root_fd is not None:
                parent_fd, leaf = self._open_parent_fd(req.path)
                try:
                    fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
                    with os.fdopen(fd, "rb") as stream:
                        info = os.fstat(stream.fileno())
                        if not stat.S_ISREG(info.st_mode):
                            raise FileSecurityError("Target must be a regular file")
                        if info.st_size > limit:
                            raise FileSecurityError("File exceeds the configured size limit")
                        content = stream.read(limit + 1)
                finally:
                    os.close(parent_fd)
            else:
                path = self._safe_fallback_path(req.path)
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(path, flags)
                with os.fdopen(fd, "rb") as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                        raise FileSecurityError("File is not regular or exceeds the configured size limit")
                    content = stream.read(limit + 1)
            if len(content) > limit:
                raise FileSecurityError("File exceeds the configured size limit")
            label = decision.data_label or SecurityLabel.INTERNAL
            self._audit_operation(req, "READ", "ALLOW", "FILE_READ_SUCCEEDED", context, label)
            return FileResult(decision, req.path, len(content), hashlib.sha256(content).hexdigest(), label, content)
        except FileSecurityError as exc:
            # Avoid duplicate blocked events for the explicit policy branch above.
            if "blocked:" not in str(exc):
                self._audit_operation(req, "READ", "BLOCK", "FILE_READ_BLOCKED", context)
            raise
        except OSError as exc:
            self._audit_operation(req, "READ", "BLOCK", "FILE_READ_FAILED", context)
            raise FileSecurityError("Unable to safely read file") from exc
        except Exception as exc:
            self._audit_operation(req, "READ", "BLOCK", "FILE_READ_FAILED", context)
            raise FileSecurityError("File read failed safely") from exc

    def write(self, request: FileRequest | dict, content: bytes, context: RequestContext | None,
              *, parent_artifact_ids: list[str] | None = None,
              declared_label: SecurityLabel | None = None) -> FileResult:
        req = self._validated_request(request)
        label: SecurityLabel | None = None
        try:
            self._check_binding(req)
            self._check_extension(req.path)
            if not isinstance(content, bytes):
                raise FileSecurityError("File content must be bytes")
            limit = min(req.max_bytes, self.max_file_bytes)
            if len(content) > limit:
                raise FileSecurityError("Content exceeds the configured size limit")
            decision = self._authorize(ActionType.SAVE, req, context, len(content))
            if not decision.allowed:
                raise FileSecurityError(f"File write blocked: {decision.code}")
            label = decision.data_label or SecurityLabel.INTERNAL
            if self.engine.store is not None and parent_artifact_ids:
                label = max(label, self.engine.store.inherit_label(req.resource_id, parent_artifact_ids, declared_label))
            elif declared_label is not None:
                label = max(label, declared_label)
            # Stage in the same trusted parent directory; no path-string replacement races on POSIX.
            temp_leaf = ".agentgate-" + secrets.token_hex(16) + ".tmp"
            if self._root_fd is not None:
                parent_fd, leaf = self._open_parent_fd(req.path)
                try:
                    try:
                        existing = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                        if not stat.S_ISREG(existing.st_mode):
                            raise FileSecurityError("Target must be a regular file")
                    except FileNotFoundError:
                        pass
                    temp_fd = os.open(temp_leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
                    with os.fdopen(temp_fd, "wb") as stream:
                        stream.write(content); stream.flush(); os.fsync(stream.fileno())
                    # Persist classification before making new content visible. If this fails, no replace occurs.
                    if self.engine.store is not None:
                        self.engine.store.set_artifact_label(req.resource_id, label)
                    os.replace(temp_leaf, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                    try: os.fsync(parent_fd)
                    except OSError: pass
                finally:
                    try: os.unlink(temp_leaf, dir_fd=parent_fd)
                    except OSError: pass
                    os.close(parent_fd)
            else:
                target = self._safe_fallback_path(req.path)
                if target.exists() and (target.is_symlink() or not target.is_file()):
                    raise FileSecurityError("Target must be a regular file")
                temp_path = target.parent / temp_leaf
                fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(content); stream.flush(); os.fsync(stream.fileno())
                    if self.engine.store is not None:
                        self.engine.store.set_artifact_label(req.resource_id, label)
                    os.replace(temp_path, target)
                finally:
                    try: temp_path.unlink(missing_ok=True)
                    except OSError: pass
            self._audit_operation(req, "SAVE", "ALLOW", "FILE_WRITE_SUCCEEDED", context, label)
            return FileResult(decision, req.path, len(content), hashlib.sha256(content).hexdigest(), label)
        except FileSecurityError as exc:
            self._audit_operation(req, "SAVE", "BLOCK", "FILE_WRITE_BLOCKED", context, label)
            raise
        except OSError as exc:
            self._audit_operation(req, "SAVE", "BLOCK", "FILE_WRITE_FAILED", context, label)
            raise FileSecurityError("Unable to safely write file") from exc
        except Exception as exc:
            self._audit_operation(req, "SAVE", "BLOCK", "FILE_WRITE_FAILED", context, label)
            raise FileSecurityError("File write failed safely") from exc

    def _safe_fallback_path(self, relative: str) -> Path:
        # Fallback for non-POSIX platforms; OS ACLs must prevent hostile concurrent mutation.
        candidate = self.root.joinpath(*PurePosixPath(relative).parts)
        current = self.root
        for part in PurePosixPath(relative).parts:
            current = current / part
            if current.is_symlink():
                raise FileSecurityError("Symbolic links are not allowed")
        try:
            candidate.parent.resolve(strict=True).relative_to(self.root)
        except (ValueError, FileNotFoundError, OSError) as exc:
            raise FileSecurityError("Path escapes the configured root") from exc
        return candidate

    @staticmethod
    def verify_sha256(content: bytes, expected_hex: str) -> bool:
        if not isinstance(content, bytes) or not isinstance(expected_hex, str):
            return False
        return hmac.compare_digest(hashlib.sha256(content).hexdigest(), expected_hex.casefold())
