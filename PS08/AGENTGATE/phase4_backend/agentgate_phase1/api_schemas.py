"""Pydantic request/response schemas for the AGENTGATE Phase 3 REST gateway."""
import re
from pydantic import BaseModel, ConfigDict, Field, field_validator

def _safe_identifier(value: str) -> str:
    value = value.strip()
    if not value or any(ord(ch) < 32 for ch in value):
        raise ValueError("Invalid input")
    lowered = value.casefold()
    suspicious = ("<script", "javascript:", "onerror=", "onload=", "union select", " or 1=1", "--", ";drop ", "<iframe")
    if any(token in lowered for token in suspicious):
        raise ValueError("Invalid input")
    return value

class AuthorizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action_type: str
    principal: str = Field(min_length=1, max_length=64)
    resource_id: str = Field(min_length=1, max_length=128)
    recipient: str | None = None
    tool_name: str = "resource"
    payload_size_bytes: int = Field(default=0, ge=0)
    destination_domain: str | None = None

    @field_validator("principal", "resource_id", "tool_name")
    @classmethod
    def validate_identifiers(cls, value):
        return _safe_identifier(value)

class FileReadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    principal: str = Field(min_length=1, max_length=64)
    resource_id: str = Field(min_length=1, max_length=128)
    path: str = Field(min_length=1, max_length=1024)
    max_bytes: int = Field(default=5_000_000, ge=1, le=50_000_000)

    @field_validator("principal", "resource_id")
    @classmethod
    def validate_identifiers(cls, value):
        return _safe_identifier(value)

    @field_validator("path")
    @classmethod
    def validate_path_input(cls, value):
        value = value.strip()
        lowered = value.casefold()
        if any(token in lowered for token in ("<script", "javascript:", "onerror=", "onload=", "union select", " or 1=1", "--", ";drop ", "<iframe")):
            raise ValueError("Invalid path")
        return value

class FileWriteRequest(FileReadRequest):
    content: str = Field(max_length=50_000_000)
    encoding: str = Field(default="utf-8", max_length=32)
    parent_artifact_ids: list[str] = Field(default_factory=list, max_length=100)
    declared_label: str | None = None
