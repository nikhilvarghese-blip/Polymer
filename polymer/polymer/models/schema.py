from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info", "unknown"]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Service(BaseModel):
    port: int
    protocol: str = "tcp"
    state: str = "open"
    name: str | None = None
    product: str | None = None
    version: str | None = None


class Finding(BaseModel):
    tool: str
    title: str
    severity: Severity = "unknown"
    category: str = "vulnerability"
    port: int | None = None
    protocol: str | None = None
    cve: list[str] = Field(default_factory=list)
    check_id: str | None = None
    policy_id: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str | None = None
    detected_at: datetime = Field(default_factory=utcnow)


class ToolResult(BaseModel):
    tool: str
    status: Literal["completed", "failed", "skipped", "not_applicable", "unavailable"]
    findings: list[Finding] = Field(default_factory=list)
    raw_artifact: str | None = None
    message: str | None = None


class Asset(BaseModel):
    ip: str
    hostname: str | None = None
    status: Literal["unknown", "up", "down", "unreachable"] = "unknown"
    services: list[Service] = Field(default_factory=list)
    tools: dict[str, ToolResult] = Field(default_factory=dict)
