from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
from typing import Any, Literal
from pydantic import BaseModel, Field, field_validator, model_validator

from polymer.reporting.paths import validate_tool_name

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

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, value: str) -> str:
        return validate_tool_name(value)


class CorrelatedFinding(BaseModel):
    finding_id: str
    asset_ip: str
    title: str
    description: str | None = None
    category: str = "vulnerability"
    severity: Severity = "unknown"
    source_severity: Severity = "unknown"
    confidence: Literal["high", "medium", "low"] = "low"
    confidence_score: int = 0
    priority_score: int = 0
    tools: list[str] = Field(default_factory=list)
    port: int | None = None
    protocol: str | None = None
    cve: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    cpe: list[str] = Field(default_factory=list)
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    kev: bool = False
    kev_details: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)
    source_findings: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("asset_ip")
    @classmethod
    def validate_asset_ip(cls, value: str) -> str:
        if "%" in value:
            raise ValueError("scoped IPv6 addresses are not supported")
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError(f"invalid correlated asset IP address: {value}") from exc


class ToolResult(BaseModel):
    tool: str
    status: Literal["completed", "failed", "skipped", "not_applicable", "unavailable"]
    findings: list[Finding] = Field(default_factory=list)
    raw_artifact: str | None = None
    message: str | None = None

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, value: str) -> str:
        return validate_tool_name(value)


class Asset(BaseModel):
    ip: str
    hostname: str | None = None
    status: Literal["unknown", "up", "down", "unreachable"] = "unknown"
    services: list[Service] = Field(default_factory=list)
    tools: dict[str, ToolResult] = Field(default_factory=dict)
    correlated_findings: list[CorrelatedFinding] = Field(default_factory=list)
    risk_summary: dict[str, Any] = Field(default_factory=dict)

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        if "%" in value:
            raise ValueError("scoped IPv6 addresses are not supported")
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError(f"invalid asset IP address: {value}") from exc

    @model_validator(mode="after")
    def validate_attribution(self) -> "Asset":
        for name, result in self.tools.items():
            validate_tool_name(name)
            if result.tool != name:
                raise ValueError(
                    f"tool result key {name!r} does not match tool {result.tool!r}"
                )
            for finding in result.findings:
                if finding.tool != result.tool:
                    raise ValueError(
                        f"finding tool {finding.tool!r} does not match result tool {result.tool!r}"
                    )
        for finding in self.correlated_findings:
            if finding.asset_ip != self.ip:
                raise ValueError(
                    f"correlated finding asset {finding.asset_ip!r} does not match {self.ip!r}"
                )
        return self
