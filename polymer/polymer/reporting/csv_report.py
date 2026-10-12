from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
import tempfile
from typing import Any, Iterable, Sequence

from polymer.intelligence.severity import SEVERITY_RANK, normalize_severity
from polymer.models.schema import (
    Asset,
    CorrelatedFinding,
    Finding,
    Service,
    ToolResult,
)
from polymer.reporting.paths import asset_folder_name, ensure_unique_asset_ips

REPORT_SCHEMA_VERSION = "1.0"

FINDING_COLUMNS = (
    "report_schema_version",
    "record_type",
    "analysis_mode",
    "finding_id",
    "ip_address",
    "hostname",
    "asset_status",
    "coverage_status",
    "assessment_complete",
    "count_basis",
    "kev_evaluation",
    "scanner_issue_count",
    "service_count",
    "open_services",
    "port",
    "affected_ports",
    "protocol",
    "service",
    "product",
    "version",
    "title",
    "description",
    "category",
    "severity",
    "source_severity",
    "priority_score",
    "confidence",
    "confidence_score",
    "cvss_score",
    "cvss_vector",
    "cvss_version",
    "cve",
    "cwe",
    "cpe",
    "known_exploited",
    "kev_details",
    "scanners",
    "scanner_status",
    "source_finding_count",
    "check_id",
    "policy_id",
    "evidence",
    "remediation",
    "detected_at",
    "raw_artifacts",
    "scanner_messages",
    "critical_count",
    "high_count",
    "medium_count",
    "low_count",
    "info_count",
    "unknown_count",
    "kev_count",
    "raw_finding_count",
    "correlated_finding_count",
)

ASSET_COLUMNS = (
    "report_schema_version",
    "ip_address",
    "hostname",
    "asset_status",
    "coverage_status",
    "assessment_complete",
    "count_basis",
    "kev_evaluation",
    "scanner_issue_count",
    "service_count",
    "open_ports",
    "scanner_count",
    "completed_scanners",
    "failed_scanners",
    "unavailable_scanners",
    "skipped_scanners",
    "not_applicable_scanners",
    "raw_finding_count",
    "correlated_finding_count",
    "highest_severity",
    "maximum_priority_score",
    "critical_count",
    "high_count",
    "medium_count",
    "low_count",
    "info_count",
    "unknown_count",
    "kev_count",
    "scanner_status",
)

SERVICE_COLUMNS = (
    "report_schema_version",
    "ip_address",
    "hostname",
    "asset_status",
    "port",
    "protocol",
    "state",
    "service",
    "product",
    "version",
    "related_finding_count",
)

SCANNER_COLUMNS = (
    "report_schema_version",
    "ip_address",
    "hostname",
    "asset_status",
    "scanner",
    "scanner_status",
    "partial_result",
    "finding_count",
    "raw_artifact",
    "message",
)

CONSOLIDATED_FINDING_COLUMNS = (
    "report_schema_version",
    "record_type",
    "ip_address",
    "hostname",
    "scan_outcome",
    "asset_status",
    "coverage_status",
    "assessment_complete",
    "tool_name",
    "tool_status",
    "tool_finding_count",
    "finding_id",
    "finding_title",
    "description",
    "severity",
    "category",
    "port",
    "protocol",
    "service",
    "product",
    "version",
    "cve",
    "check_id",
    "policy_id",
    "detected_at",
    "evidence",
    "remediation",
    "service_count",
    "open_services",
    "asset_raw_finding_count",
    "asset_correlated_finding_count",
    "critical_count",
    "high_count",
    "medium_count",
    "low_count",
    "info_count",
    "unknown_count",
    "raw_artifact",
    "tool_message",
)


def _json_cell(value: Any) -> str:
    if isinstance(value, set):
        value = sorted(value, key=str)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _safe_cell(value: Any) -> Any:
    """Prevent spreadsheet formula injection while retaining machine-readable CSV."""
    if value is None:
        return ""
    if isinstance(value, datetime):
        value = value.isoformat()
    elif isinstance(value, (dict, list, tuple, set)):
        value = _json_cell(value)
    if not isinstance(value, str):
        return value
    stripped = value.lstrip()
    if value.startswith(("\t", "\r")) or stripped.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def _write_csv(rows: Iterable[dict[str, Any]], columns: Sequence[str], path: Path) -> None:
    """Write a deterministic, formula-safe CSV atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            writer = csv.DictWriter(
                handle,
                fieldnames=list(columns),
                extrasaction="raise",
                lineterminator="\n",
            )
            writer.writeheader()
            for row in rows:
                writer.writerow(
                    {column: _safe_cell(row.get(column, "")) for column in columns}
                )
        temporary.replace(path)
    except Exception:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        raise


def _joined(values: Iterable[Any]) -> str:
    return "; ".join(str(value) for value in values if value not in (None, ""))


def _coverage_status(asset: Asset) -> str:
    statuses = {result.status for result in asset.tools.values()}
    if asset.status != "up":
        return "not_assessed"
    if not statuses:
        return "not_assessed"
    if statuses.issubset({"skipped", "not_applicable"}):
        return "not_assessed"
    if statuses.intersection({"failed", "unavailable", "skipped"}):
        return "partial"
    return "complete"


def _count_basis(asset: Asset) -> str:
    return "correlated" if asset.correlated_findings or asset.risk_summary else "raw"


def _kev_evaluation(asset: Asset) -> str:
    cve_findings = [
        finding for finding in asset.correlated_findings if finding.cve
    ]
    if not cve_findings:
        return "not_applicable" if _count_basis(asset) == "correlated" else "not_evaluated"
    if any(finding.kev for finding in cve_findings):
        return "confirmed_kev"
    return "not_evaluated"


def _scanner_issue_count(asset: Asset) -> int:
    return sum(
        1
        for result in asset.tools.values()
        if result.status in {"failed", "unavailable"}
    )


def scan_outcome(asset: Asset) -> str:
    """Describe scan execution coverage, independently of vulnerability severity."""
    if asset.status == "unknown" and not asset.tools:
        return "not_started"
    if asset.status != "up":
        return "failed"
    if any(
        result.status in {"failed", "unavailable", "skipped"}
        for result in asset.tools.values()
    ):
        return "failed"
    if not any(result.status == "completed" for result in asset.tools.values()):
        return "failed"
    return "passed"


def _open_services(asset: Asset) -> str:
    return _joined(
        f"{service.port}/{service.protocol}:{service.name or 'unknown'}"
        for service in asset.services
        if service.state == "open"
    )


def _severity_data(asset: Asset) -> dict[str, Any]:
    if asset.correlated_findings:
        severities = [finding.severity for finding in asset.correlated_findings]
    else:
        severities = [
            finding.severity
            for result in asset.tools.values()
            for finding in result.findings
        ]
    normalized = [normalize_severity(value) for value in severities]
    counts = Counter(normalized)
    highest = max(
        normalized,
        key=lambda value: SEVERITY_RANK[value],
        default="",
    )
    return {
        "highest_severity": highest,
        "critical_count": counts.get("critical", 0),
        "high_count": counts.get("high", 0),
        "medium_count": counts.get("medium", 0),
        "low_count": counts.get("low", 0),
        "info_count": counts.get("info", 0),
        "unknown_count": counts.get("unknown", 0),
        "kev_count": sum(
            1 for finding in asset.correlated_findings if finding.kev
        ),
        "raw_finding_count": sum(
            len(result.findings) for result in asset.tools.values()
        ),
        "correlated_finding_count": len(asset.correlated_findings),
    }


def _service_for(
    asset: Asset,
    port: int | None,
    protocol: str | None = None,
) -> Service | None:
    if port is None:
        return None
    matches = [service for service in asset.services if service.port == port]
    if protocol:
        return next(
            (service for service in matches if service.protocol == protocol),
            None,
        )
    return matches[0] if len(matches) == 1 else None


def _scanner_details(asset: Asset, scanners: Iterable[str]) -> dict[str, str]:
    names = list(dict.fromkeys(scanners))
    statuses = []
    artifacts = []
    messages = []
    for name in names:
        result = asset.tools.get(name)
        if result is None:
            statuses.append(f"{name}:not_recorded")
            continue
        statuses.append(f"{name}:{result.status}")
        if result.raw_artifact:
            artifacts.append(f"{name}:{result.raw_artifact}")
        if result.message:
            messages.append(f"{name}:{result.message}")
    return {
        "scanners": _joined(names),
        "scanner_status": _joined(statuses),
        "raw_artifacts": _joined(artifacts),
        "scanner_messages": _joined(messages),
    }


def _base_finding_row(asset: Asset, port: int | None, protocol: str | None) -> dict[str, Any]:
    service = _service_for(asset, port, protocol)
    row = {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "ip_address": asset.ip,
        "hostname": asset.hostname or "",
        "asset_status": asset.status,
        "coverage_status": _coverage_status(asset),
        "assessment_complete": "yes" if _coverage_status(asset) == "complete" else "no",
        "count_basis": _count_basis(asset),
        "kev_evaluation": _kev_evaluation(asset),
        "scanner_issue_count": _scanner_issue_count(asset),
        "service_count": len(asset.services),
        "open_services": _open_services(asset),
        "port": port if port is not None else "",
        "affected_ports": port if port is not None else "",
        "protocol": protocol or (service.protocol if service else ""),
        "service": service.name or "" if service else "",
        "product": service.product or "" if service else "",
        "version": service.version or "" if service else "",
    }
    row.update(_severity_data(asset))
    return row


def _raw_finding_id(asset: Asset, finding: Finding) -> str:
    material = "|".join(
        [
            asset.ip,
            finding.tool,
            str(finding.port or ""),
            finding.protocol or "",
            finding.title,
            ",".join(sorted(finding.cve)),
            finding.check_id or "",
            finding.policy_id or "",
        ]
    )
    return "POLY-RAW-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:12].upper()


def _correlated_row(asset: Asset, finding: CorrelatedFinding) -> dict[str, Any]:
    source_findings = finding.source_findings or []
    protocols = {
        str(item["protocol"])
        for item in source_findings
        if item.get("protocol")
    }
    protocol = finding.protocol or (next(iter(protocols)) if len(protocols) == 1 else None)
    row = _base_finding_row(asset, finding.port, protocol)
    scanner_data = _scanner_details(asset, finding.tools)
    affected_ports = sorted(
        ({finding.port} if finding.port is not None else set())
        | {
            int(item["port"])
            for item in finding.evidence
            if item.get("port") is not None and str(item.get("port")).isdigit()
        }
    )
    detected_at = _joined(
        item.get("detected_at") for item in source_findings
    )
    row.update(scanner_data)
    row.update(
        {
            "record_type": "finding",
            "analysis_mode": "correlated",
            "finding_id": finding.finding_id,
            "title": finding.title,
            "description": finding.description or "",
            "category": finding.category,
            "affected_ports": _joined(affected_ports),
            "severity": finding.severity,
            "source_severity": finding.source_severity,
            "priority_score": finding.priority_score,
            "confidence": finding.confidence,
            "confidence_score": finding.confidence_score,
            "cvss_score": finding.cvss_score if finding.cvss_score is not None else "",
            "cvss_vector": finding.cvss_vector or "",
            "cvss_version": finding.cvss_version or "",
            "cve": _joined(finding.cve),
            "cwe": _joined(finding.cwe),
            "cpe": _joined(finding.cpe),
            "known_exploited": (
                "yes" if finding.kev else "not_evaluated" if finding.cve else "not_applicable"
            ),
            "kev_details": finding.kev_details,
            "source_finding_count": len(source_findings),
            "check_id": _joined(
                item.get("check_id") for item in source_findings
            ),
            "policy_id": _joined(
                item.get("policy_id") for item in source_findings
            ),
            "evidence": finding.evidence,
            "remediation": _joined(finding.remediation),
            "detected_at": detected_at,
        }
    )
    return row


def _raw_row(asset: Asset, finding: Finding) -> dict[str, Any]:
    row = _base_finding_row(asset, finding.port, finding.protocol)
    row.update(_scanner_details(asset, [finding.tool]))
    description = finding.evidence.get("description")
    row.update(
        {
            "record_type": "finding",
            "analysis_mode": "raw",
            "finding_id": _raw_finding_id(asset, finding),
            "title": finding.title,
            "description": description if isinstance(description, str) else "",
            "category": finding.category,
            "affected_ports": finding.port if finding.port is not None else "",
            "severity": finding.severity,
            "source_severity": finding.severity,
            "cve": _joined(finding.cve),
            "known_exploited": "not_evaluated" if finding.cve else "not_applicable",
            "source_finding_count": 1,
            "check_id": finding.check_id or "",
            "policy_id": finding.policy_id or "",
            "evidence": finding.evidence,
            "remediation": finding.remediation or "",
            "detected_at": finding.detected_at,
        }
    )
    return row


def raw_finding_rows(assets: Iterable[Asset]) -> list[dict[str, Any]]:
    """Return every source-tool finding, even when correlation is available."""
    return [
        _raw_row(asset, finding)
        for asset in assets
        for result in asset.tools.values()
        for finding in result.findings
    ]


def finding_rows(assets: Iterable[Asset]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for asset in assets:
        if asset.correlated_findings:
            rows.extend(
                _correlated_row(asset, finding)
                for finding in asset.correlated_findings
            )
            continue
        raw_findings = [
            finding
            for result in asset.tools.values()
            for finding in result.findings
        ]
        if raw_findings:
            rows.extend(_raw_row(asset, finding) for finding in raw_findings)
            continue
        row = _base_finding_row(asset, None, None)
        scanner_names = list(asset.tools)
        row.update(_scanner_details(asset, scanner_names))
        coverage = _coverage_status(asset)
        row.update(
            {
                "record_type": "asset_summary",
                "analysis_mode": "summary",
                "title": (
                    "No findings available - scanner coverage incomplete"
                    if coverage == "partial"
                    else "Target not assessed - no findings conclusion unavailable"
                    if coverage == "not_assessed"
                    else "No findings reported"
                ),
                "description": (
                    "Review scanner_status and scanner_messages before treating this target as clean."
                    if coverage != "complete"
                    else "All recorded scanners completed without reporting findings."
                ),
                "category": "scan_summary",
                "source_finding_count": 0,
            }
        )
        rows.append(row)
    return rows


def asset_rows(assets: Iterable[Asset]) -> list[dict[str, Any]]:
    rows = []
    for asset in assets:
        statuses = Counter(result.status for result in asset.tools.values())
        severity = _severity_data(asset)
        rows.append(
            {
                "ip_address": asset.ip,
                "report_schema_version": REPORT_SCHEMA_VERSION,
                "hostname": asset.hostname or "",
                "asset_status": asset.status,
                "coverage_status": _coverage_status(asset),
                "assessment_complete": "yes" if _coverage_status(asset) == "complete" else "no",
                "count_basis": _count_basis(asset),
                "kev_evaluation": _kev_evaluation(asset),
                "scanner_issue_count": _scanner_issue_count(asset),
                "service_count": len(asset.services),
                "open_ports": _joined(
                    f"{service.port}/{service.protocol}"
                    for service in asset.services
                    if service.state == "open"
                ),
                "scanner_count": len(asset.tools),
                "completed_scanners": statuses.get("completed", 0),
                "failed_scanners": statuses.get("failed", 0),
                "unavailable_scanners": statuses.get("unavailable", 0),
                "skipped_scanners": statuses.get("skipped", 0),
                "not_applicable_scanners": statuses.get("not_applicable", 0),
                "maximum_priority_score": max(
                    (finding.priority_score for finding in asset.correlated_findings),
                    default=0,
                ),
                "scanner_status": _scanner_details(asset, asset.tools)[
                    "scanner_status"
                ],
                **severity,
            }
        )
    return rows


def service_rows(assets: Iterable[Asset]) -> list[dict[str, Any]]:
    rows = []
    for asset in assets:
        raw_findings = [
            finding
            for result in asset.tools.values()
            for finding in result.findings
        ]
        for service in asset.services:
            same_port_services = [
                item for item in asset.services if item.port == service.port
            ]
            related = sum(
                1
                for finding in (
                    asset.correlated_findings
                    if asset.correlated_findings
                    else raw_findings
                )
                if finding.port == service.port
                and (
                    finding.protocol == service.protocol
                    or (
                        finding.protocol is None
                        and len(same_port_services) == 1
                    )
                )
            )
            rows.append(
                {
                    "ip_address": asset.ip,
                    "report_schema_version": REPORT_SCHEMA_VERSION,
                    "hostname": asset.hostname or "",
                    "asset_status": asset.status,
                    "port": service.port,
                    "protocol": service.protocol,
                    "state": service.state,
                    "service": service.name or "",
                    "product": service.product or "",
                    "version": service.version or "",
                    "related_finding_count": related,
                }
            )
    return rows


def scanner_rows(assets: Iterable[Asset]) -> list[dict[str, Any]]:
    return [
        {
            "ip_address": asset.ip,
            "report_schema_version": REPORT_SCHEMA_VERSION,
            "hostname": asset.hostname or "",
            "asset_status": asset.status,
            "scanner": name,
            "scanner_status": result.status,
            "partial_result": (
                "yes"
                if result.findings and result.status != "completed"
                else "no"
            ),
            "finding_count": len(result.findings),
            "raw_artifact": result.raw_artifact or "",
            "message": result.message or "",
        }
        for asset in assets
        for name, result in asset.tools.items()
    ]


def _consolidated_row(
    asset: Asset,
    tool_name: str = "",
    result: ToolResult | None = None,
    finding: Finding | None = None,
) -> dict[str, Any]:
    service = _service_for(
        asset,
        finding.port if finding else None,
        finding.protocol if finding else None,
    )
    severity = _severity_data(asset)
    if finding is not None:
        record_type = "finding"
        title = finding.title
        description = finding.evidence.get("description")
        if not isinstance(description, str):
            description = ""
    elif result is not None:
        record_type = "scanner_summary"
        title = (
            f"No findings reported by {tool_name}"
            if result.status == "completed"
            else f"{tool_name} scan status: {result.status}"
        )
        description = result.message or ""
    else:
        record_type = "target_summary"
        title = "Target was not scanned"
        description = "No scanner execution was recorded for this requested IP."

    return {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "record_type": record_type,
        "ip_address": asset.ip,
        "hostname": asset.hostname or "",
        "scan_outcome": scan_outcome(asset),
        "asset_status": asset.status,
        "coverage_status": _coverage_status(asset),
        "assessment_complete": "yes" if _coverage_status(asset) == "complete" else "no",
        "tool_name": tool_name,
        "tool_status": result.status if result else "not_started",
        "tool_finding_count": len(result.findings) if result else 0,
        "finding_id": _raw_finding_id(asset, finding) if finding else "",
        "finding_title": title,
        "description": description,
        "severity": finding.severity if finding else "",
        "category": finding.category if finding else "scan_summary",
        "port": finding.port if finding and finding.port is not None else "",
        "protocol": (
            (finding.protocol or (service.protocol if service else ""))
            if finding
            else ""
        ),
        "service": (service.name or "") if service else "",
        "product": (service.product or "") if service else "",
        "version": (service.version or "") if service else "",
        "cve": _joined(finding.cve) if finding else "",
        "check_id": (finding.check_id or "") if finding else "",
        "policy_id": (finding.policy_id or "") if finding else "",
        "detected_at": finding.detected_at if finding else "",
        "evidence": finding.evidence if finding else {},
        "remediation": (finding.remediation or "") if finding else "",
        "service_count": len(asset.services),
        "open_services": _open_services(asset),
        "asset_raw_finding_count": severity["raw_finding_count"],
        "asset_correlated_finding_count": severity["correlated_finding_count"],
        "critical_count": severity["critical_count"],
        "high_count": severity["high_count"],
        "medium_count": severity["medium_count"],
        "low_count": severity["low_count"],
        "info_count": severity["info_count"],
        "unknown_count": severity["unknown_count"],
        "raw_artifact": (result.raw_artifact or "") if result else "",
        "tool_message": (result.message or "") if result else "",
    }


def consolidated_finding_rows(assets: Iterable[Asset]) -> list[dict[str, Any]]:
    """Return one operational row per raw finding plus empty-tool summaries."""
    rows: list[dict[str, Any]] = []
    for asset in assets:
        if not asset.tools:
            rows.append(_consolidated_row(asset))
            continue
        for tool_name, result in asset.tools.items():
            if result.findings:
                rows.extend(
                    _consolidated_row(asset, tool_name, result, finding)
                    for finding in result.findings
                )
            else:
                rows.append(_consolidated_row(asset, tool_name, result))
    return rows


def _requested_asset_rows(
    assets: list[Asset], requested_ips: Sequence[str] | None
) -> list[Asset]:
    if requested_ips is None:
        return list(assets)
    requested = [Asset(ip=value).ip for value in requested_ips]
    if len(requested) != len(set(requested)):
        raise ValueError("duplicate requested IPs cannot be reported")
    by_ip = {asset.ip: asset for asset in assets}
    ordered = [by_ip.pop(ip, Asset(ip=ip)) for ip in requested]
    ordered.extend(by_ip.values())
    return ordered


def write_csv_reports(
    assets: list[Asset],
    root: Path,
    requested_ips: Sequence[str] | None = None,
) -> None:
    """Write consolidated and per-IP CSV reports for a complete Polymer run."""
    ensure_unique_asset_ips(assets)
    report_assets = _requested_asset_rows(assets, requested_ips)
    ensure_unique_asset_ips(report_assets)
    _write_csv(
        consolidated_finding_rows(report_assets),
        CONSOLIDATED_FINDING_COLUMNS,
        root / "consolidated_findings.csv",
    )
    _write_csv(finding_rows(report_assets), FINDING_COLUMNS, root / "polymer.csv")
    _write_csv(
        raw_finding_rows(report_assets),
        FINDING_COLUMNS,
        root / "raw_findings.csv",
    )
    _write_csv(asset_rows(report_assets), ASSET_COLUMNS, root / "assets.csv")
    _write_csv(service_rows(report_assets), SERVICE_COLUMNS, root / "services.csv")
    _write_csv(
        scanner_rows(report_assets),
        SCANNER_COLUMNS,
        root / "scanner_status.csv",
    )

    for asset in report_assets:
        folder = root / "by_ip" / asset_folder_name(asset.ip)
        _write_csv(finding_rows([asset]), FINDING_COLUMNS, folder / "report.csv")
        _write_csv(
            raw_finding_rows([asset]),
            FINDING_COLUMNS,
            folder / "raw_findings.csv",
        )
        _write_csv(asset_rows([asset]), ASSET_COLUMNS, folder / "summary.csv")
        _write_csv(service_rows([asset]), SERVICE_COLUMNS, folder / "services.csv")
        _write_csv(
            scanner_rows([asset]),
            SCANNER_COLUMNS,
            folder / "scanner_status.csv",
        )
