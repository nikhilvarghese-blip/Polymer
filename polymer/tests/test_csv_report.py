import csv
from pathlib import Path

import pytest
from pydantic import ValidationError

from polymer.models.schema import (
    Asset,
    CorrelatedFinding,
    Finding,
    Service,
    ToolResult,
)
from polymer.intelligence.correlation import CorrelationEngine
from polymer.reporting.csv_report import _safe_cell, write_csv_reports


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def test_csv_bundle_is_complete_per_ip_and_formula_safe(tmp_path: Path):
    raw = Finding(
        tool="nuclei",
        title="=WEBSERVICE('https://example.invalid')",
        severity="high",
        category="web",
        port=443,
        protocol="tcp",
        cve=["CVE-2026-1234"],
        evidence={"request": "GET /admin", "description": "Remote execution"},
        remediation="Upgrade the affected package",
    )
    affected = Asset(
        ip="10.0.0.10",
        hostname="web-01",
        status="up",
        services=[
            Service(
                port=443,
                protocol="tcp",
                name="https",
                product="nginx",
                version="1.25",
            )
        ],
        tools={
            "nmap": ToolResult(tool="nmap", status="completed"),
            "nuclei": ToolResult(
                tool="nuclei",
                status="failed",
                findings=[raw],
                raw_artifact="raw/nuclei/10.0.0.10.jsonl",
                message="partial output retained",
            ),
        },
        correlated_findings=[
            CorrelatedFinding(
                finding_id="POLY-ABC123",
                asset_ip="10.0.0.10",
                title="=WEBSERVICE('https://example.invalid')",
                description="Authoritative vulnerability description",
                severity="critical",
                source_severity="high",
                confidence="high",
                confidence_score=90,
                priority_score=100,
                tools=["nuclei"],
                port=443,
                cve=["CVE-2026-1234"],
                cwe=["CWE-78"],
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cvss_version="3.1",
                kev=True,
                evidence=[{"tool": "nuclei", "request": "GET /admin"}],
                remediation=["Upgrade the affected package"],
                source_findings=[{"tool": "nuclei", "title": raw.title}],
            )
        ],
    )
    no_findings = Asset(
        ip="10.0.0.11",
        status="unknown",
        tools={
            "nmap": ToolResult(
                tool="nmap",
                status="unavailable",
                message="nmap not installed",
            )
        },
    )

    write_csv_reports([affected, no_findings], tmp_path)

    report = read_csv(tmp_path / "polymer.csv")
    assert {row["ip_address"] for row in report} == {"10.0.0.10", "10.0.0.11"}
    finding = next(row for row in report if row["record_type"] == "finding")
    assert finding["analysis_mode"] == "correlated"
    assert finding["title"].startswith("'=")
    assert finding["description"] == "Authoritative vulnerability description"
    assert finding["product"] == "nginx"
    assert finding["cve"] == "CVE-2026-1234"
    assert finding["known_exploited"] == "yes"
    assert finding["priority_score"] == "100"
    summary = next(row for row in report if row["record_type"] == "asset_summary")
    assert summary["coverage_status"] == "not_assessed"
    assert summary["assessment_complete"] == "no"
    assert "not assessed" in summary["title"]

    raw_rows = read_csv(tmp_path / "raw_findings.csv")
    assert len(raw_rows) == 1
    assert raw_rows[0]["analysis_mode"] == "raw"
    assert raw_rows[0]["title"].startswith("'=")

    assets = read_csv(tmp_path / "assets.csv")
    affected_summary = next(row for row in assets if row["ip_address"] == "10.0.0.10")
    assert affected_summary["highest_severity"] == "critical"
    assert affected_summary["raw_finding_count"] == "1"
    assert affected_summary["correlated_finding_count"] == "1"

    services = read_csv(tmp_path / "services.csv")
    assert services[0]["related_finding_count"] == "1"
    scanners = read_csv(tmp_path / "scanner_status.csv")
    nuclei = next(row for row in scanners if row["scanner"] == "nuclei")
    assert nuclei["partial_result"] == "yes"

    for filename in (
        "report.csv",
        "raw_findings.csv",
        "summary.csv",
        "services.csv",
        "scanner_status.csv",
    ):
        assert (tmp_path / "by_ip" / "10.0.0.10" / filename).exists()
        assert (tmp_path / "by_ip" / "10.0.0.11" / filename).exists()


def test_asset_ip_validation_prevents_report_path_traversal():
    with pytest.raises(ValidationError, match="invalid asset IP address"):
        Asset(ip="../../outside")


@pytest.mark.parametrize(
    "value",
    ["=1+1", "+cmd", "-2+3", "@SUM(A1)", "\tformula", "\rformula", "  =1"],
)
def test_csv_formula_prefixes_are_escaped(value: str):
    assert _safe_cell(value).startswith("'")


def test_protocol_specific_findings_do_not_conflate_tcp_and_udp(tmp_path: Path):
    asset = Asset(
        ip="10.0.0.53",
        status="up",
        services=[
            Service(port=53, protocol="tcp", name="domain", product="tcp-dns"),
            Service(port=53, protocol="udp", name="domain", product="udp-dns"),
        ],
        tools={
            "fixture": ToolResult(
                tool="fixture",
                status="completed",
                findings=[
                    Finding(
                        tool="fixture",
                        title="DNS issue",
                        severity="medium",
                        port=53,
                        protocol="tcp",
                        cve=["CVE-2026-0053"],
                    ),
                    Finding(
                        tool="fixture",
                        title="DNS issue",
                        severity="medium",
                        port=53,
                        protocol="udp",
                        cve=["CVE-2026-0053"],
                    ),
                ],
            )
        },
    )
    CorrelationEngine({}, intel=None).analyze_assets([asset])
    assert len(asset.correlated_findings) == 2

    write_csv_reports([asset], tmp_path)
    report = read_csv(tmp_path / "polymer.csv")
    assert {(row["protocol"], row["product"]) for row in report} == {
        ("tcp", "tcp-dns"),
        ("udp", "udp-dns"),
    }
    services = read_csv(tmp_path / "services.csv")
    assert [row["related_finding_count"] for row in services] == ["1", "1"]
    raw = read_csv(tmp_path / "raw_findings.csv")
    assert len({row["finding_id"] for row in raw}) == 2


def test_imported_report_attribution_and_duplicate_ips_are_rejected(tmp_path: Path):
    with pytest.raises(ValidationError, match="tool result key"):
        Asset(
            ip="10.0.0.1",
            tools={"safe": ToolResult(tool="different", status="completed")},
        )
    with pytest.raises(ValidationError, match="tool name"):
        Asset(
            ip="10.0.0.1",
            tools={"../../escape": ToolResult(tool="safe", status="completed")},
        )
    with pytest.raises(ValidationError, match="scoped IPv6"):
        Asset(ip="fe80::1%unsafe")
    with pytest.raises(ValueError, match="duplicate asset IPs"):
        write_csv_reports(
            [Asset(ip="10.0.0.1"), Asset(ip="10.0.0.1")],
            tmp_path,
        )
