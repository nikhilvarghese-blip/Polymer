import csv
import json
import subprocess
from pathlib import Path

from polymer.models.schema import Asset, Service, ToolResult
from polymer.reporting.csv_report import write_csv_reports
from polymer.scanners.ssh_audit import SSHAuditScanner


def ssh_audit_payload() -> dict:
    return {
        "kex": [
            {
                "algorithm": "ecdh-sha2-nistp256",
                "notes": {
                    "fail": ["scanner supplied failure note"],
                    "info": ["available since OpenSSH 5.7"],
                },
            }
        ],
        "key": [
            {"algorithm": "ssh-rsa", "notes": {"warn": ["scanner warning"]}}
        ],
        "mac": [
            {"algorithm": "hmac-sha1", "notes": {"info": ["informational only"]}}
        ],
        "recommendations": {
            "critical": {
                "del": {
                    "kex": [
                        {"name": "ecdh-sha2-nistp256", "notes": ""},
                        {"name": "ecdh-sha2-nistp384", "notes": ""},
                    ],
                    "key": [{"name": "ssh-rsa", "notes": ""}],
                }
            },
            "warning": {
                "del": {
                    "mac": [{"name": "hmac-sha1", "notes": ""}],
                }
            },
            "informational": {
                "add": {
                    "kex": [{"name": "curve25519-sha256", "notes": ""}],
                }
            },
        },
    }


def test_ssh_audit_flattens_recommendations_into_human_findings(
    tmp_path: Path, monkeypatch
):
    scanner = SSHAuditScanner({"binary": "ssh-audit", "timeout": 5}, tmp_path)
    monkeypatch.setattr(scanner, "available", lambda: True)

    def fake_command(argv, timeout):
        return subprocess.CompletedProcess(
            argv,
            1,
            json.dumps(ssh_audit_payload()),
            "",
        )

    monkeypatch.setattr("polymer.scanners.ssh_audit.run_command", fake_command)
    asset = Asset(
        ip="10.0.0.22",
        status="up",
        services=[Service(port=22, name="ssh")],
    )

    result = scanner.run(asset)

    assert result.status == "completed"
    assert len(result.findings) == 5
    assert all(
        "{" not in finding.title and "[" not in finding.title
        for finding in result.findings
    )

    ecdh = next(
        finding
        for finding in result.findings
        if finding.evidence["algorithm"] == "ecdh-sha2-nistp256"
    )
    assert ecdh.severity == "critical"
    assert ecdh.evidence["description"] == "scanner supplied failure note"
    assert (
        ecdh.remediation
        == "ssh-audit recommendation: Remove SSH key exchange algorithm "
        "'ecdh-sha2-nistp256'."
    )

    ssh_rsa = next(
        finding
        for finding in result.findings
        if finding.evidence["algorithm"] == "ssh-rsa"
    )
    assert ssh_rsa.evidence["description"] == "scanner warning"
    assert (
        ssh_rsa.remediation
        == "ssh-audit recommendation: Remove SSH host key algorithm 'ssh-rsa'."
    )


def test_ssh_audit_csv_has_management_columns_not_object_titles(tmp_path: Path):
    asset = Asset(
        ip="10.0.0.22",
        status="up",
        services=[Service(port=22, name="ssh")],
    )
    findings = SSHAuditScanner._findings(ssh_audit_payload(), 22)
    asset.tools["ssh_audit"] = ToolResult(
        tool="ssh_audit",
        status="completed",
        findings=findings,
    )
    write_csv_reports([asset], tmp_path / "reports")

    with (tmp_path / "reports" / "consolidated_findings.csv").open(
        encoding="utf-8", newline=""
    ) as handle:
        rows = [
            row
            for row in csv.DictReader(handle)
            if row["record_type"] == "finding"
        ]

    assert rows
    assert all("{'" not in row["finding_title"] for row in rows)
    assert all(row["severity"] for row in rows)
    assert all(row["description"] for row in rows)
    assert any(
        row["remediation"].startswith("ssh-audit recommendation: Remove SSH")
        for row in rows
    )
