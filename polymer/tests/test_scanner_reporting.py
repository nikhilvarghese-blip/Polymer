import json
import subprocess
from pathlib import Path

import lxml.etree as LET

from polymer.models.schema import Asset, Service, ToolResult
from polymer.reporting.csv_report import raw_finding_rows
from polymer.scanners.enum4linux import Enum4LinuxScanner
from polymer.scanners.greenbone import GreenboneScanner
from polymer.scanners.nikto import NiktoScanner
from polymer.scanners.testssl import TestSSLScanner as TLSScanner
from polymer.scanners.wazuh import WazuhSCAScanner


def test_testssl_reads_pretty_results_and_keeps_only_explicit_issues(
    tmp_path: Path, monkeypatch
):
    scanner = TLSScanner({"binary": "testssl", "timeout": 5}, tmp_path)
    monkeypatch.setattr(scanner, "available", lambda: True)

    payload = {
        "scanResult": [
            {
                "serverDefaults": [
                    {
                        "id": "cert_trust",
                        "severity": "HIGH",
                        "finding": "certificate does not match supplied URI",
                        "cve": "CVE-2026-12345",
                        "cwe": "CWE-297",
                        "recommendation": "Replace the mismatched certificate.",
                    },
                    {
                        "id": "TLS1_3",
                        "severity": "INFO",
                        "finding": "not offered",
                    },
                    {
                        "id": "bad-structure",
                        "severity": "HIGH",
                        "finding": {"unexpected": "object"},
                    },
                ]
            }
        ]
    }

    def fake_command(argv, timeout):
        outfile = Path(argv[argv.index("--jsonfile") + 1])
        outfile.write_text(json.dumps(payload), encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr("polymer.scanners.testssl.run_command", fake_command)
    asset = Asset(
        ip="10.0.0.44",
        status="up",
        services=[Service(port=443, name="https")],
    )

    result = scanner.run(asset)

    assert result.status == "completed"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.title == "testssl.sh check: certificate trust validation"
    assert finding.evidence["description"] == (
        "certificate does not match supplied URI"
    )
    assert finding.check_id == "cert_trust"
    assert finding.cve == ["CVE-2026-12345"]
    assert finding.remediation == "Replace the mismatched certificate."
    assert "{" not in finding.title


def test_testssl_warn_is_scanner_failure_not_vulnerability(
    tmp_path: Path, monkeypatch
):
    scanner = TLSScanner({"binary": "testssl", "timeout": 5}, tmp_path)
    monkeypatch.setattr(scanner, "available", lambda: True)

    def fake_command(argv, timeout):
        outfile = Path(argv[argv.index("--jsonfile") + 1])
        outfile.write_text(
            json.dumps(
                [
                    {
                        "id": "OCSP",
                        "severity": "WARN",
                        "finding": "check could not be performed",
                    }
                ]
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr("polymer.scanners.testssl.run_command", fake_command)
    result = scanner.run(
        Asset(
            ip="10.0.0.44",
            status="up",
            services=[Service(port=443, name="https")],
        )
    )

    assert result.status == "failed"
    assert result.findings == []
    assert "WARN: check could not be performed" in result.message


def test_nikto_reads_multi_host_json_without_object_dumping(
    tmp_path: Path, monkeypatch
):
    scanner = NiktoScanner({"binary": "nikto", "timeout": 5}, tmp_path)
    monkeypatch.setattr(scanner, "available", lambda: True)

    def fake_command(argv, timeout):
        outfile = Path(argv[argv.index("-output") + 1])
        outfile.write_text(
            json.dumps(
                [
                    {
                        "host": "10.0.0.80",
                        "port": "8080",
                        "vulnerabilities": [
                            {
                                "id": "123456",
                                "method": "GET",
                                "url": "/admin",
                                "msg": "Administrative endpoint was exposed.",
                                "references": ["CVE-2026-54321", "URL-example"],
                            },
                            {"id": "bad", "msg": {"not": "text"}},
                        ],
                    }
                ]
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr("polymer.scanners.nikto.run_command", fake_command)
    result = scanner.run(
        Asset(
            ip="10.0.0.80",
            status="up",
            services=[Service(port=8080, name="http")],
        )
    )

    assert result.status == "completed"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.title == "Administrative endpoint was exposed."
    assert finding.evidence["description"] == finding.title
    assert finding.check_id == "123456"
    assert finding.cve == ["CVE-2026-54321"]
    assert finding.port == 8080
    assert finding.remediation is None


def test_enum4linux_uses_exact_booleans_not_global_substring_matches(tmp_path: Path):
    scanner = Enum4LinuxScanner({}, tmp_path)
    no_findings = scanner._findings(
        {
            "unrelated_note": "signing disabled and anonymous success",
            "smb_dialects": {"SMB signing required": True, "SMB1 only": False},
            "sessions": {"null": False, "guest": False},
        },
        445,
    )
    assert no_findings == []

    findings = scanner._findings(
        {
            "smb_dialects": {
                "SMB signing required": False,
                "SMB1 only": True,
                "Preferred dialect": "SMB 1.0",
            },
            "sessions": {"null": True, "guest": True},
        },
        445,
    )
    assert {finding.check_id for finding in findings} == {
        "smb-signing-required",
        "smb1-only",
        "null-session",
        "guest-session",
    }
    assert all(finding.severity == "unknown" for finding in findings)
    assert all("{" not in finding.title for finding in findings)


def test_greenbone_separates_observations_and_preserves_direct_solutions(
    tmp_path: Path,
):
    scanner = GreenboneScanner({}, tmp_path)
    report = LET.fromstring(
        b"""
        <get_reports_response>
          <report><results>
            <result id="result-1">
              <name>Services</name><host>10.0.0.9</host><port>443/tcp</port>
              <severity>0.0</severity><threat>Log</threat>
              <description>A TLS server answered on this port</description>
              <nvt oid="1.3.6.1.4.1.test.services">
                <family>Service detection</family><cve>NOCVE</cve>
                <tags>summary=Discovery|solution=Review the detected service.|solution_type=Mitigation</tags>
              </nvt>
            </result>
            <result id="result-2">
              <name>Services</name><host>10.0.0.9</host><port>443/tcp</port>
              <severity>0.0</severity><threat>Log</threat>
              <description>A web server is running through TLS</description>
              <nvt oid="1.3.6.1.4.1.test.services">
                <family>Service detection</family><cve>NOCVE</cve>
              </nvt>
            </result>
            <result id="result-3">
              <name>ICMP Timestamp Reply Information Disclosure</name>
              <host>10.0.0.9</host><port>general/icmp</port>
              <severity>2.1</severity><threat>Low</threat>
              <description>An ICMP timestamp reply was received.</description>
              <nvt oid="1.3.6.1.4.1.test.icmp">
                <family>General</family><cve>CVE-2026-10000, NOCVE</cve>
                <solution type="Mitigation">Filter timestamp requests.</solution>
              </nvt>
            </result>
          </results></report>
        </get_reports_response>
        """
    )

    findings = scanner._parse_report(report, "report-1", "10.0.0.9")

    assert len(findings) == 3
    observations = [finding for finding in findings if finding.severity == "info"]
    assert len(observations) == 2
    assert all(finding.category == "observation" for finding in observations)
    assert len({finding.title for finding in observations}) == 2
    assert observations[0].protocol == "tcp"
    assert observations[0].check_id == "1.3.6.1.4.1.test.services"
    assert observations[0].remediation == "Review the detected service."

    vulnerability = next(finding for finding in findings if finding.severity == "low")
    assert vulnerability.category == "vulnerability"
    assert vulnerability.protocol == "icmp"
    assert vulnerability.cve == ["CVE-2026-10000"]
    assert vulnerability.remediation == "Filter timestamp requests."
    assert vulnerability.evidence["solution_type"] == "Mitigation"

    asset = Asset(
        ip="10.0.0.9",
        status="up",
        tools={
            "greenbone": ToolResult(
                tool="greenbone", status="completed", findings=observations
            )
        },
    )
    ids = [row["finding_id"] for row in raw_finding_rows([asset])]
    assert len(ids) == len(set(ids))


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class _WazuhSession:
    def get(self, url, params=None, timeout=None):
        if url.endswith("/agents"):
            return _Response({"data": {"affected_items": [{"id": "001"}]}})
        if url.endswith("/sca/001"):
            return _Response(
                {"data": {"affected_items": [{"policy_id": "policy-1"}]}}
            )
        return _Response(
            {
                "data": {
                    "affected_items": [
                        {
                            "id": 10,
                            "result": "failed",
                            "title": "Disable an insecure setting",
                            "reason": "The setting remained enabled.",
                            "remediation": "Disable the setting.",
                        },
                        {
                            "id": 11,
                            "result": "failed",
                            "title": {"unexpected": "object"},
                            "reason": {"unexpected": "object"},
                            "remediation": {"unexpected": "object"},
                        },
                    ]
                }
            }
        )


def test_wazuh_ignores_structured_management_text(tmp_path: Path, monkeypatch):
    scanner = WazuhSCAScanner(
        {
            "url": "https://wazuh.invalid",
            "username_env": "WAZUH_TEST_USER",
            "password_env": "WAZUH_TEST_PASSWORD",
        },
        tmp_path,
    )
    monkeypatch.setattr(
        scanner, "_session", lambda: (_WazuhSession(), "https://wazuh.invalid")
    )
    monkeypatch.setattr(scanner, "available", lambda: True)

    result = scanner.run(Asset(ip="10.0.0.10", status="up"))

    assert result.status == "completed"
    assert len(result.findings) == 2
    assert result.findings[0].evidence["description"] == (
        "The setting remained enabled."
    )
    assert result.findings[0].remediation == "Disable the setting."
    assert result.findings[1].title == "SCA check 11"
    assert result.findings[1].remediation is None
    assert "description" not in result.findings[1].evidence
