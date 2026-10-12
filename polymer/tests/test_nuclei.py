import json
import subprocess
from pathlib import Path

from polymer.models.schema import Asset, Finding, Service, ToolResult
from polymer.scanners.nuclei import NucleiScanner


def test_nuclei_normalizes_string_cve_and_unknown_severity(tmp_path: Path, monkeypatch):
    scanner = NucleiScanner(
        {"binary": "nuclei", "severity": ["high"], "timeout": 5},
        tmp_path,
    )
    monkeypatch.setattr(scanner, "available", lambda: True)

    def fake_command(argv, timeout):
        outfile = Path(argv[argv.index("-o") + 1])
        outfile.write_text(
            json.dumps(
                {
                    "template-id": "fixture",
                    "matched-at": "https://10.0.0.1:8443/admin",
                    "info": {
                        "name": "Fixture finding",
                        "severity": "unexpected",
                        "classification": {"cve-id": "CVE-2026-1234"},
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr("polymer.scanners.nuclei.run_command", fake_command)
    asset = Asset(
        ip="10.0.0.1",
        status="up",
        services=[Service(port=443, name="https")],
    )

    result = scanner.run(asset)

    assert result.status == "completed"
    assert result.findings[0].severity == "unknown"
    assert result.findings[0].cve == ["CVE-2026-1234"]
    assert result.findings[0].port == 8443
    assert result.findings[0].protocol == "tcp"


def test_nuclei_scans_in_scope_kiterunner_api_routes(tmp_path: Path, monkeypatch):
    scanner = NucleiScanner(
        {
            "binary": "nuclei",
            "timeout": 5,
            "headers_env": "POLYMER_API_HEADERS",
        },
        tmp_path,
    )
    monkeypatch.setattr(scanner, "available", lambda: True)
    monkeypatch.setenv(
        "POLYMER_API_HEADERS",
        json.dumps({"Authorization": "Bearer fixture-token"}),
    )
    captured_targets = []
    captured_argv = []

    def fake_command(argv, timeout):
        captured_argv.extend(argv)
        target_file = Path(argv[argv.index("-l") + 1])
        captured_targets.extend(target_file.read_text().splitlines())
        outfile = Path(argv[argv.index("-o") + 1])
        outfile.write_text(
            json.dumps(
                {
                    "template-id": "api-fixture",
                    "matched-at": "https://10.0.0.1:8443/api/v1/users",
                    "info": {"name": "API fixture", "severity": "medium"},
                }
            ) + "\n",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr("polymer.scanners.nuclei.run_command", fake_command)
    asset = Asset(
        ip="10.0.0.1",
        status="up",
        services=[Service(port=8443, name="https")],
        tools={
            "kiterunner": ToolResult(
                tool="kiterunner",
                status="completed",
                findings=[
                    Finding(
                        tool="kiterunner",
                        title="API route",
                        category="api_discovery",
                        severity="info",
                        evidence={"url": "https://10.0.0.1:8443/api/v1"},
                    ),
                    Finding(
                        tool="kiterunner",
                        title="Out-of-scope redirect",
                        category="api_discovery",
                        severity="info",
                        evidence={"url": "https://example.com/api"},
                    ),
                ],
            )
        },
    )

    result = scanner.run(asset)

    assert captured_targets == [
        "https://10.0.0.1:8443",
        "https://10.0.0.1:8443/api/v1",
    ]
    assert ["-H", "Authorization: Bearer fixture-token"] == captured_argv[-2:]
    assert result.status == "completed"
    assert result.findings[0].category == "api"
    assert result.findings[0].evidence["target_source"] == "kiterunner"
    assert "1 Kiterunner-discovered" in result.message


def test_nuclei_scans_ip_for_network_templates_when_enabled(tmp_path: Path, monkeypatch):
    scanner = NucleiScanner(
        {"binary": "nuclei", "timeout": 5, "scan_ip": True},
        tmp_path,
    )
    monkeypatch.setattr(scanner, "available", lambda: True)
    captured_targets = []

    def fake_command(argv, timeout):
        target_file = Path(argv[argv.index("-l") + 1])
        captured_targets.extend(target_file.read_text().splitlines())
        outfile = Path(argv[argv.index("-o") + 1])
        outfile.write_text(
            json.dumps(
                {
                    "template-id": "network-fixture",
                    "matched-at": "10.0.0.9:5060",
                    "port": 5060,
                    "info": {"name": "Network fixture", "severity": "low"},
                }
            ) + "\n",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr("polymer.scanners.nuclei.run_command", fake_command)
    asset = Asset(
        ip="10.0.0.9",
        status="up",
        services=[Service(port=5060, name="sip")],
    )

    result = scanner.run(asset)

    assert captured_targets == ["10.0.0.9"]
    assert result.status == "completed"
    assert result.findings[0].category == "network"
    assert result.findings[0].port == 5060
