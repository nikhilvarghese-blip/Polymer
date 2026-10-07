import json
import subprocess
from pathlib import Path

from polymer.models.schema import Asset, Service
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
