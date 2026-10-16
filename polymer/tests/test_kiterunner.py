import json
import subprocess
from pathlib import Path

from polymer.models.schema import Asset, Service
from polymer.scanners.kiterunner import KiterunnerScanner


def test_kiterunner_normalizes_discovered_api_routes(tmp_path: Path, monkeypatch):
    wordlist = tmp_path / "routes-small.kite"
    wordlist.write_bytes(b"fixture")
    scanner = KiterunnerScanner(
        {
            "binary": "kr",
            "wordlist": str(wordlist),
            "timeout": 5,
            "fail_status_codes": [404],
            "headers_env": "POLYMER_API_HEADERS",
        },
        tmp_path / "raw",
    )
    monkeypatch.setattr(scanner, "available", lambda: True)
    monkeypatch.setenv(
        "POLYMER_API_HEADERS",
        json.dumps({"Authorization": "Bearer fixture-token"}),
    )
    captured = []

    def fake_command(argv, timeout):
        captured.append(argv)
        records = [
            {
                "method": "post",
                "target": "https://10.0.0.8:8443",
                "path": "/api/v1/users",
                "responses": [{"uri": "", "sc": 401, "len": 42}],
            },
            {
                "method": "GET",
                "target": "https://outside.example",
                "path": "/redirected",
                "responses": [{"uri": "", "sc": 200, "len": 10}],
            },
        ]
        return subprocess.CompletedProcess(
            argv,
            0,
            "\n".join(json.dumps(record) for record in records) + "\n",
            "",
        )

    monkeypatch.setattr("polymer.scanners.kiterunner.run_command", fake_command)
    asset = Asset(
        ip="10.0.0.8",
        status="up",
        services=[Service(port=8443, name="https")],
    )

    result = scanner.run(asset)

    assert result.status == "completed"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.category == "api_discovery"
    assert finding.severity == "info"
    assert finding.port == 8443
    assert finding.evidence == {
        "description": (
            "Kiterunner reported HTTP status 401 for POST "
            "https://10.0.0.8:8443/api/v1/users."
        ),
        "url": "https://10.0.0.8:8443/api/v1/users",
        "method": "POST",
        "status_code": 401,
        "response_chain": [{"uri": "", "sc": 401, "len": 42}],
    }
    assert finding.check_id == "POST /api/v1/users"
    assert "--output" in captured[0]
    assert "--progress=false" in captured[0]
    assert captured[0][-2:] == ["--header", "Authorization: Bearer fixture-token"]
    assert "ignored 1 malformed or out-of-scope" in result.message
    assert Path(result.raw_artifact).exists()


def test_kiterunner_missing_wordlist_is_nonfatal_unavailable(tmp_path: Path, monkeypatch):
    scanner = KiterunnerScanner(
        {"binary": "kr", "wordlist": str(tmp_path / "missing.kite")},
        tmp_path / "raw",
    )
    monkeypatch.setattr(scanner, "available", lambda: True)
    asset = Asset(
        ip="10.0.0.8",
        status="up",
        services=[Service(port=80, name="http")],
    )

    result = scanner.run(asset)

    assert result.status == "unavailable"
    assert "wordlist not found" in result.message


def test_kiterunner_skips_assets_that_are_not_up(tmp_path: Path, monkeypatch):
    scanner = KiterunnerScanner({}, tmp_path)
    monkeypatch.setattr(
        scanner,
        "available",
        lambda: (_ for _ in ()).throw(AssertionError("availability was checked")),
    )

    result = scanner.run(Asset(ip="10.0.0.8", status="down"))

    assert result.status == "skipped"
