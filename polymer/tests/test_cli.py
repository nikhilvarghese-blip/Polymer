from pathlib import Path
import json

import yaml
from typer.testing import CliRunner

from polymer.cli import app


runner = CliRunner()


def write_config(path: Path, output: Path, *, nmap_enabled: bool) -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "project": {"output_dir": str(output)},
                "scope": {"allow_public_ips": False, "max_expanded_hosts": 8},
                "scan": {
                    "nmap": {
                        "enabled": nmap_enabled,
                        "binary": "polymer-definitely-missing-nmap",
                    }
                },
                "intelligence": {"enabled": False},
            }
        ),
        encoding="utf-8",
    )


def test_scan_shows_overall_progress_and_writes_reports(tmp_path: Path):
    targets = tmp_path / "targets.txt"
    targets.write_text("10.0.0.1\n", encoding="utf-8")
    config = tmp_path / "polymer.yaml"
    output = tmp_path / "output"
    write_config(config, output, nmap_enabled=False)

    result = runner.invoke(
        app,
        [
            "scan",
            "--targets",
            str(targets),
            "--config",
            str(config),
            "--no-intelligence",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Polymer scan complete" in result.output
    reports = list(output.glob("run-*/polymer.json"))
    assert len(reports) == 1
    assert '"10.0.0.1"' in reports[0].read_text(encoding="utf-8")
    run_dir = reports[0].parent
    assert (run_dir / "polymer.csv").exists()
    assert (run_dir / "assets.csv").exists()
    assert (run_dir / "services.csv").exists()
    assert (run_dir / "scanner_status.csv").exists()
    assert (run_dir / "raw_findings.csv").exists()
    assert (run_dir / "by_ip" / "10.0.0.1" / "report.csv").exists()
    scan_log = run_dir / "scan.log"
    assert scan_log.exists()
    events = [json.loads(line)["event"] for line in scan_log.read_text().splitlines()]
    assert events[0] == "run_started"
    assert "scanner_started" in events
    assert "asset_completed" in events
    assert events[-1] == "run_completed"


def test_fail_on_tool_error_returns_status_two(tmp_path: Path):
    targets = tmp_path / "targets.txt"
    targets.write_text("10.0.0.1\n", encoding="utf-8")
    config = tmp_path / "polymer.yaml"
    write_config(config, tmp_path / "output", nmap_enabled=True)

    result = runner.invoke(
        app,
        [
            "scan",
            "--targets",
            str(targets),
            "--config",
            str(config),
            "--no-intelligence",
            "--fail-on-tool-error",
        ],
    )

    assert result.exit_code == 2
    assert "Completed with 1 scanner issue" in result.output


def test_invalid_config_is_a_concise_cli_error(tmp_path: Path):
    targets = tmp_path / "targets.txt"
    targets.write_text("10.0.0.1\n", encoding="utf-8")
    config = tmp_path / "polymer.yaml"
    config.write_text("- not\n- a\n- mapping\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["validate", "--targets", str(targets), "--config", str(config)],
    )

    assert result.exit_code == 1
    assert "configuration root must be a mapping" in result.output
    assert "Traceback" not in result.output


def test_analyze_writes_csv_to_a_unique_output_directory(tmp_path: Path):
    targets = tmp_path / "targets.txt"
    targets.write_text("10.0.0.1\n", encoding="utf-8")
    config = tmp_path / "polymer.yaml"
    output = tmp_path / "output"
    write_config(config, output, nmap_enabled=False)
    scan_result = runner.invoke(
        app,
        [
            "scan",
            "--targets",
            str(targets),
            "--config",
            str(config),
            "--no-intelligence",
        ],
    )
    assert scan_result.exit_code == 0, scan_result.output
    input_report = next(output.glob("run-*/polymer.json"))

    result = runner.invoke(
        app,
        ["analyze", "--input", str(input_report), "--config", str(config)],
    )

    assert result.exit_code == 0, result.output
    analysis_dirs = list(input_report.parent.glob("analysis-*"))
    assert len(analysis_dirs) == 1
    assert (analysis_dirs[0] / "polymer.csv").exists()
    assert (analysis_dirs[0] / "by_ip" / "10.0.0.1" / "report.csv").exists()
