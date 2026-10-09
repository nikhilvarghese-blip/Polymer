from pathlib import Path
from datetime import datetime, timedelta, timezone

from polymer.core.orchestrator import Orchestrator
from polymer.core.timing import ScanWindow


def test_discovery_failure_is_preserved_and_emits_progress(tmp_path: Path, monkeypatch):
    events = []
    orchestrator = Orchestrator(
        {"scan": {"nmap": {"enabled": True}}},
        tmp_path,
        progress_callback=events.append,
    )

    def fail(_asset):
        raise RuntimeError("nmap fixture failure")

    monkeypatch.setattr(orchestrator.nmap, "run", fail)
    asset = orchestrator.scan_asset("10.0.0.1")

    assert asset.status == "unreachable"
    assert asset.tools["nmap"].status == "failed"
    assert "RuntimeError: nmap fixture failure" in asset.tools["nmap"].message
    assert [event.kind for event in events] == [
        "scanner_started",
        "scanner_completed",
        "scan_planned",
        "asset_completed",
    ]


def test_scanner_failure_does_not_abort_remaining_orchestration(tmp_path: Path, monkeypatch):
    config = {
        "scan": {
            "nmap": {"enabled": False},
            "greenbone": {"enabled": True},
        }
    }
    orchestrator = Orchestrator(config, tmp_path)

    class BrokenScanner:
        def run(self, _asset):
            raise OSError("scanner fixture failure")

    monkeypatch.setattr(orchestrator.registry, "get", lambda _name: BrokenScanner())
    from polymer.models.schema import Asset

    asset = orchestrator.scan_discovered_asset(Asset(ip="10.0.0.2", status="up"))
    assert asset.tools["greenbone"].status == "failed"
    assert "OSError: scanner fixture failure" in asset.tools["greenbone"].message


def test_expired_scan_window_does_not_start_discovery(tmp_path: Path, monkeypatch):
    now = datetime.now(timezone.utc)
    events = []
    orchestrator = Orchestrator(
        {"scan": {"nmap": {"enabled": True}}},
        tmp_path,
        progress_callback=events.append,
        scan_window=ScanWindow(now - timedelta(minutes=2), now - timedelta(minutes=1)),
    )

    def must_not_run(_asset):
        raise AssertionError("expired scanner was started")

    monkeypatch.setattr(orchestrator.nmap, "run", must_not_run)
    asset = orchestrator.scan_asset("10.0.0.3")

    assert asset.tools["nmap"].status == "skipped"
    assert "end time reached" in asset.tools["nmap"].message
    assert [event.kind for event in events] == [
        "scanner_completed",
        "scan_planned",
        "asset_completed",
    ]
