from datetime import datetime, timedelta, timezone
import json

import pytest

from polymer.core.audit import ScanAuditLog
from polymer.core.events import ScanEvent
from polymer.core.timing import ScanWindow, resolve_end_time
from polymer.models.schema import ToolResult


def test_end_time_uses_next_occurrence_on_server_clock():
    started = datetime(2026, 10, 9, 23, 30, tzinfo=timezone.utc)

    end = resolve_end_time("01:15", started)

    assert end == datetime(2026, 10, 10, 1, 15, tzinfo=timezone.utc)


def test_end_time_requires_strict_24_hour_format():
    started = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="HH:MM"):
        resolve_end_time("7:30", started)


def test_scan_window_caps_scanner_timeout():
    started = datetime.now(timezone.utc)
    window = ScanWindow(started, started + timedelta(minutes=10))

    assert window.timeout(1800) <= 600


def test_audit_log_records_per_ip_scanner_timeline(tmp_path):
    path = tmp_path / "scan.log"
    started = datetime.now(timezone.utc)
    with ScanAuditLog(
        path,
        started_at=started,
        end_at=None,
        ntp_synchronized=True,
        target_count=1,
    ) as audit:
        audit.begin_asset("10.0.0.1")
        audit(ScanEvent("scanner_started", "10.0.0.1", scanner="nmap"))
        audit(
            ScanEvent(
                "scanner_completed",
                "10.0.0.1",
                scanner="nmap",
                result=ToolResult(
                    tool="nmap", status="failed", message="fixture error"
                ),
            )
        )
        audit(ScanEvent("asset_completed", "10.0.0.1"))
        audit.finish("completed", targets_scanned=1, targets_not_started=0)

    records = [json.loads(line) for line in path.read_text().splitlines()]
    completed = next(r for r in records if r["event"] == "scanner_completed")
    asset = next(r for r in records if r["event"] == "asset_completed")
    assert completed["status"] == "failed"
    assert completed["message"] == "fixture error"
    assert completed["duration_seconds"] is not None
    assert asset["scanners_triggered"] == ["nmap"]
    assert asset["errors"][0]["message"] == "fixture error"
