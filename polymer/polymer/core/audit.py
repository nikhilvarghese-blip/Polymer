from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import time
from typing import Any

from polymer.core.events import ScanEvent


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


class ScanAuditLog:
    """Durable JSON-lines audit trail for a complete scan run."""

    def __init__(
        self,
        path: Path,
        *,
        started_at: datetime,
        end_at: datetime | None,
        ntp_synchronized: bool | None,
        target_count: int,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._stream = path.open("a", encoding="utf-8", buffering=1)
        self._run_started = time.monotonic()
        self._asset_started: dict[str, float] = {}
        self._scanner_started: dict[tuple[str, str], float] = {}
        self._asset_scanners: dict[str, list[str]] = {}
        self._asset_errors: dict[str, list[dict[str, str]]] = {}
        self.write(
            "run_started",
            level="info",
            clock_source="server_system_clock",
            ntp_synchronized=ntp_synchronized,
            command_started_at=started_at.isoformat(),
            configured_end_at=end_at.isoformat() if end_at else None,
            target_count=target_count,
        )

    def write(self, event: str, *, level: str = "info", **details: Any) -> None:
        record = {
            "timestamp": _utc_timestamp(),
            "level": level,
            "event": event,
            **details,
        }
        self._stream.write(json.dumps(record, sort_keys=True, default=str) + "\n")
        self._stream.flush()

    def begin_asset(self, ip: str) -> None:
        self._asset_started[ip] = time.monotonic()
        self._asset_scanners[ip] = []
        self._asset_errors[ip] = []
        self.write("asset_started", asset_ip=ip)

    def target_not_started(self, ip: str, reason: str) -> None:
        self.write(
            "asset_not_started",
            level="warning",
            asset_ip=ip,
            reason=reason,
        )

    def __call__(self, event: ScanEvent) -> None:
        ip = event.asset_ip
        scanner = event.scanner
        if event.kind == "scan_planned":
            self.write(
                "scan_planned",
                asset_ip=ip,
                scanner_total=event.scanner_total,
                scanners=list(event.scanners or ()),
            )
            return

        if event.kind == "scanner_started" and scanner:
            self._scanner_started[(ip, scanner)] = time.monotonic()
            self._asset_scanners.setdefault(ip, []).append(scanner)
            self.write("scanner_started", asset_ip=ip, scanner=scanner)
            return

        if event.kind == "scanner_completed" and scanner:
            result = event.result
            began = self._scanner_started.pop((ip, scanner), None)
            duration = time.monotonic() - began if began is not None else None
            status = result.status if result else "unknown"
            message = result.message if result else None
            level = "error" if status == "failed" else (
                "warning" if status in {"unavailable", "skipped"} else "info"
            )
            if status in {"failed", "unavailable"}:
                self._asset_errors.setdefault(ip, []).append(
                    {"scanner": scanner, "status": status, "message": message or ""}
                )
            self.write(
                "scanner_completed",
                level=level,
                asset_ip=ip,
                scanner=scanner,
                status=status,
                duration_seconds=round(duration, 3) if duration is not None else None,
                findings_count=len(result.findings) if result else 0,
                raw_artifact=result.raw_artifact if result else None,
                message=message,
            )
            return

        if event.kind == "asset_completed":
            began = self._asset_started.pop(ip, None)
            duration = time.monotonic() - began if began is not None else None
            self.write(
                "asset_completed",
                asset_ip=ip,
                duration_seconds=round(duration, 3) if duration is not None else None,
                scanners_triggered=self._asset_scanners.pop(ip, []),
                errors=self._asset_errors.pop(ip, []),
            )

    def phase(self, name: str, status: str) -> None:
        self.write("phase", phase=name, status=status)

    def finish(self, status: str, **details: Any) -> None:
        self.write(
            "run_completed",
            level="error" if status == "failed" else "info",
            status=status,
            duration_seconds=round(time.monotonic() - self._run_started, 3),
            **details,
        )

    def close(self) -> None:
        self._stream.close()

    def __enter__(self) -> "ScanAuditLog":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if exc is not None:
            self.finish("failed", error=f"{type(exc).__name__}: {exc}")
        self.close()
