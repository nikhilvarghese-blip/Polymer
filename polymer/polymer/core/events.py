from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Literal

from polymer.models.schema import ToolResult

EventKind = Literal[
    "scanner_started",
    "scanner_completed",
    "scan_planned",
    "asset_completed",
]


@dataclass(frozen=True)
class ScanEvent:
    """A UI-neutral progress event emitted by the scan orchestrator."""

    kind: EventKind
    asset_ip: str
    scanner: str | None = None
    scanner_total: int | None = None
    scanners: tuple[str, ...] | None = None
    result: ToolResult | None = None


ProgressCallback = Callable[[ScanEvent], None]
