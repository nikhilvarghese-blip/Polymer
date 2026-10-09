from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from polymer.core.timing import ScanWindow
from polymer.models.schema import Asset, ToolResult


class Scanner(ABC):
    name: str

    def __init__(
        self,
        config: dict,
        workdir: Path,
        scan_window: ScanWindow | None = None,
    ):
        self.config = config
        self.workdir = workdir
        self.scan_window = scan_window
        self.workdir.mkdir(parents=True, exist_ok=True)

    def timeout(self, configured_seconds: float) -> float:
        if self.scan_window is None:
            return configured_seconds
        return self.scan_window.timeout(configured_seconds)

    @abstractmethod
    def available(self) -> bool: ...

    @abstractmethod
    def run(self, asset: Asset) -> ToolResult: ...
