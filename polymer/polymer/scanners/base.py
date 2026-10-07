from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from polymer.models.schema import Asset, ToolResult


class Scanner(ABC):
    name: str

    def __init__(self, config: dict, workdir: Path):
        self.config = config
        self.workdir = workdir
        self.workdir.mkdir(parents=True, exist_ok=True)

    @abstractmethod
    def available(self) -> bool: ...

    @abstractmethod
    def run(self, asset: Asset) -> ToolResult: ...
