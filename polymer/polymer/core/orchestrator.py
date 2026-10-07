from __future__ import annotations

from pathlib import Path

from polymer.core.events import ProgressCallback, ScanEvent
from polymer.core.dispatcher import ScannerDispatcher
from polymer.models.schema import Asset, ToolResult
from polymer.scanners.nmap import NmapScanner
from polymer.scanners.registry import ScannerRegistry


class Orchestrator:
    def __init__(
        self,
        config: dict,
        run_dir: Path,
        profile_tools: set[str] | None = None,
        progress_callback: ProgressCallback | None = None,
    ):
        self.config = config
        self.progress_callback = progress_callback
        scan = config.get("scan", {})
        self.nmap = NmapScanner(scan.get("nmap", {}), run_dir / "raw" / "nmap")
        self.registry = ScannerRegistry(config, run_dir)
        self.dispatcher = ScannerDispatcher(config, profile_tools)

    def _emit(self, event: ScanEvent) -> None:
        if self.progress_callback is not None:
            self.progress_callback(event)

    def discover_asset(self, ip: str) -> Asset:
        asset = Asset(ip=ip)
        self._emit(ScanEvent("scanner_started", ip, scanner="nmap"))
        if not self.config.get("scan", {}).get("nmap", {}).get("enabled", True):
            result = ToolResult(tool="nmap", status="skipped", message="nmap disabled")
            asset.tools["nmap"] = result
            self._emit(ScanEvent("scanner_completed", ip, scanner="nmap", result=result))
            return asset
        try:
            result = self.nmap.run(asset)
        except Exception as exc:
            asset.status = "unreachable"
            result = ToolResult(
                tool="nmap",
                status="failed",
                message=f"{type(exc).__name__}: {exc}",
            )
        asset.tools["nmap"] = result
        self._emit(ScanEvent("scanner_completed", ip, scanner="nmap", result=result))
        return asset

    def plan_asset(self, asset: Asset) -> list[str]:
        return self.dispatcher.scanners_for_asset(asset)

    def scan_discovered_asset(self, asset: Asset) -> Asset:
        scanner_names = self.plan_asset(asset)
        self._emit(
            ScanEvent(
                "scan_planned",
                asset.ip,
                scanner_total=1 + len(scanner_names),
            )
        )
        for scanner_name in scanner_names:
            self._emit(ScanEvent("scanner_started", asset.ip, scanner=scanner_name))
            try:
                scanner = self.registry.get(scanner_name)
                result = scanner.run(asset)
            except Exception as exc:
                result = ToolResult(
                    tool=scanner_name,
                    status="failed",
                    message=f"{type(exc).__name__}: {exc}",
                )
            asset.tools[scanner_name] = result
            self._emit(
                ScanEvent(
                    "scanner_completed",
                    asset.ip,
                    scanner=scanner_name,
                    result=result,
                )
            )
        return asset

    def scan_asset(self, ip: str) -> Asset:
        asset = self.discover_asset(ip)
        if asset.status == "up":
            self.scan_discovered_asset(asset)
        else:
            self._emit(ScanEvent("scan_planned", ip, scanner_total=1))
        self._emit(ScanEvent("asset_completed", ip))
        return asset
