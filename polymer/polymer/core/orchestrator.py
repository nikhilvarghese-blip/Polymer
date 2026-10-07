from __future__ import annotations

from pathlib import Path
from polymer.models.schema import Asset, ToolResult
from polymer.scanners.nmap import NmapScanner
from polymer.scanners.registry import ScannerRegistry
from polymer.core.dispatcher import ScannerDispatcher


class Orchestrator:
    def __init__(self, config: dict, run_dir: Path, profile_tools: set[str] | None = None):
        self.config=config
        scan=config.get("scan",{})
        self.nmap=NmapScanner(scan.get("nmap",{}),run_dir/"raw"/"nmap")
        self.registry=ScannerRegistry(config,run_dir)
        self.dispatcher=ScannerDispatcher(config,profile_tools)

    def discover_asset(self, ip: str) -> Asset:
        asset=Asset(ip=ip)
        if not self.config.get("scan",{}).get("nmap",{}).get("enabled",True):
            asset.tools["nmap"]=ToolResult(tool="nmap",status="skipped",message="nmap disabled")
            return asset
        result=self.nmap.run(asset)
        asset.tools["nmap"]=result
        return asset

    def plan_asset(self, asset: Asset) -> list[str]:
        return self.dispatcher.scanners_for_asset(asset)

    def scan_discovered_asset(self, asset: Asset) -> Asset:
        for scanner_name in self.plan_asset(asset):
            scanner=self.registry.get(scanner_name)
            try:
                asset.tools[scanner_name]=scanner.run(asset)
            except Exception as exc:
                asset.tools[scanner_name]=ToolResult(tool=scanner_name,status="failed",message=str(exc))
        return asset

    def scan_asset(self, ip: str) -> Asset:
        asset=self.discover_asset(ip)
        if asset.status == "up":
            self.scan_discovered_asset(asset)
        return asset
