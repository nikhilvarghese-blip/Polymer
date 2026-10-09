from __future__ import annotations
from pathlib import Path
from polymer.core.timing import ScanWindow
from polymer.scanners.nuclei import NucleiScanner
from polymer.scanners.wazuh import WazuhSCAScanner
from polymer.scanners.ssh_audit import SSHAuditScanner
from polymer.scanners.testssl import TestSSLScanner
from polymer.scanners.nikto import NiktoScanner
from polymer.scanners.enum4linux import Enum4LinuxScanner
from polymer.scanners.greenbone import GreenboneScanner


class ScannerRegistry:
    def __init__(self, config: dict, run_dir: Path, scan_window: ScanWindow | None = None):
        scan=config.get("scan",{})
        self.scanners={
            "nuclei": NucleiScanner(scan.get("nuclei",{}),run_dir/"raw"/"nuclei",scan_window),
            "wazuh_sca": WazuhSCAScanner(scan.get("wazuh",{}),run_dir/"raw"/"wazuh",scan_window),
            "ssh_audit": SSHAuditScanner(scan.get("ssh_audit",{}),run_dir/"raw"/"ssh_audit",scan_window),
            "testssl": TestSSLScanner(scan.get("testssl",{}),run_dir/"raw"/"testssl",scan_window),
            "nikto": NiktoScanner(scan.get("nikto",{}),run_dir/"raw"/"nikto",scan_window),
            "enum4linux": Enum4LinuxScanner(scan.get("enum4linux",{}),run_dir/"raw"/"enum4linux",scan_window),
            "greenbone": GreenboneScanner(scan.get("greenbone",{}),run_dir/"raw"/"greenbone",scan_window),
        }

    def get(self,name: str):
        return self.scanners[name]
