from __future__ import annotations

import json
import shutil
from polymer.core.services import tls_ports
from polymer.models.schema import Asset, Finding, ToolResult
from polymer.scanners.base import Scanner
from polymer.utils.command import run_command


class TestSSLScanner(Scanner):
    name = "testssl"

    def available(self) -> bool:
        return shutil.which(self.config.get("binary", "testssl")) is not None

    def run(self, asset: Asset) -> ToolResult:
        if not self.available():
            return ToolResult(tool=self.name,status="unavailable",message="testssl not found")
        ports=tls_ports(asset)
        if not ports:
            return ToolResult(tool=self.name,status="not_applicable",message="no TLS service detected")
        findings=[]; artifacts=[]
        for port in ports:
            outfile=self.workdir / f"{asset.ip}_{port}.json"
            cmd=[self.config.get("binary","testssl"),"--quiet","--warnings","batch","--jsonfile",str(outfile),f"{asset.ip}:{port}"]
            proc=run_command(cmd,timeout=int(self.config.get("timeout",600)))
            if not outfile.exists():
                if proc.returncode != 0:
                    continue
                continue
            artifacts.append(str(outfile))
            try: data=json.loads(outfile.read_text(errors="replace"))
            except json.JSONDecodeError: continue
            if isinstance(data, dict):
                data=data.get("scanResult") or data.get("results") or [data]
            for item in data if isinstance(data,list) else []:
                if not isinstance(item,dict): continue
                sev=str(item.get("severity") or "info").lower()
                if sev not in {"critical","high","medium","low","info"}: sev="unknown"
                # Keep actionable/non-OK items; informational items stay as evidence only when severity is explicit.
                finding_text=item.get("finding") or item.get("id") or item.get("fqdn")
                if sev in {"critical","high","medium","low"} and finding_text:
                    findings.append(Finding(tool=self.name,title=str(item.get("id") or finding_text),severity=sev,category="tls",port=port,protocol="tcp",evidence={"finding":finding_text}))
        return ToolResult(tool=self.name,status="completed",findings=findings,raw_artifact=", ".join(artifacts) or None)
