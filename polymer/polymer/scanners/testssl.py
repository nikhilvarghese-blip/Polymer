from __future__ import annotations

import json
import shutil
from polymer.core.services import tls_ports
from polymer.models.schema import Asset, Finding, ToolResult
from polymer.scanners.base import Scanner
from polymer.utils.command import CommandExecutionError, run_command


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
        findings=[]; artifacts=[]; errors=[]; successful=0
        for port in ports:
            outfile=self.workdir / f"{asset.ip}_{port}.json"
            cmd=[self.config.get("binary","testssl"),"--quiet","--warnings","batch","--jsonfile",str(outfile),f"{asset.ip}:{port}"]
            try:
                proc=run_command(cmd,timeout=self.timeout(float(self.config.get("timeout",600))))
            except CommandExecutionError as exc:
                errors.append(f"{asset.ip}:{port}: {exc}")
                continue
            if not outfile.exists():
                detail=proc.stderr.strip() or f"no JSON artifact (exit code {proc.returncode})"
                errors.append(f"{asset.ip}:{port}: {detail}")
                continue
            artifacts.append(str(outfile))
            try: data=json.loads(outfile.read_text(errors="replace"))
            except json.JSONDecodeError as exc:
                errors.append(f"{asset.ip}:{port}: invalid JSON: {exc}")
                continue
            successful += 1
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
        status="completed" if successful else "failed"
        return ToolResult(tool=self.name,status=status,findings=findings,raw_artifact=", ".join(artifacts) or None,message="; ".join(errors) or None)
