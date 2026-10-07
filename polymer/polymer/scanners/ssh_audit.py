from __future__ import annotations

import json
import shutil
from polymer.core.services import ssh_ports
from polymer.models.schema import Asset, Finding, ToolResult
from polymer.scanners.base import Scanner
from polymer.utils.command import CommandExecutionError, run_command


class SSHAuditScanner(Scanner):
    name = "ssh_audit"

    def available(self) -> bool:
        return shutil.which(self.config.get("binary", "ssh-audit")) is not None

    def run(self, asset: Asset) -> ToolResult:
        if not self.available():
            return ToolResult(tool=self.name, status="unavailable", message="ssh-audit not found")
        ports = ssh_ports(asset)
        if not ports:
            return ToolResult(tool=self.name, status="not_applicable", message="no SSH service detected")
        findings: list[Finding] = []
        artifacts=[]
        errors=[]
        successful=0
        for port in ports:
            outfile = self.workdir / f"{asset.ip}_{port}.json"
            try:
                proc = run_command([self.config.get("binary", "ssh-audit"), "-j", f"{asset.ip}:{port}"], timeout=int(self.config.get("timeout", 120)))
            except CommandExecutionError as exc:
                errors.append(f"{asset.ip}:{port}: {exc}")
                continue
            raw = proc.stdout.strip()
            if raw:
                outfile.write_text(raw, encoding="utf-8", errors="replace")
                artifacts.append(str(outfile))
                try:
                    data=json.loads(raw)
                except json.JSONDecodeError as exc:
                    errors.append(f"{asset.ip}:{port}: invalid JSON: {exc}")
                    continue
                successful += 1
                recs=data.get("recommendations", {})
                for sev_key, severity in (("critical","critical"),("warning","medium"),("warn","medium")):
                    items=recs.get(sev_key, [])
                    if isinstance(items, dict):
                        items=[f"{k}: {v}" for k,v in items.items()]
                    for item in items or []:
                        findings.append(Finding(tool=self.name,title=str(item),severity=severity,category="ssh",port=port,protocol="tcp",evidence={"source":"ssh-audit recommendations"}))
                # Keep useful algorithm warnings even if recommendation schema differs.
                for section in ("kex", "key", "enc", "mac"):
                    block=data.get(section, {})
                    if not isinstance(block, dict):
                        continue
                    for alg, details in block.items():
                        if not isinstance(details, dict):
                            continue
                        notes=details.get("notes") or details.get("warnings") or []
                        if isinstance(notes, str): notes=[notes]
                        for note in notes:
                            findings.append(Finding(tool=self.name,title=f"{section.upper()} {alg}: {note}",severity="medium",category="ssh",port=port,protocol="tcp"))
            elif proc.returncode != 0:
                errors.append(proc.stderr.strip() or f"ssh-audit exited with code {proc.returncode}")
            else:
                errors.append(f"{asset.ip}:{port}: ssh-audit returned no JSON")
        status="completed" if successful else "failed"
        return ToolResult(tool=self.name,status=status,findings=findings,raw_artifact=", ".join(artifacts) or None,message="; ".join(errors) or None)
