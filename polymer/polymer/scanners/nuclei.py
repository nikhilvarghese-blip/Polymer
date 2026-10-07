from __future__ import annotations

import json
import shutil
from polymer.models.schema import Asset, Finding, ToolResult
from polymer.scanners.base import Scanner
from polymer.utils.command import run_command


class NucleiScanner(Scanner):
    name = "nuclei"

    def available(self) -> bool:
        return shutil.which(self.config.get("binary", "nuclei")) is not None

    def run(self, asset: Asset) -> ToolResult:
        if not self.available():
            return ToolResult(tool=self.name, status="unavailable", message="nuclei not found")
        if asset.status != "up":
            return ToolResult(tool=self.name, status="skipped", message="asset is not up")

        targets = []
        for service in asset.services:
            if service.name in {"http", "http-proxy", "https", "ssl/http"} or service.port in {80, 443, 8080, 8443}:
                scheme = "https" if service.port in {443, 8443} or (service.name and "https" in service.name) else "http"
                targets.append(f"{scheme}://{asset.ip}:{service.port}")
        if not targets:
            return ToolResult(tool=self.name, status="not_applicable", message="no HTTP(S) services detected")

        outfile = self.workdir / f"{asset.ip}.jsonl"
        argv = [self.config.get("binary", "nuclei"), "-silent", "-jsonl", "-o", str(outfile)]
        severity = self.config.get("severity")
        if severity:
            argv += ["-severity", ",".join(severity)]
        for target in targets:
            argv += ["-u", target]
        proc = run_command(argv)
        if proc.returncode != 0 and not outfile.exists():
            return ToolResult(tool=self.name, status="failed", message=proc.stderr.strip() or "nuclei failed")

        findings: list[Finding] = []
        if outfile.exists():
            for line in outfile.read_text(errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                info = item.get("info", {})
                findings.append(Finding(
                    tool=self.name,
                    title=info.get("name") or item.get("template-id") or "Nuclei finding",
                    severity=(info.get("severity") or "unknown").lower(),
                    category="web",
                    cve=(info.get("classification", {}).get("cve-id") or []),
                    evidence={"matched_at": item.get("matched-at"), "template_id": item.get("template-id")},
                ))
        return ToolResult(tool=self.name, status="completed", findings=findings, raw_artifact=str(outfile))
