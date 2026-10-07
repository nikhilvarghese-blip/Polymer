from __future__ import annotations

import json
import shutil
from urllib.parse import urlsplit
from polymer.models.schema import Asset, Finding, ToolResult
from polymer.scanners.base import Scanner
from polymer.utils.command import run_command


class NucleiScanner(Scanner):
    name = "nuclei"

    def available(self) -> bool:
        return shutil.which(self.config.get("binary", "nuclei")) is not None

    @staticmethod
    def _matched_port(item: dict) -> int | None:
        raw_port = item.get("port")
        if raw_port is not None:
            try:
                return int(raw_port)
            except (TypeError, ValueError):
                pass
        matched = item.get("matched-at") or item.get("host") or item.get("url")
        if not isinstance(matched, str) or not matched:
            return None
        try:
            parsed = urlsplit(matched if "://" in matched else f"//{matched}")
            if parsed.port is not None:
                return parsed.port
            if parsed.scheme == "https":
                return 443
            if parsed.scheme == "http":
                return 80
        except ValueError:
            return None
        return None

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
            if not isinstance(severity, list) or not all(
                isinstance(item, str) for item in severity
            ):
                return ToolResult(
                    tool=self.name,
                    status="failed",
                    message="nuclei severity must be a list of strings",
                )
            argv += ["-severity", ",".join(severity)]
        for target in targets:
            argv += ["-u", target]
        proc = run_command(argv, timeout=int(self.config.get("timeout", 600)))
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
                if not isinstance(item, dict):
                    continue
                info = item.get("info", {})
                if not isinstance(info, dict):
                    info = {}
                classification = info.get("classification", {})
                if not isinstance(classification, dict):
                    classification = {}
                raw_cves = classification.get("cve-id") or []
                if isinstance(raw_cves, str):
                    raw_cves = [raw_cves]
                severity = str(info.get("severity") or "unknown").lower()
                if severity not in {"critical", "high", "medium", "low", "info"}:
                    severity = "unknown"
                description = info.get("description")
                remediation = info.get("remediation")
                findings.append(Finding(
                    tool=self.name,
                    title=info.get("name") or item.get("template-id") or "Nuclei finding",
                    severity=severity,
                    category="web",
                    port=self._matched_port(item),
                    protocol="tcp",
                    cve=[str(cve).upper() for cve in raw_cves if cve],
                    evidence={
                        "matched_at": item.get("matched-at"),
                        "template_id": item.get("template-id"),
                        "description": description if isinstance(description, str) else None,
                        "references": info.get("reference") or [],
                    },
                    remediation=(
                        remediation if isinstance(remediation, str) else None
                    ),
                ))
        if proc.returncode != 0:
            return ToolResult(
                tool=self.name,
                status="failed",
                findings=findings,
                raw_artifact=str(outfile) if outfile.exists() else None,
                message=proc.stderr.strip() or f"nuclei exited with code {proc.returncode}",
            )
        return ToolResult(tool=self.name, status="completed", findings=findings, raw_artifact=str(outfile))
