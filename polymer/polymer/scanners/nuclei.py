from __future__ import annotations

import ipaddress
import json
import shutil
from urllib.parse import urlsplit

from polymer.core.http_headers import api_headers
from polymer.core.services import web_endpoints
from polymer.models.schema import Asset, Finding, ToolResult
from polymer.scanners.base import Scanner
from polymer.utils.command import run_command


class NucleiScanner(Scanner):
    name = "nuclei"

    def available(self) -> bool:
        return shutil.which(self.config.get("binary", "nuclei")) is not None

    @staticmethod
    def _in_scope_url(value: object, asset_ip: str) -> str | None:
        if not isinstance(value, str) or not value:
            return None
        try:
            parsed = urlsplit(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                return None
            if ipaddress.ip_address(parsed.hostname) != ipaddress.ip_address(asset_ip):
                return None
        except (TypeError, ValueError):
            return None
        return value

    def _targets(self, asset: Asset) -> tuple[list[str], set[str]]:
        roots = [url for url, _port in web_endpoints(asset)]
        network_targets = [asset.ip] if self.config.get("scan_ip", False) else []
        discovered: list[str] = []
        result = asset.tools.get("kiterunner")
        if result is not None:
            for finding in result.findings:
                if finding.category != "api_discovery":
                    continue
                value = self._in_scope_url(finding.evidence.get("url"), asset.ip)
                if value:
                    discovered.append(value)
        api_targets = set(discovered)
        return list(
            dict.fromkeys([*network_targets, *roots, *discovered])
        ), api_targets

    @staticmethod
    def _category(value: object, api_match: bool) -> str:
        if api_match:
            return "api"
        if isinstance(value, str):
            try:
                if urlsplit(value).scheme in {"http", "https"}:
                    return "web"
            except ValueError:
                pass
        return "network"

    @staticmethod
    def _is_api_match(value: object, api_targets: set[str]) -> bool:
        if not isinstance(value, str):
            return False
        try:
            matched = urlsplit(value)
        except ValueError:
            return False
        for target in api_targets:
            try:
                discovered = urlsplit(target)
                matched_port = matched.port or (443 if matched.scheme == "https" else 80)
                discovered_port = discovered.port or (
                    443 if discovered.scheme == "https" else 80
                )
            except ValueError:
                continue
            if (
                matched.scheme != discovered.scheme
                or matched.hostname != discovered.hostname
                or matched_port != discovered_port
            ):
                continue
            discovered_path = discovered.path.rstrip("/") or "/"
            if matched.path == discovered_path or matched.path.startswith(
                discovered_path.rstrip("/") + "/"
            ):
                return True
        return False

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

        targets, api_targets = self._targets(asset)
        if not targets:
            return ToolResult(tool=self.name, status="not_applicable", message="no HTTP(S) services detected")

        outfile = self.workdir / f"{asset.ip}.jsonl"
        target_file = self.workdir / f"{asset.ip}.targets.txt"
        target_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
        argv = [
            self.config.get("binary", "nuclei"),
            "-silent",
            "-jsonl",
            "-o",
            str(outfile),
            "-l",
            str(target_file),
        ]
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
        try:
            headers = api_headers(self.config)
        except ValueError as exc:
            return ToolResult(tool=self.name, status="failed", message=str(exc))
        for header in headers:
            argv += ["-H", header]
        proc = run_command(
            argv, timeout=self.timeout(float(self.config.get("timeout", 600)))
        )
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
                matched_at = item.get("matched-at") or item.get("host") or item.get("url")
                api_match = self._is_api_match(matched_at, api_targets)
                findings.append(Finding(
                    tool=self.name,
                    title=info.get("name") or item.get("template-id") or "Nuclei finding",
                    severity=severity,
                    category=self._category(matched_at, api_match),
                    port=self._matched_port(item),
                    protocol="tcp",
                    cve=[str(cve).upper() for cve in raw_cves if cve],
                    evidence={
                        "matched_at": matched_at,
                        "target_source": "kiterunner" if api_match else "service_discovery",
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
                raw_artifact=(
                    f"{outfile}, {target_file}" if outfile.exists() else str(target_file)
                ),
                message=proc.stderr.strip() or f"nuclei exited with code {proc.returncode}",
            )
        return ToolResult(
            tool=self.name,
            status="completed",
            findings=findings,
            raw_artifact=f"{outfile}, {target_file}",
            message=(
                f"scanned {len(targets)} network/URL target(s), including "
                f"{len(api_targets)} Kiterunner-discovered API endpoint(s)"
            ),
        )
