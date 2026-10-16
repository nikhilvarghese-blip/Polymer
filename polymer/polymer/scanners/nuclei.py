from __future__ import annotations

import ipaddress
import json
import re
import shutil
from urllib.parse import urlsplit

from polymer.core.http_headers import api_headers
from polymer.core.services import web_endpoints
from polymer.models.schema import Asset, Finding, ToolResult
from polymer.scanners.base import Scanner
from polymer.utils.command import CommandExecutionError, run_command


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

    @staticmethod
    def _matched_protocol(
        item: dict, asset: Asset, port: int | None
    ) -> str | None:
        raw_protocol = item.get("protocol")
        if isinstance(raw_protocol, str):
            protocol = raw_protocol.strip().lower()
            if protocol in {"tcp", "udp", "icmp", "sctp"}:
                return protocol

        matched = item.get("matched-at") or item.get("host") or item.get("url")
        if isinstance(matched, str):
            try:
                if urlsplit(matched).scheme in {"http", "https"}:
                    return "tcp"
            except ValueError:
                pass

        if port is not None:
            protocols = {
                service.protocol
                for service in asset.services
                if service.port == port and service.state == "open"
            }
            if len(protocols) == 1:
                return next(iter(protocols))
        return None

    @staticmethod
    def _cves(value: object) -> list[str]:
        if isinstance(value, str):
            values = [value]
        elif isinstance(value, list):
            values = [item for item in value if isinstance(item, str)]
        else:
            return []
        return list(
            dict.fromkeys(
                match.upper()
                for entry in values
                for match in re.findall(
                    r"CVE-\d{4}-\d{4,}", entry, flags=re.IGNORECASE
                )
            )
        )

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
        try:
            proc = run_command(
                argv, timeout=self.timeout(float(self.config.get("timeout", 600)))
            )
        except CommandExecutionError as exc:
            return ToolResult(
                tool=self.name,
                status="failed",
                raw_artifact=str(target_file),
                message=str(exc),
            )
        if not outfile.exists():
            return ToolResult(
                tool=self.name,
                status="failed",
                raw_artifact=str(target_file),
                message=proc.stderr.strip() or "nuclei produced no JSONL artifact",
            )

        findings: list[Finding] = []
        parse_errors = 0
        if outfile.exists():
            for line in outfile.read_text(errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    parse_errors += 1
                    continue
                if not isinstance(item, dict):
                    parse_errors += 1
                    continue
                info = item.get("info", {})
                if not isinstance(info, dict):
                    info = {}
                classification = info.get("classification", {})
                if not isinstance(classification, dict):
                    classification = {}
                raw_severity = info.get("severity")
                severity = (
                    raw_severity.strip().lower()
                    if isinstance(raw_severity, str)
                    else "unknown"
                )
                if severity not in {"critical", "high", "medium", "low", "info"}:
                    severity = "unknown"
                description = info.get("description")
                remediation = info.get("remediation")
                matched_at = item.get("matched-at") or item.get("host") or item.get("url")
                api_match = self._is_api_match(matched_at, api_targets)
                template_id = item.get("template-id")
                if not isinstance(template_id, str) or not template_id.strip():
                    template_id = None
                else:
                    template_id = template_id.strip()
                name = info.get("name")
                if not isinstance(name, str) or not name.strip():
                    name = template_id
                else:
                    name = name.strip()
                if name is None:
                    parse_errors += 1
                    continue
                port = self._matched_port(item)
                references = info.get("reference")
                if isinstance(references, str):
                    references = [references.strip()] if references.strip() else []
                elif isinstance(references, list):
                    references = [
                        value.strip()
                        for value in references
                        if isinstance(value, str) and value.strip()
                    ]
                else:
                    references = []
                findings.append(Finding(
                    tool=self.name,
                    title=name,
                    severity=severity,
                    category=self._category(matched_at, api_match),
                    port=port,
                    protocol=self._matched_protocol(item, asset, port),
                    cve=self._cves(classification.get("cve-id")),
                    check_id=template_id,
                    evidence={
                        "matched_at": matched_at,
                        "target_source": "kiterunner" if api_match else "service_discovery",
                        "template_id": template_id,
                        "description": description if isinstance(description, str) else None,
                        "references": references,
                        "nuclei_severity": raw_severity if isinstance(raw_severity, str) else None,
                    },
                    remediation=(
                        remediation if isinstance(remediation, str) else None
                    ),
                ))
        if proc.returncode != 0 or parse_errors:
            messages = []
            if proc.returncode != 0:
                messages.append(
                    proc.stderr.strip()
                    or f"nuclei exited with code {proc.returncode}"
                )
            if parse_errors:
                messages.append(
                    f"ignored {parse_errors} malformed Nuclei JSONL record(s)"
                )
            return ToolResult(
                tool=self.name,
                status="failed",
                findings=findings,
                raw_artifact=(
                    f"{outfile}, {target_file}" if outfile.exists() else str(target_file)
                ),
                message="; ".join(messages),
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
