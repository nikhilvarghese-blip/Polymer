from __future__ import annotations

import json
import re
import shutil
from collections.abc import Iterator
from typing import Any

from polymer.core.services import tls_ports
from polymer.models.schema import Asset, Finding, ToolResult
from polymer.scanners.base import Scanner
from polymer.utils.command import CommandExecutionError, run_command


ISSUE_SEVERITIES = {"critical", "high", "medium", "low"}

CHECK_LABELS = {
    "breach": "BREACH compression exposure",
    "cert_trust": "certificate trust validation",
    "cert_trust_wildcard": "certificate trust via wildcard",
    "dns_caarecord": "DNS CAA record",
    "fs_kems": "forward-secrecy key encapsulation mechanisms",
    "fs_tls12_sig_algs": "TLS 1.2 signature algorithms",
    "ocsp_stapling": "OCSP stapling",
    "overall_grade": "overall TLS/SSL grade",
}

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _text(value: object) -> str | None:
    """Return scanner text without converting objects into report prose."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _string_values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [
            item.strip()
            for item in value
            if isinstance(item, str) and item.strip()
        ]
    return []


class TestSSLScanner(Scanner):
    name = "testssl"

    def available(self) -> bool:
        return shutil.which(self.config.get("binary", "testssl")) is not None

    @staticmethod
    def _result_items(value: object) -> Iterator[dict[str, Any]]:
        """Support testssl.sh flat and pretty JSON without guessing at values."""
        if isinstance(value, list):
            for child in value:
                yield from TestSSLScanner._result_items(child)
            return
        if not isinstance(value, dict):
            return

        if all(key in value for key in ("id", "severity", "finding")):
            yield value
        for child in value.values():
            if isinstance(child, (dict, list)):
                yield from TestSSLScanner._result_items(child)

    @staticmethod
    def _title(check_id: str) -> str:
        label = CHECK_LABELS.get(check_id.lower())
        if label is None:
            label = re.sub(r"[_-]+", " ", check_id).strip()
        return f"testssl.sh check: {label}"

    @staticmethod
    def _cves(value: object) -> list[str]:
        cves: list[str] = []
        for entry in _string_values(value):
            cves.extend(match.upper() for match in CVE_PATTERN.findall(entry))
        return list(dict.fromkeys(cves))

    @staticmethod
    def _remediation(item: dict[str, Any]) -> str | None:
        for key in ("remediation", "recommendation", "solution"):
            value = _text(item.get(key))
            if value:
                return value
        return None

    def run(self, asset: Asset) -> ToolResult:
        if not self.available():
            return ToolResult(
                tool=self.name,
                status="unavailable",
                message="testssl.sh not found",
            )
        ports = tls_ports(asset)
        if not ports:
            return ToolResult(
                tool=self.name,
                status="not_applicable",
                message="no TLS service detected",
            )

        findings: list[Finding] = []
        artifacts: list[str] = []
        errors: list[str] = []
        scanner_notices: list[str] = []
        successful = 0
        incomplete = False
        seen: set[tuple[int, str, str, str]] = set()

        for port in ports:
            outfile = self.workdir / f"{asset.ip}_{port}.json"
            cmd = [
                self.config.get("binary", "testssl"),
                "--quiet",
                "--warnings",
                "batch",
                "--jsonfile",
                str(outfile),
                f"{asset.ip}:{port}",
            ]
            try:
                proc = run_command(
                    cmd,
                    timeout=self.timeout(float(self.config.get("timeout", 600))),
                )
            except CommandExecutionError as exc:
                errors.append(f"{asset.ip}:{port}: {exc}")
                incomplete = True
                continue
            if not outfile.exists():
                detail = proc.stderr.strip() or (
                    f"no JSON artifact (exit code {proc.returncode})"
                )
                errors.append(f"{asset.ip}:{port}: {detail}")
                incomplete = True
                continue
            artifacts.append(str(outfile))
            try:
                data = json.loads(outfile.read_text(errors="replace"))
            except json.JSONDecodeError as exc:
                errors.append(f"{asset.ip}:{port}: invalid JSON: {exc}")
                incomplete = True
                continue

            successful += 1
            if proc.returncode != 0:
                errors.append(
                    f"{asset.ip}:{port}: "
                    f"{proc.stderr.strip() or f'testssl.sh exited with code {proc.returncode}'}"
                )
                incomplete = True

            result_item_count = 0
            for item in self._result_items(data):
                result_item_count += 1
                source_severity = _text(item.get("severity"))
                if source_severity is None:
                    continue
                source_severity = source_severity.lower()
                check_id = _text(item.get("id"))
                description = _text(item.get("finding"))

                # WARN and FATAL describe scanner/check execution problems in
                # testssl.sh, not target vulnerabilities.
                if source_severity in {"warn", "fatal"}:
                    incomplete = True
                    detail = description or "no scanner detail supplied"
                    scanner_notices.append(
                        f"{asset.ip}:{port} {source_severity.upper()}: {detail}"
                    )
                    continue
                if source_severity not in ISSUE_SEVERITIES:
                    continue
                if check_id is None or description is None:
                    continue

                duplicate_key = (port, check_id, description, source_severity)
                if duplicate_key in seen:
                    continue
                seen.add(duplicate_key)

                evidence: dict[str, Any] = {
                    "description": description,
                    "finding": description,
                    "testssl_id": check_id,
                    "testssl_severity": source_severity.upper(),
                }
                for key in ("cwe", "hint", "ip", "fqdn"):
                    values = _string_values(item.get(key))
                    if values:
                        evidence[key] = values[0] if len(values) == 1 else values

                findings.append(
                    Finding(
                        tool=self.name,
                        title=self._title(check_id),
                        severity=source_severity,
                        category="tls",
                        port=port,
                        protocol="tcp",
                        cve=self._cves(item.get("cve")),
                        check_id=check_id,
                        evidence=evidence,
                        remediation=self._remediation(item),
                    )
                )
            if result_item_count == 0:
                errors.append(
                    f"{asset.ip}:{port}: unsupported or empty testssl.sh JSON report layout"
                )
                incomplete = True

        messages = [*errors, *scanner_notices]
        status = "completed" if successful and not incomplete else "failed"
        return ToolResult(
            tool=self.name,
            status=status,
            findings=findings,
            raw_artifact=", ".join(artifacts) or None,
            message="; ".join(messages) or None,
        )
