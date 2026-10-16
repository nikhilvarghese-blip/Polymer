from __future__ import annotations

import json
import re
import shutil
from collections.abc import Iterator
from typing import Any

from polymer.core.services import web_endpoints
from polymer.models.schema import Asset, Finding, ToolResult
from polymer.scanners.base import Scanner
from polymer.utils.command import CommandExecutionError, run_command


CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _identifier(value: object) -> str | None:
    if isinstance(value, str):
        return value.strip() or None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return None


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [
            item.strip()
            for item in value
            if isinstance(item, str) and item.strip()
        ]
    return []


class NiktoScanner(Scanner):
    name = "nikto"

    def available(self) -> bool:
        return shutil.which(self.config.get("binary", "nikto")) is not None

    @staticmethod
    def _port(value: object, fallback: int) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return fallback
        return parsed if 0 < parsed <= 65535 else fallback

    @staticmethod
    def _records(value: object, fallback_port: int) -> Iterator[tuple[dict, int]]:
        """Read legacy and Nikto 2.6 multi-host JSON report layouts."""
        if isinstance(value, list):
            for child in value:
                yield from NiktoScanner._records(child, fallback_port)
            return
        if not isinstance(value, dict):
            return

        port = NiktoScanner._port(value.get("port"), fallback_port)
        collections: list[object] = []
        for key in ("vulnerabilities", "items"):
            if key in value:
                collections.append(value.get(key))

        if collections:
            for collection in collections:
                if isinstance(collection, dict):
                    collection = list(collection.values())
                if isinstance(collection, list):
                    for record in collection:
                        if isinstance(record, dict):
                            yield record, port
            return

        # Some legacy output places finding records directly in the root list.
        if any(key in value for key in ("msg", "message", "description")):
            yield value, port

    @staticmethod
    def _recognized_report(value: object) -> bool:
        if isinstance(value, dict):
            return any(
                key in value
                for key in (
                    "vulnerabilities",
                    "items",
                    "msg",
                    "message",
                    "description",
                )
            )
        if isinstance(value, list) and value:
            return all(
                isinstance(item, dict) and NiktoScanner._recognized_report(item)
                for item in value
            )
        return False

    @staticmethod
    def _cves(references: list[str]) -> list[str]:
        values = [
            match.upper()
            for reference in references
            for match in CVE_PATTERN.findall(reference)
        ]
        return list(dict.fromkeys(values))

    @staticmethod
    def _remediation(record: dict[str, Any]) -> str | None:
        for key in ("remediation", "recommendation", "solution"):
            value = _text(record.get(key))
            if value:
                return value
        return None

    def run(self, asset: Asset) -> ToolResult:
        if not self.available():
            return ToolResult(
                tool=self.name,
                status="unavailable",
                message="nikto not found",
            )
        endpoints = web_endpoints(asset)
        if not endpoints:
            return ToolResult(
                tool=self.name,
                status="not_applicable",
                message="no HTTP(S) service detected",
            )

        findings: list[Finding] = []
        artifacts: list[str] = []
        errors: list[str] = []
        successful = 0
        incomplete = False

        for url, port in endpoints:
            outfile = self.workdir / f"{asset.ip}_{port}.json"
            cmd = [
                self.config.get("binary", "nikto"),
                "-host",
                url,
                "-nointeractive",
                "-Format",
                "json",
                "-output",
                str(outfile),
            ]
            tuning = self.config.get("tuning")
            if tuning:
                cmd += ["-Tuning", str(tuning)]
            try:
                proc = run_command(
                    cmd,
                    timeout=self.timeout(float(self.config.get("timeout", 900))),
                )
            except CommandExecutionError as exc:
                errors.append(f"{url}: {exc}")
                incomplete = True
                continue
            if not outfile.exists():
                detail = proc.stderr.strip() or (
                    f"no JSON artifact (exit code {proc.returncode})"
                )
                errors.append(f"{url}: {detail}")
                incomplete = True
                continue
            artifacts.append(str(outfile))
            try:
                data = json.loads(outfile.read_text(errors="replace"))
            except json.JSONDecodeError as exc:
                errors.append(f"{url}: invalid JSON: {exc}")
                incomplete = True
                continue

            if not self._recognized_report(data):
                errors.append(f"{url}: unsupported or empty Nikto JSON report layout")
                incomplete = True
                continue

            successful += 1
            if proc.returncode != 0:
                errors.append(
                    f"{url}: {proc.stderr.strip() or f'nikto exited with code {proc.returncode}'}"
                )
                incomplete = True

            for record, report_port in self._records(data, port):
                description = next(
                    (
                        value
                        for key in ("msg", "message", "description")
                        if (value := _text(record.get(key))) is not None
                    ),
                    None,
                )
                if description is None:
                    continue
                check_id = _identifier(
                    record.get("id")
                    if record.get("id") is not None
                    else record.get("nikto_id")
                )
                references = _strings(record.get("references")) or _strings(
                    record.get("refs")
                )
                evidence: dict[str, Any] = {"description": description}
                if check_id:
                    evidence["nikto_id"] = check_id
                for key in ("url", "uri", "method", "OSVDB"):
                    value = _identifier(record.get(key))
                    if value:
                        evidence[key] = value
                if references:
                    evidence["references"] = references

                findings.append(
                    Finding(
                        tool=self.name,
                        title=description,
                        severity="unknown",
                        category="web",
                        port=report_port,
                        protocol="tcp",
                        cve=self._cves(references),
                        check_id=check_id,
                        evidence=evidence,
                        remediation=self._remediation(record),
                    )
                )

        status = "completed" if successful and not incomplete else "failed"
        return ToolResult(
            tool=self.name,
            status=status,
            findings=findings,
            raw_artifact=", ".join(artifacts) or None,
            message="; ".join(errors) or None,
        )
