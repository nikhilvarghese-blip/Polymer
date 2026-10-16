from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import shutil
from urllib.parse import urlsplit

from polymer.core.http_headers import api_headers
from polymer.core.services import web_endpoints
from polymer.core.timing import ScanDeadlineReached
from polymer.models.schema import Asset, Finding, ToolResult
from polymer.scanners.base import Scanner
from polymer.utils.command import CommandExecutionError, run_command


class KiterunnerScanner(Scanner):
    """Discover contextual API routes before Nuclei vulnerability scanning."""

    name = "kiterunner"

    def available(self) -> bool:
        return shutil.which(self.config.get("binary", "kr")) is not None

    @staticmethod
    def _endpoint(item: dict, asset_ip: str) -> tuple[str, str, int, list[dict]] | None:
        target = item.get("target")
        path = item.get("path")
        method = item.get("method")
        responses = item.get("responses")
        if not all(isinstance(value, str) and value for value in (target, path, method)):
            return None
        if not isinstance(responses, list) or not responses:
            return None

        url = f"{target.rstrip('/')}/{path.lstrip('/')}"
        try:
            parsed = urlsplit(url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                return None
            if ipaddress.ip_address(parsed.hostname) != ipaddress.ip_address(asset_ip):
                return None
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except (ValueError, TypeError):
            return None

        normalized_responses = [entry for entry in responses if isinstance(entry, dict)]
        if not normalized_responses:
            return None
        try:
            status_code = int(normalized_responses[0].get("sc", 0))
        except (TypeError, ValueError):
            status_code = 0
        return url, method.upper(), status_code, normalized_responses

    def run(self, asset: Asset) -> ToolResult:
        if asset.status != "up":
            return ToolResult(
                tool=self.name,
                status="skipped",
                message="asset is not up",
            )
        if not self.available():
            binary = self.config.get("binary", "kr")
            return ToolResult(
                tool=self.name,
                status="unavailable",
                message=f"Kiterunner executable {binary!r} not found",
            )
        endpoints = web_endpoints(asset)
        if not endpoints:
            return ToolResult(
                tool=self.name,
                status="not_applicable",
                message="no HTTP(S) services detected",
            )

        try:
            wordlist = Path(
                self.config.get(
                    "wordlist", "/usr/local/share/kiterunner/routes-small.kite"
                )
            )
        except TypeError:
            return ToolResult(
                tool=self.name,
                status="failed",
                message="Kiterunner wordlist must be a filesystem path",
            )
        if not wordlist.is_file():
            return ToolResult(
                tool=self.name,
                status="unavailable",
                message=f"Kiterunner wordlist not found: {wordlist}",
            )

        try:
            max_connections = int(self.config.get("max_connections_per_host", 3))
            max_redirects = int(self.config.get("max_redirects", 2))
            max_endpoints = int(self.config.get("max_endpoints", 2000))
            command_timeout = float(self.config.get("timeout", 900))
        except (TypeError, ValueError):
            return ToolResult(
                tool=self.name,
                status="failed",
                message="Kiterunner numeric limits must contain valid numbers",
            )
        request_timeout = str(self.config.get("request_timeout", "3s"))
        if max_connections <= 0 or max_redirects < 0 or max_endpoints <= 0:
            return ToolResult(
                tool=self.name,
                status="failed",
                message="Kiterunner connection, redirect and endpoint limits are invalid",
            )

        try:
            headers = api_headers(self.config)
        except ValueError as exc:
            return ToolResult(tool=self.name, status="failed", message=str(exc))
        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        command_errors: list[str] = []
        completed_commands = 0
        binary = self.config.get("binary", "kr")
        force_method = self.config.get("force_method")
        if force_method is not None and str(force_method).upper() not in {
            "GET", "POST", "PUT", "PATCH", "DELETE", "TRACE"
        }:
            return ToolResult(
                tool=self.name,
                status="failed",
                message="Kiterunner force_method is not a supported HTTP method",
            )
        fail_status_codes = self.config.get("fail_status_codes", [404])
        if (
            not isinstance(fail_status_codes, list)
            or not fail_status_codes
            or not all(isinstance(code, int) for code in fail_status_codes)
        ):
            return ToolResult(
                tool=self.name,
                status="failed",
                message="Kiterunner fail_status_codes must be a non-empty list of integers",
            )

        for target, _port in endpoints:
            argv = [
                binary,
                "scan",
                target,
                "-w",
                str(wordlist),
                "-x",
                str(max_connections),
                "-j",
                "1",
                "--timeout",
                request_timeout,
                "--max-redirects",
                str(max_redirects),
                "--fail-status-codes",
                ",".join(str(code) for code in fail_status_codes),
                "--progress=false",
                "--output",
                "json",
                "--quiet",
            ]
            for header in headers:
                argv.extend(["--header", header])
            if force_method is not None:
                argv.extend(["--force-method", str(force_method).upper()])
            try:
                proc = run_command(
                    argv,
                    timeout=self.timeout(command_timeout),
                )
            except (CommandExecutionError, ScanDeadlineReached) as exc:
                command_errors.append(f"{target}: {exc}")
                if isinstance(exc, ScanDeadlineReached):
                    break
                continue
            completed_commands += 1
            if proc.stdout:
                stdout_parts.append(proc.stdout)
            if proc.stderr:
                stderr_parts.append(f"[{target}]\n{proc.stderr}")
            if proc.returncode != 0:
                command_errors.append(
                    f"{target}: {proc.stderr.strip() or f'exited with code {proc.returncode}'}"
                )

        rawfile = self.workdir / f"{asset.ip}.jsonl"
        stderr_file = self.workdir / f"{asset.ip}.stderr.log"
        raw_text = "\n".join(part.rstrip("\n") for part in stdout_parts)
        rawfile.write_text(raw_text + ("\n" if raw_text else ""), encoding="utf-8")
        if stderr_parts:
            stderr_file.write_text("\n".join(stderr_parts), encoding="utf-8")

        findings: list[Finding] = []
        parse_errors = 0
        seen: set[tuple[str, str]] = set()
        truncated = False
        for line in raw_text.splitlines():
            line = line.strip().lstrip("\r")
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                parse_errors += 1
                continue
            if not isinstance(item, dict):
                parse_errors += 1
                continue
            endpoint = self._endpoint(item, asset.ip)
            if endpoint is None:
                parse_errors += 1
                continue
            url, method, status_code, responses = endpoint
            key = (method, url)
            if key in seen:
                continue
            seen.add(key)
            if len(findings) >= max_endpoints:
                truncated = True
                continue
            port = urlsplit(url).port or (443 if url.startswith("https://") else 80)
            description = (
                f"Kiterunner reported HTTP status {status_code} for "
                f"{method} {url}."
                if status_code
                else f"Kiterunner reported the API route {method} {url}."
            )
            findings.append(
                Finding(
                    tool=self.name,
                    title=f"API endpoint discovered: {method} {urlsplit(url).path}",
                    severity="info",
                    category="api_discovery",
                    port=port,
                    protocol="tcp",
                    check_id=f"{method} {urlsplit(url).path}",
                    evidence={
                        "description": description,
                        "url": url,
                        "method": method,
                        "status_code": status_code,
                        "response_chain": responses,
                    },
                )
            )

        messages = list(command_errors)
        if parse_errors:
            messages.append(f"ignored {parse_errors} malformed or out-of-scope result line(s)")
        if truncated:
            messages.append(f"endpoint results truncated at configured limit {max_endpoints}")
        if headers:
            messages.append(f"used {len(headers)} API authentication/header value(s) from environment")
        message = "; ".join(messages) or f"discovered {len(findings)} API endpoint(s)"
        status = "failed" if command_errors or completed_commands == 0 else "completed"
        artifacts = [str(rawfile)]
        if stderr_parts:
            artifacts.append(str(stderr_file))
        return ToolResult(
            tool=self.name,
            status=status,
            findings=findings,
            raw_artifact=", ".join(artifacts),
            message=message,
        )
