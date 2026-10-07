from __future__ import annotations

import os
import time
from pathlib import Path

from polymer.models.schema import Asset, Finding, ToolResult
from polymer.scanners.base import Scanner


class GreenboneScanner(Scanner):
    name = "greenbone"

    def available(self) -> bool:
        if not self.config.get("enabled", False):
            return False

        try:
            import gvm  # noqa: F401
        except ImportError:
            return False

        mode = self.config.get("mode", "socket")

        if mode == "socket":
            socket_path = Path(
                self.config.get(
                    "socket",
                    "/run/gvmd/gvmd.sock",
                )
            )
            return socket_path.exists()

        return False

    def run(self, asset: Asset) -> ToolResult:
        if not self.available():
            return ToolResult(
                tool=self.name,
                status="unavailable",
                message=(
                    "Greenbone is disabled, python-gvm is missing, "
                    "or the gvmd socket is unavailable"
                ),
            )

        if asset.status != "up":
            return ToolResult(
                tool=self.name,
                status="skipped",
                message="asset is not up",
            )

        from gvm.connections import UnixSocketConnection
        from gvm.errors import GvmError
        from gvm.protocols.gmp import GMP
        from gvm.transforms import EtreeCheckCommandTransform
        import lxml.etree as LET

        username = os.getenv(
            self.config.get(
                "username_env",
                "POLYMER_GVM_USERNAME",
            )
        )

        password = os.getenv(
            self.config.get(
                "password_env",
                "POLYMER_GVM_PASSWORD",
            )
        )

        if not username or not password:
            return ToolResult(
                tool=self.name,
                status="unavailable",
                message="Greenbone credentials missing",
            )

        socket_path = self.config.get(
            "socket",
            "/run/gvmd/gvmd.sock",
        )

        config_id = self.config.get(
            "scan_config_id",
            "daba56c8-73ec-11df-a475-002264764cea",
        )

        scanner_id = self.config.get(
            "scanner_id",
            "08b69003-5fc2-4037-a479-93b440211c73",
        )

        timeout = int(
            self.config.get("task_timeout", 7200)
        )

        poll_interval = int(
            self.config.get("poll_interval", 15)
        )

        rawfile = self.workdir / f"{asset.ip}.xml"

        try:
            connection = UnixSocketConnection(
                path=socket_path,
                timeout=60,
            )

            transform = EtreeCheckCommandTransform()

            with GMP(
                connection=connection,
                transform=transform,
            ) as gmp:
                gmp.authenticate(
                    username,
                    password,
                )

                target_id = self._get_or_create_target(
                    gmp,
                    asset.ip,
                )

                task_id = self._create_task(
                    gmp,
                    asset.ip,
                    target_id,
                    config_id,
                    scanner_id,
                )

                start_response = gmp.start_task(task_id)

                report_id = start_response.findtext(
                    "report_id"
                )

                if not report_id:
                    return ToolResult(
                        tool=self.name,
                        status="failed",
                        message=(
                            "Greenbone did not return "
                            "a report ID"
                        ),
                    )

                completed, final_status = (
                    self._wait_for_task(
                        gmp,
                        task_id,
                        timeout,
                        poll_interval,
                    )
                )

                if not completed:
                    try:
                        gmp.stop_task(task_id)
                    except Exception:
                        pass

                    return ToolResult(
                        tool=self.name,
                        status="failed",
                        message=(
                            f"Greenbone task timed out "
                            f"after {timeout}s "
                            f"(last status: {final_status})"
                        ),
                    )

                if final_status.lower() != "done":
                    return ToolResult(
                        tool=self.name,
                        status="failed",
                        message=(
                            "Greenbone scan finished "
                            f"with status: {final_status}"
                        ),
                    )

                report = gmp.get_report(
                    report_id=report_id,
                    ignore_pagination=True,
                    details=True,
                )

                rawfile.write_bytes(
                    LET.tostring(
                        report,
                        pretty_print=True,
                        encoding="utf-8",
                    )
                )

                findings = self._parse_report(
                    report,
                    report_id,
                    asset.ip,
                )

                return ToolResult(
                    tool=self.name,
                    status="completed",
                    findings=findings,
                    raw_artifact=str(rawfile),
                    message=f"report {report_id}",
                )

        except GvmError as exc:
            return ToolResult(
                tool=self.name,
                status="failed",
                message=f"GVM error: {exc}",
            )

        except OSError as exc:
            return ToolResult(
                tool=self.name,
                status="failed",
                message=f"Greenbone socket/OS error: {exc}",
            )

        except Exception as exc:
            return ToolResult(
                tool=self.name,
                status="failed",
                message=(
                    f"Unexpected Greenbone error: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

    def _get_or_create_target(
        self,
        gmp,
        ip: str,
    ) -> str:
        target_name = f"Polymer {ip}"

        existing = gmp.get_targets(
            filter_string=f'name="{target_name}"'
        )

        targets = existing.xpath("target")

        if targets:
            target_id = targets[0].get("id")

            if target_id:
                return target_id

        response = gmp.create_target(
            name=target_name,
            hosts=[ip],
        )

        target_id = response.get("id")

        if not target_id:
            raise RuntimeError(
                f"Failed to create Greenbone target for {ip}"
            )

        return target_id

    def _create_task(
        self,
        gmp,
        ip: str,
        target_id: str,
        config_id: str,
        scanner_id: str,
    ) -> str:
        task_name = (
            f"Polymer scan {ip} "
            f"{int(time.time())}"
        )

        response = gmp.create_task(
            name=task_name,
            config_id=config_id,
            target_id=target_id,
            scanner_id=scanner_id,
        )

        task_id = response.get("id")

        if not task_id:
            raise RuntimeError(
                f"Failed to create Greenbone task for {ip}"
            )

        return task_id

    def _wait_for_task(
        self,
        gmp,
        task_id: str,
        timeout: int,
        poll_interval: int,
    ) -> tuple[bool, str]:
        deadline = time.time() + timeout
        last_status = "unknown"

        while time.time() < deadline:
            response = gmp.get_task(task_id)

            status = (
                response.findtext(".//status")
                or "unknown"
            )

            last_status = status

            normalized = status.lower()

            if normalized == "done":
                return True, status

            if normalized in {
                "stopped",
                "interrupted",
                "delete requested",
            }:
                return True, status

            time.sleep(poll_interval)

        return False, last_status

    def _parse_report(
        self,
        report,
        report_id: str,
        asset_ip: str,
    ) -> list[Finding]:
        findings = []

        results = report.xpath(
            ".//report/results/result"
        )

        if not results:
            results = report.xpath(
                ".//results/result"
            )

        for result in results:
            title = (
                result.findtext("name")
                or "Greenbone finding"
            )

            severity_text = (
                result.findtext("severity")
                or "0"
            )

            try:
                score = float(severity_text)
            except ValueError:
                score = 0.0

            severity = self._severity_from_cvss(
                score
            )

            port_text = (
                result.findtext("port")
                or ""
            )

            port = self._parse_port(
                port_text
            )

            host = (
                result.findtext("host")
                or asset_ip
            )

            nvt = result.find("nvt")

            cves = []
            oid = None
            family = None

            if nvt is not None:
                oid = nvt.get("oid")

                family = nvt.findtext(
                    "family"
                )

                cve_text = (
                    nvt.findtext("cve")
                    or ""
                )

                cves = [
                    cve.strip()
                    for cve in cve_text.split(",")
                    if cve.strip()
                    and cve.strip().upper()
                    != "NOCVE"
                ]

            description = (
                result.findtext("description")
                or ""
            )

            threat = (
                result.findtext("threat")
                or ""
            )

            qos_text = (
                result.findtext("qod/value")
                or result.findtext("qod")
                or ""
            )

            evidence = {
                "cvss": score,
                "report_id": report_id,
                "host": host,
                "greenbone_port": port_text,
                "threat": threat,
                "description": description,
            }

            if oid:
                evidence["nvt_oid"] = oid

            if family:
                evidence["nvt_family"] = family

            if qos_text:
                evidence["qod"] = qos_text

            findings.append(
                Finding(
                    tool=self.name,
                    title=title,
                    severity=severity,
                    category="vulnerability",
                    port=port,
                    cve=cves,
                    evidence=evidence,
                )
            )

        return findings

    @staticmethod
    def _severity_from_cvss(
        score: float,
    ) -> str:
        if score >= 9.0:
            return "critical"

        if score >= 7.0:
            return "high"

        if score >= 4.0:
            return "medium"

        if score > 0:
            return "low"

        return "info"

    @staticmethod
    def _parse_port(
        value: str,
    ) -> int | None:
        if not value:
            return None

        try:
            first = value.split("/")[0]

            if first.isdigit():
                return int(first)

        except Exception:
            pass

        return None
