from __future__ import annotations

import os
import time
from pathlib import Path

import lxml.etree as LET

from polymer.models.schema import Asset, Finding, ToolResult
from polymer.scanners.base import Scanner


class GreenboneScanner(Scanner):
    """
    Greenbone / OpenVAS scanner integration for Polymer.

    Workflow:
        1. Connect to gvmd through Unix socket
        2. Authenticate using environment variables
        3. Create/reuse a Greenbone target
        4. Associate a valid Greenbone port list
        5. Create a scan task
        6. Start the task
        7. Poll until completion
        8. Retrieve the report
        9. Normalize Greenbone findings into Polymer Finding objects
    """

    name = "greenbone"

    DEFAULT_SOCKET = "/run/gvmd/gvmd.sock"

    # Greenbone "Full and fast"
    DEFAULT_SCAN_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"

    # Greenbone "OpenVAS Default"
    DEFAULT_SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"

    # Greenbone "All IANA assigned TCP"
    DEFAULT_PORT_LIST_ID = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"

    DEFAULT_TIMEOUT = 7200
    DEFAULT_POLL_INTERVAL = 15

    # ---------------------------------------------------------------------
    # Availability
    # ---------------------------------------------------------------------

    def available(self) -> bool:
        if not self.config.get("enabled", False):
            return False

        try:
            import gvm  # noqa: F401
        except ImportError:
            return False

        mode = self.config.get("mode", "socket")

        if mode != "socket":
            return False

        socket_path = Path(
            self.config.get(
                "socket",
                self.DEFAULT_SOCKET,
            )
        )

        return socket_path.exists()

    # ---------------------------------------------------------------------
    # Main scanner entry point
    # ---------------------------------------------------------------------

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

        # -----------------------------------------------------------------
        # Credentials
        # -----------------------------------------------------------------

        username_env = self.config.get(
            "username_env",
            "POLYMER_GVM_USERNAME",
        )

        password_env = self.config.get(
            "password_env",
            "POLYMER_GVM_PASSWORD",
        )

        username = os.getenv(username_env)
        password = os.getenv(password_env)

        if not username or not password:
            return ToolResult(
                tool=self.name,
                status="unavailable",
                message=(
                    "Greenbone credentials missing. "
                    f"Expected environment variables "
                    f"{username_env} and {password_env}"
                ),
            )

        # -----------------------------------------------------------------
        # Greenbone configuration
        # -----------------------------------------------------------------

        socket_path = self.config.get(
            "socket",
            self.DEFAULT_SOCKET,
        )

        config_id = self.config.get(
            "scan_config_id",
            self.DEFAULT_SCAN_CONFIG_ID,
        )

        scanner_id = self.config.get(
            "scanner_id",
            self.DEFAULT_SCANNER_ID,
        )

        port_list_id = self.config.get(
            "port_list_id",
            self.DEFAULT_PORT_LIST_ID,
        )

        timeout = self.timeout(
            float(
                self.config.get(
                    "task_timeout",
                    self.DEFAULT_TIMEOUT,
                )
            )
        )

        poll_interval = int(
            self.config.get(
                "poll_interval",
                self.DEFAULT_POLL_INTERVAL,
            )
        )

        self.workdir.mkdir(
            parents=True,
            exist_ok=True,
        )

        rawfile = self.workdir / f"{asset.ip}.xml"

        # -----------------------------------------------------------------
        # Connect to Greenbone
        # -----------------------------------------------------------------

        try:
            connection = UnixSocketConnection(
                path=socket_path,
                timeout=self.timeout(60),
            )

            transform = EtreeCheckCommandTransform()

            with GMP(
                connection=connection,
                transform=transform,
            ) as gmp:

                # ---------------------------------------------------------
                # Authentication
                # ---------------------------------------------------------

                gmp.authenticate(
                    username,
                    password,
                )

                # ---------------------------------------------------------
                # Target creation
                # ---------------------------------------------------------

                target_id = self._get_or_create_target(
                    gmp=gmp,
                    ip=asset.ip,
                    port_list_id=port_list_id,
                )

                # ---------------------------------------------------------
                # Task creation
                # ---------------------------------------------------------

                task_id = self._create_task(
                    gmp=gmp,
                    ip=asset.ip,
                    target_id=target_id,
                    config_id=config_id,
                    scanner_id=scanner_id,
                )

                # ---------------------------------------------------------
                # Start scan
                # ---------------------------------------------------------

                start_response = gmp.start_task(
                    task_id,
                )

                report_id = self._extract_report_id(
                    start_response
                )

                if not report_id:
                    response_xml = self._xml_to_string(
                        start_response
                    )

                    return ToolResult(
                        tool=self.name,
                        status="failed",
                        message=(
                            "Greenbone task started but no report ID "
                            f"was returned. Response: {response_xml}"
                        ),
                    )

                # ---------------------------------------------------------
                # Wait for task
                # ---------------------------------------------------------

                completed, final_status = self._wait_for_task(
                    gmp=gmp,
                    task_id=task_id,
                    timeout=timeout,
                    poll_interval=poll_interval,
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
                            f"Greenbone task timed out after {timeout}s "
                            f"(last status: {final_status})"
                        ),
                    )

                if final_status.lower() != "done":
                    return ToolResult(
                        tool=self.name,
                        status="failed",
                        message=(
                            "Greenbone scan finished with status: "
                            f"{final_status}"
                        ),
                    )

                # ---------------------------------------------------------
                # Retrieve report
                # ---------------------------------------------------------

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

                # ---------------------------------------------------------
                # Parse Greenbone findings
                # ---------------------------------------------------------

                findings = self._parse_report(
                    report=report,
                    report_id=report_id,
                    asset_ip=asset.ip,
                )

                return ToolResult(
                    tool=self.name,
                    status="completed",
                    findings=findings,
                    raw_artifact=str(rawfile),
                    message=(
                        f"Greenbone report {report_id}; "
                        f"{len(findings)} finding(s)"
                    ),
                )

        except GvmError as exc:
            return ToolResult(
                tool=self.name,
                status="failed",
                message=f"GVM error: {exc}",
            )

        except PermissionError as exc:
            return ToolResult(
                tool=self.name,
                status="failed",
                message=(
                    "Greenbone socket permission error: "
                    f"{exc}"
                ),
            )

        except OSError as exc:
            return ToolResult(
                tool=self.name,
                status="failed",
                message=(
                    "Greenbone socket/OS error: "
                    f"{exc}"
                ),
            )

        except Exception as exc:
            return ToolResult(
                tool=self.name,
                status="failed",
                message=(
                    "Unexpected Greenbone error: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

    # ---------------------------------------------------------------------
    # Greenbone target
    # ---------------------------------------------------------------------

    def _get_or_create_target(
        self,
        gmp,
        ip: str,
        port_list_id: str,
    ) -> str:
        """
        Get an existing Polymer Greenbone target or create one.

        A Greenbone target MUST contain either:
            - port_list_id
            - or port_range

        Polymer uses a Greenbone port list.
        """

        # Include part of the port-list UUID in the target name.
        # This prevents Polymer from accidentally reusing an old target
        # created with a different port list.
        target_name = (
            f"Polymer {ip} "
            f"[{port_list_id[:8]}]"
        )

        # -------------------------------------------------------------
        # Search for existing target
        # -------------------------------------------------------------

        existing = gmp.get_targets(
            filter_string=f'name="{target_name}"'
        )

        targets = existing.xpath(".//target")

        if targets:
            target_id = targets[0].get("id")

            if target_id:
                return target_id

        # -------------------------------------------------------------
        # Create target WITH PORT LIST
        # -------------------------------------------------------------

        response = gmp.create_target(
            name=target_name,
            hosts=[ip],
            port_list_id=port_list_id,
        )

        target_id = response.get("id")

        if not target_id:
            response_xml = self._xml_to_string(
                response
            )

            raise RuntimeError(
                "Failed to create Greenbone target "
                f"for {ip}. Response: {response_xml}"
            )

        return target_id

    # ---------------------------------------------------------------------
    # Greenbone task
    # ---------------------------------------------------------------------

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
            response_xml = self._xml_to_string(
                response
            )

            raise RuntimeError(
                "Failed to create Greenbone task "
                f"for {ip}. Response: {response_xml}"
            )

        return task_id

    # ---------------------------------------------------------------------
    # Report ID extraction
    # ---------------------------------------------------------------------

    @staticmethod
    def _extract_report_id(
        response,
    ) -> str | None:
        """
        Extract report ID from a Greenbone start_task response.

        Handles multiple python-gvm / GMP response layouts.
        """

        if response is None:
            return None

        # Common case:
        #
        # <start_task_response>
        #     <report_id>...</report_id>
        # </start_task_response>
        report_id = response.findtext(
            ".//report_id"
        )

        if report_id:
            return report_id.strip()

        # Some response representations may expose it as an attribute.
        report_id = response.get(
            "report_id"
        )

        if report_id:
            return report_id.strip()

        # Defensive fallback for unusual response structures.
        for child in response.iter():
            if child.tag.endswith("report_id"):
                if child.text:
                    return child.text.strip()

        return None

    # ---------------------------------------------------------------------
    # Task polling
    # ---------------------------------------------------------------------

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
            response = gmp.get_task(
                task_id
            )

            status = (
                response.findtext(
                    ".//task/status"
                )
                or response.findtext(
                    ".//status"
                )
                or "unknown"
            )

            status = status.strip()

            last_status = status

            normalized = status.lower()

            # Successful termination
            if normalized == "done":
                return True, status

            # Terminal failure states
            if normalized in {
                "stopped",
                "interrupted",
                "delete requested",
            }:
                return True, status

            time.sleep(
                min(poll_interval, max(0.0, deadline - time.time()))
            )

        return False, last_status

    # ---------------------------------------------------------------------
    # Report parser
    # ---------------------------------------------------------------------

    def _parse_report(
        self,
        report,
        report_id: str,
        asset_ip: str,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Greenbone report responses can contain different levels of
        # wrapping depending on GMP/python-gvm versions.

        results = report.xpath(
            ".//report/results/result"
        )

        if not results:
            results = report.xpath(
                ".//results/result"
            )

        if not results:
            results = report.xpath(
                ".//result"
            )

        for result in results:

            # ---------------------------------------------------------
            # Finding name
            # ---------------------------------------------------------

            title = (
                result.findtext("name")
                or "Greenbone finding"
            )

            # ---------------------------------------------------------
            # CVSS / severity
            # ---------------------------------------------------------

            severity_text = (
                result.findtext("severity")
                or "0"
            )

            try:
                score = float(
                    severity_text
                )
            except (TypeError, ValueError):
                score = 0.0

            severity = self._severity_from_cvss(
                score
            )

            # ---------------------------------------------------------
            # Port
            # ---------------------------------------------------------

            port_text = (
                result.findtext("port")
                or ""
            )

            port = self._parse_port(
                port_text
            )

            # ---------------------------------------------------------
            # Host
            # ---------------------------------------------------------

            host = (
                result.findtext("host")
                or asset_ip
            )

            # ---------------------------------------------------------
            # NVT information
            # ---------------------------------------------------------

            nvt = result.find("nvt")

            cves: list[str] = []

            oid = None
            family = None

            if nvt is not None:

                oid = nvt.get(
                    "oid"
                )

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

            # ---------------------------------------------------------
            # Additional Greenbone information
            # ---------------------------------------------------------

            description = (
                result.findtext(
                    "description"
                )
                or ""
            )

            threat = (
                result.findtext(
                    "threat"
                )
                or ""
            )

            qod_text = (
                result.findtext(
                    "qod/value"
                )
                or result.findtext(
                    "qod"
                )
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

            if qod_text:
                evidence["qod"] = qod_text

            # ---------------------------------------------------------
            # Polymer finding
            # ---------------------------------------------------------

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

    # ---------------------------------------------------------------------
    # Severity conversion
    # ---------------------------------------------------------------------

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

    # ---------------------------------------------------------------------
    # Port parser
    # ---------------------------------------------------------------------

    @staticmethod
    def _parse_port(
        value: str,
    ) -> int | None:
        if not value:
            return None

        try:
            first = value.split(
                "/",
                1,
            )[0]

            if first.isdigit():
                return int(first)

        except (TypeError, ValueError, AttributeError):
            pass

        return None

    # ---------------------------------------------------------------------
    # XML utility
    # ---------------------------------------------------------------------

    @staticmethod
    def _xml_to_string(
        element,
    ) -> str:
        """
        Safely convert a GMP XML response into a compact string for
        diagnostic error messages.
        """

        if element is None:
            return "<empty response>"

        try:
            return LET.tostring(
                element,
                encoding="unicode",
                pretty_print=False,
            )

        except Exception:
            return str(element)
