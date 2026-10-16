from __future__ import annotations

import json
import shutil
from typing import Any

from polymer.core.services import SMB_PORTS, open_services, smb_present
from polymer.models.schema import Asset, Finding, ToolResult
from polymer.scanners.base import Scanner
from polymer.utils.command import CommandExecutionError, run_command


class Enum4LinuxScanner(Scanner):
    name = "enum4linux"

    def available(self) -> bool:
        return shutil.which(self.config.get("binary", "enum4linux-ng")) is not None

    @staticmethod
    def _smb_port(asset: Asset) -> int | None:
        ports = [
            service.port
            for service in open_services(asset)
            if service.port in SMB_PORTS
            or (service.name or "").lower() in {"microsoft-ds", "netbios-ssn", "smb"}
        ]
        if 445 in ports:
            return 445
        return ports[0] if ports else None

    @classmethod
    def _findings(cls, data: dict[str, Any], port: int | None) -> list[Finding]:
        """Use exact enum4linux-ng result keys; never infer from JSON text."""
        findings: list[Finding] = []
        dialects = data.get("smb_dialects")
        if isinstance(dialects, dict):
            signing_required = dialects.get("SMB signing required")
            if signing_required is False:
                findings.append(
                    Finding(
                        tool=cls.name,
                        title="SMB signing is not required",
                        severity="unknown",
                        category="smb",
                        port=port,
                        protocol="tcp",
                        check_id="smb-signing-required",
                        evidence={
                            "description": (
                                "enum4linux-ng reported 'SMB signing required' "
                                "as false."
                            ),
                            "smb_signing_required": False,
                            "preferred_dialect": dialects.get("Preferred dialect"),
                        },
                    )
                )
            if dialects.get("SMB1 only") is True:
                findings.append(
                    Finding(
                        tool=cls.name,
                        title="SMBv1 is the only supported SMB dialect",
                        severity="unknown",
                        category="smb",
                        port=port,
                        protocol="tcp",
                        check_id="smb1-only",
                        evidence={
                            "description": (
                                "enum4linux-ng reported 'SMB1 only' as true."
                            ),
                            "smb1_only": True,
                            "supported_dialects": dialects.get(
                                "Supported dialects"
                            ),
                        },
                    )
                )

        sessions = data.get("sessions")
        if isinstance(sessions, dict):
            for key, title, check_id in (
                ("null", "Anonymous SMB null session was accepted", "null-session"),
                ("guest", "SMB guest session was accepted", "guest-session"),
            ):
                if sessions.get(key) is not True:
                    continue
                findings.append(
                    Finding(
                        tool=cls.name,
                        title=title,
                        severity="unknown",
                        category="smb",
                        port=port,
                        protocol="tcp",
                        check_id=check_id,
                        evidence={
                            "description": (
                                f"enum4linux-ng reported the '{key}' session result "
                                "as true."
                            ),
                            "session_type": key,
                            "session_accepted": True,
                        },
                    )
                )
        return findings

    def run(self, asset: Asset) -> ToolResult:
        if not self.available():
            return ToolResult(
                tool=self.name,
                status="unavailable",
                message="enum4linux-ng not found",
            )
        if not smb_present(asset):
            return ToolResult(
                tool=self.name,
                status="not_applicable",
                message="no SMB service detected",
            )

        base = self.workdir / asset.ip
        cmd = [
            self.config.get("binary", "enum4linux-ng"),
            "-As",
            "-oJ",
            str(base),
            asset.ip,
        ]
        try:
            proc = run_command(
                cmd,
                timeout=self.timeout(float(self.config.get("timeout", 600))),
            )
        except CommandExecutionError as exc:
            return ToolResult(tool=self.name, status="failed", message=str(exc))

        candidates = [base.with_suffix(".json"), self.workdir / f"{asset.ip}.json"]
        outfile = next((path for path in candidates if path.exists()), None)
        if outfile is None:
            return ToolResult(
                tool=self.name,
                status="failed" if proc.returncode else "completed",
                message=proc.stderr.strip() or "no JSON artifact produced",
            )
        try:
            data = json.loads(outfile.read_text(errors="replace"))
        except json.JSONDecodeError:
            return ToolResult(
                tool=self.name,
                status="failed",
                raw_artifact=str(outfile),
                message="invalid enum4linux-ng JSON",
            )
        if not isinstance(data, dict):
            return ToolResult(
                tool=self.name,
                status="failed",
                raw_artifact=str(outfile),
                message="enum4linux-ng JSON root is not an object",
            )

        findings = self._findings(data, self._smb_port(asset))
        return ToolResult(
            tool=self.name,
            status="failed" if proc.returncode else "completed",
            findings=findings,
            raw_artifact=str(outfile),
            message=(
                proc.stderr.strip()
                or (f"enum4linux-ng exited with code {proc.returncode}" if proc.returncode else None)
            ),
        )
