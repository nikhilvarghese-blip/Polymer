from __future__ import annotations

import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from polymer.models.schema import Asset, Service, ToolResult
from polymer.scanners.base import Scanner
from polymer.utils.command import run_command


class NmapScanner(Scanner):
    name = "nmap"

    def available(self) -> bool:
        return shutil.which(self.config.get("binary", "nmap")) is not None

    def run(self, asset: Asset) -> ToolResult:
        if not self.available():
            return ToolResult(tool=self.name, status="unavailable", message="nmap not found")

        outfile = self.workdir / f"{asset.ip}.xml"
        arguments = self.config.get("arguments", ["-Pn", "-sV", "--version-light"])
        if not isinstance(arguments, list) or not all(
            isinstance(argument, str) for argument in arguments
        ):
            return ToolResult(
                tool=self.name,
                status="failed",
                message="nmap arguments must be a list of strings",
            )
        args = [self.config.get("binary", "nmap"), *arguments, "-oX", str(outfile), asset.ip]
        proc = run_command(
            args, timeout=self.timeout(float(self.config.get("timeout", 1800)))
        )
        if proc.returncode != 0 or not outfile.exists():
            return ToolResult(tool=self.name, status="failed", message=proc.stderr.strip() or "nmap failed")

        root = ET.parse(outfile).getroot()
        host = root.find("host")
        if host is None:
            return ToolResult(tool=self.name, status="completed", raw_artifact=str(outfile))

        state = host.find("status")
        asset.status = "up" if state is not None and state.attrib.get("state") == "up" else "down"
        hn = host.find("hostnames/hostname")
        if hn is not None:
            asset.hostname = hn.attrib.get("name")

        services: list[Service] = []
        for port in host.findall("ports/port"):
            st = port.find("state")
            if st is None or st.attrib.get("state") != "open":
                continue
            svc = port.find("service")
            services.append(Service(
                port=int(port.attrib["portid"]),
                protocol=port.attrib.get("protocol", "tcp"),
                state="open",
                name=svc.attrib.get("name") if svc is not None else None,
                product=svc.attrib.get("product") if svc is not None else None,
                version=svc.attrib.get("version") if svc is not None else None,
            ))
        asset.services = services
        return ToolResult(tool=self.name, status="completed", raw_artifact=str(outfile))
