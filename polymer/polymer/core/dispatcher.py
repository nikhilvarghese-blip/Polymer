from __future__ import annotations

from polymer.core.services import smb_present, ssh_ports, tls_ports, web_endpoints


class ScannerDispatcher:
    """Map discovered services to scanner adapters.

    Nmap is intentionally not returned here because discovery happens before dispatch.
    """

    def __init__(self, config: dict, profile_tools: set[str] | None = None):
        self.config = config
        self.profile_tools = profile_tools
        self.routing = config.get("scan", {}).get("routing", "adaptive")
        if self.routing not in {"adaptive", "exhaustive"}:
            raise ValueError("scan.routing must be 'adaptive' or 'exhaustive'")

    def _enabled(self, key: str) -> bool:
        cfg = self.config.get("scan", {}).get(key, {})
        enabled = bool(cfg.get("enabled", False))
        if (
            self.profile_tools is not None
            and key not in self.profile_tools
            and key.replace("_sca", "wazuh") not in self.profile_tools
        ):
            return False
        return enabled

    def scanners_for_asset(self, asset) -> list[str]:
        if asset.status != "up":
            return []
        selected: list[str] = []
        if self._enabled("wazuh"):
            selected.append("wazuh_sca")
        # API discovery must run before Nuclei so its routes become VA targets.
        if self._enabled("kiterunner") and (
            self.routing == "exhaustive" or web_endpoints(asset)
        ):
            selected.append("kiterunner")
        nuclei_ip_scan = bool(
            self.config.get("scan", {}).get("nuclei", {}).get("scan_ip", False)
        )
        if self._enabled("nuclei") and (
            self.routing == "exhaustive" or nuclei_ip_scan or web_endpoints(asset)
        ):
            selected.append("nuclei")
        if self._enabled("nikto") and (
            self.routing == "exhaustive" or web_endpoints(asset)
        ):
            selected.append("nikto")
        if self._enabled("testssl") and (
            self.routing == "exhaustive" or tls_ports(asset)
        ):
            selected.append("testssl")
        if self._enabled("ssh_audit") and (
            self.routing == "exhaustive" or ssh_ports(asset)
        ):
            selected.append("ssh_audit")
        if self._enabled("enum4linux") and (
            self.routing == "exhaustive" or smb_present(asset)
        ):
            selected.append("enum4linux")
        if self._enabled("greenbone"):
            selected.append("greenbone")
        return list(dict.fromkeys(selected))
