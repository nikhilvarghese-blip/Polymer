from __future__ import annotations

from polymer.core.services import smb_present, ssh_ports, tls_ports, web_endpoints


class ScannerDispatcher:
    """Map discovered services to scanner adapters.

    Nmap is intentionally not returned here because discovery happens before dispatch.
    """

    def __init__(self, config: dict, profile_tools: set[str] | None = None):
        self.config = config
        self.profile_tools = profile_tools

    def _enabled(self, key: str) -> bool:
        cfg = self.config.get("scan", {}).get(key, {})
        enabled = bool(cfg.get("enabled", False))
        if self.profile_tools is not None and key not in self.profile_tools and key.replace("_sca", "wazuh") not in self.profile_tools:
            return False
        return enabled

    def scanners_for_asset(self, asset) -> list[str]:
        if asset.status != "up":
            return []
        selected: list[str] = []
        if self._enabled("wazuh"):
            selected.append("wazuh_sca")
        if self._enabled("nuclei") and web_endpoints(asset):
            selected.append("nuclei")
        if self._enabled("nikto") and web_endpoints(asset):
            selected.append("nikto")
        if self._enabled("testssl") and tls_ports(asset):
            selected.append("testssl")
        if self._enabled("ssh_audit") and ssh_ports(asset):
            selected.append("ssh_audit")
        if self._enabled("enum4linux") and smb_present(asset):
            selected.append("enum4linux")
        if self._enabled("greenbone"):
            selected.append("greenbone")
        return list(dict.fromkeys(selected))
