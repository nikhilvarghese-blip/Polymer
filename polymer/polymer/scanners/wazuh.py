from __future__ import annotations

import os
import requests
from polymer.models.schema import Asset, Finding, ToolResult
from polymer.scanners.base import Scanner


class WazuhSCAScanner(Scanner):
    name = "wazuh_sca"

    def available(self) -> bool:
        return bool(self.config.get("url") and os.getenv(self.config.get("username_env", "POLYMER_WAZUH_USERNAME")) and os.getenv(self.config.get("password_env", "POLYMER_WAZUH_PASSWORD")))

    def _session(self) -> tuple[requests.Session, str]:
        s = requests.Session()
        s.verify = bool(self.config.get("verify_tls", True))
        base = self.config["url"].rstrip("/")
        user = os.environ[self.config.get("username_env", "POLYMER_WAZUH_USERNAME")]
        password = os.environ[self.config.get("password_env", "POLYMER_WAZUH_PASSWORD")]
        response = s.post(f"{base}/security/user/authenticate", auth=(user, password), timeout=30)
        response.raise_for_status()
        token = response.json()["data"]["token"]
        s.headers.update({"Authorization": f"Bearer {token}"})
        return s, base

    def run(self, asset: Asset) -> ToolResult:
        if not self.available():
            return ToolResult(tool=self.name, status="unavailable", message="Wazuh API config/credentials unavailable")
        try:
            s, base = self._session()
            r = s.get(f"{base}/agents", params={"q": f"ip={asset.ip}", "limit": 50}, timeout=30)
            r.raise_for_status()
            agents = r.json().get("data", {}).get("affected_items", [])
            if not agents:
                return ToolResult(tool=self.name, status="not_applicable", message="no Wazuh agent matched this IP")

            agent_id = str(agents[0]["id"])
            policies_resp = s.get(f"{base}/sca/{agent_id}", timeout=30)
            policies_resp.raise_for_status()
            policies = policies_resp.json().get("data", {}).get("affected_items", [])
            findings: list[Finding] = []
            for policy in policies:
                policy_id = str(policy.get("policy_id") or policy.get("id") or "")
                if not policy_id:
                    continue
                checks_resp = s.get(f"{base}/sca/{agent_id}/checks/{policy_id}", timeout=30)
                checks_resp.raise_for_status()
                checks = checks_resp.json().get("data", {}).get("affected_items", [])
                for check in checks:
                    result = str(check.get("result", "")).lower()
                    if result not in {"failed", "fail"}:
                        continue
                    findings.append(Finding(
                        tool=self.name,
                        title=check.get("title") or f"SCA check {check.get('id', '')}",
                        severity="unknown",
                        category="configuration",
                        check_id=str(check.get("id")) if check.get("id") is not None else None,
                        policy_id=policy_id,
                        remediation=check.get("remediation"),
                        evidence={"agent_id": agent_id, "result": check.get("result"), "reason": check.get("reason")},
                    ))
            return ToolResult(tool=self.name, status="completed", findings=findings, message=f"Wazuh agent {agent_id}")
        except requests.RequestException as exc:
            return ToolResult(tool=self.name, status="failed", message=str(exc))
