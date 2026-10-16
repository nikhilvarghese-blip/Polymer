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
        response = s.post(f"{base}/security/user/authenticate", auth=(user, password), timeout=self.timeout(30))
        response.raise_for_status()
        token = response.json()["data"]["token"]
        s.headers.update({"Authorization": f"Bearer {token}"})
        return s, base

    @staticmethod
    def _affected_items(response, label: str) -> list:
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError(f"Wazuh {label} response is not an object")
        data = payload.get("data")
        if not isinstance(data, dict):
            raise ValueError(f"Wazuh {label} response has no data object")
        items = data.get("affected_items")
        if not isinstance(items, list):
            raise ValueError(f"Wazuh {label} response has no affected_items list")
        return items

    def run(self, asset: Asset) -> ToolResult:
        if not self.available():
            return ToolResult(tool=self.name, status="unavailable", message="Wazuh API config/credentials unavailable")
        try:
            s, base = self._session()
            r = s.get(f"{base}/agents", params={"q": f"ip={asset.ip}", "limit": 50}, timeout=self.timeout(30))
            r.raise_for_status()
            agents = self._affected_items(r, "agents")
            if not agents:
                return ToolResult(tool=self.name, status="not_applicable", message="no Wazuh agent matched this IP")

            agent_id = str(agents[0]["id"])
            policies_resp = s.get(f"{base}/sca/{agent_id}", timeout=self.timeout(30))
            policies_resp.raise_for_status()
            policies = self._affected_items(policies_resp, "policies")
            findings: list[Finding] = []
            for policy in policies:
                if not isinstance(policy, dict):
                    continue
                policy_id = str(policy.get("policy_id") or policy.get("id") or "")
                if not policy_id:
                    continue
                checks_resp = s.get(f"{base}/sca/{agent_id}/checks/{policy_id}", timeout=self.timeout(30))
                checks_resp.raise_for_status()
                checks = self._affected_items(checks_resp, "checks")
                for check in checks:
                    if not isinstance(check, dict):
                        continue
                    result = str(check.get("result", "")).lower()
                    if result not in {"failed", "fail"}:
                        continue
                    reason = check.get("reason")
                    evidence = {
                        "agent_id": agent_id,
                        "result": check.get("result"),
                        "reason": reason,
                    }
                    if isinstance(reason, str) and reason.strip():
                        evidence["description"] = reason.strip()
                    raw_check_id = check.get("id")
                    check_id = (
                        str(raw_check_id)
                        if isinstance(raw_check_id, (str, int, float))
                        and not isinstance(raw_check_id, bool)
                        else None
                    )
                    raw_title = check.get("title")
                    title = (
                        raw_title.strip()
                        if isinstance(raw_title, str) and raw_title.strip()
                        else f"SCA check {check_id}"
                        if check_id
                        else "Wazuh SCA failed check"
                    )
                    raw_remediation = check.get("remediation")
                    remediation = (
                        raw_remediation.strip()
                        if isinstance(raw_remediation, str)
                        and raw_remediation.strip()
                        else None
                    )
                    findings.append(Finding(
                        tool=self.name,
                        title=title,
                        severity="unknown",
                        category="configuration",
                        check_id=check_id,
                        policy_id=policy_id,
                        remediation=remediation,
                        evidence=evidence,
                    ))
            return ToolResult(tool=self.name, status="completed", findings=findings, message=f"Wazuh agent {agent_id}")
        except (
            requests.RequestException,
            AttributeError,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            return ToolResult(tool=self.name, status="failed", message=str(exc))
