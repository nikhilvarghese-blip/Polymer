from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

import requests

from polymer.intelligence.severity import severity_from_cvss


@dataclass
class CVEIntel:
    cve: str
    description: str | None = None
    cwes: list[str] | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    cvss_severity: str | None = None
    cpes: list[str] | None = None
    kev: bool = False
    kev_date_added: str | None = None
    kev_due_date: str | None = None
    kev_ransomware: str | None = None
    kev_required_action: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class VulnerabilityIntelligence:
    """Small cached NVD + CISA KEV client.

    Enrichment is best-effort by design. Scan results remain usable when external
    services are unavailable.
    """

    def __init__(self, config: dict, cache_dir: Path):
        self.config = config or {}
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()
        self.nvd_url = self.config.get(
            "nvd_url", "https://services.nvd.nist.gov/rest/json/cves/2.0"
        )
        self.kev_url = self.config.get(
            "kev_url",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        )
        self.timeout = int(self.config.get("timeout", 30))
        self.nvd_delay = float(self.config.get("nvd_delay_seconds", 0.7))
        self.nvd_api_key_env = self.config.get("nvd_api_key_env", "NVD_API_KEY")
        self.offline = bool(self.config.get("offline", False))
        self._last_nvd_request = 0.0
        self._kev_index: dict[str, dict[str, Any]] | None = None

    def _json_cache(self, name: str) -> Path:
        safe = name.replace("/", "_").replace(":", "_")
        return self.cache_dir / f"{safe}.json"

    def _load_cache(self, name: str) -> dict[str, Any] | None:
        path = self._json_cache(name)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else None
        except (OSError, json.JSONDecodeError):
            return None

    def _save_cache(self, name: str, payload: dict[str, Any]) -> None:
        path = self._json_cache(name)
        temporary = path.with_suffix(".json.tmp")
        try:
            temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            temporary.replace(path)
        except OSError:
            # Enrichment is best-effort; an unwritable cache must not discard scans.
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def _load_kev(self) -> dict[str, dict[str, Any]]:
        if self._kev_index is not None:
            return self._kev_index

        payload = self._load_cache("cisa-kev")
        if payload is None and not self.offline:
            try:
                response = self.session.get(self.kev_url, timeout=self.timeout)
                response.raise_for_status()
                payload = response.json()
                if not isinstance(payload, dict):
                    payload = None
                else:
                    self._save_cache("cisa-kev", payload)
            except (requests.RequestException, ValueError):
                payload = None

        index: dict[str, dict[str, Any]] = {}
        if payload:
            for item in payload.get("vulnerabilities", []):
                cve = str(item.get("cveID") or "").upper()
                if cve:
                    index[cve] = item
        self._kev_index = index
        return index

    def _nvd_payload(self, cve: str) -> dict[str, Any] | None:
        key = f"nvd-{cve.upper()}"
        cached = self._load_cache(key)
        if cached is not None:
            return cached
        if self.offline:
            return None

        delay = self.nvd_delay - (time.monotonic() - self._last_nvd_request)
        if delay > 0:
            time.sleep(delay)

        headers = {}
        api_key = os.getenv(self.nvd_api_key_env)
        if api_key:
            headers["apiKey"] = api_key
        try:
            response = self.session.get(
                self.nvd_url,
                params={"cveId": cve.upper()},
                headers=headers,
                timeout=self.timeout,
            )
            self._last_nvd_request = time.monotonic()
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                return None
            self._save_cache(key, payload)
            return payload
        except (requests.RequestException, ValueError):
            return None

    @staticmethod
    def _extract_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
        # Prefer CVSS v4, then v3.1, then v3.0, then v2 when present.
        for key, version in (
            ("cvssMetricV40", "4.0"),
            ("cvssMetricV31", "3.1"),
            ("cvssMetricV30", "3.0"),
            ("cvssMetricV2", "2.0"),
        ):
            entries = metrics.get(key) or []
            if not entries:
                continue
            preferred = next((e for e in entries if e.get("type") == "Primary"), entries[0])
            data = preferred.get("cvssData", {})
            score = data.get("baseScore")
            vector = data.get("vectorString")
            try:
                score_value = float(score) if score is not None else None
            except (TypeError, ValueError):
                score_value = None
            return score_value, vector, version
        return None, None, None

    @staticmethod
    def _extract_cpes(configurations: list[dict[str, Any]]) -> list[str]:
        values: set[str] = set()

        def walk(node: dict[str, Any]) -> None:
            for match in node.get("cpeMatch", []) or []:
                criteria = match.get("criteria")
                if criteria:
                    values.add(criteria)
            for child in node.get("nodes", []) or []:
                walk(child)

        for configuration in configurations or []:
            for node in configuration.get("nodes", []) or []:
                walk(node)
        return sorted(values)

    def enrich_cve(self, cve: str) -> CVEIntel:
        cve = cve.upper().strip()
        intel = CVEIntel(cve=cve, cwes=[], cpes=[])
        payload = self._nvd_payload(cve)

        if payload:
            vulnerabilities = payload.get("vulnerabilities") or []
            if vulnerabilities:
                record = vulnerabilities[0].get("cve", {})
                descriptions = record.get("descriptions") or []
                english = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)
                intel.description = english or (descriptions[0].get("value") if descriptions else None)

                cwes: set[str] = set()
                for weakness in record.get("weaknesses") or []:
                    for desc in weakness.get("description") or []:
                        value = desc.get("value")
                        if value and value.upper().startswith("CWE-"):
                            cwes.add(value.upper())
                intel.cwes = sorted(cwes)

                score, vector, version = self._extract_cvss(record.get("metrics") or {})
                intel.cvss_score = score
                intel.cvss_vector = vector
                intel.cvss_version = version
                intel.cvss_severity = severity_from_cvss(score) if score is not None else None
                intel.cpes = self._extract_cpes(record.get("configurations") or [])

        kev = self._load_kev().get(cve)
        if kev:
            intel.kev = True
            intel.kev_date_added = kev.get("dateAdded")
            intel.kev_due_date = kev.get("dueDate")
            intel.kev_ransomware = kev.get("knownRansomwareCampaignUse")
            intel.kev_required_action = kev.get("requiredAction")

        return intel
