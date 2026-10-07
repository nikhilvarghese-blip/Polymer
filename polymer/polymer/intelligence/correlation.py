from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import dataclass
from typing import Iterable

from polymer.intelligence.enrichment import VulnerabilityIntelligence, CVEIntel
from polymer.intelligence.severity import highest_severity, normalize_severity, SEVERITY_RANK
from polymer.models.schema import Asset, CorrelatedFinding, Finding


def _norm_title(value: str) -> str:
    text = re.sub(r"[^a-z0-9]+", " ", (value or "").lower()).strip()
    return " ".join(text.split())


def _stable_id(
    asset_ip: str,
    title: str,
    port: int | None,
    protocol: str | None,
    cves: Iterable[str],
) -> str:
    material = "|".join(
        [
            asset_ip,
            str(port or ""),
            protocol or "",
            ",".join(sorted(cves)),
            _norm_title(title),
        ]
    )
    return "POLY-" + hashlib.sha256(material.encode()).hexdigest()[:12].upper()


@dataclass
class _Source:
    tool: str
    finding: Finding


class CorrelationEngine:
    def __init__(self, config: dict, intel: VulnerabilityIntelligence | None = None):
        self.config = config or {}
        self.intel = intel

    @staticmethod
    def _compatible_port(a: int | None, b: int | None) -> bool:
        return a is None or b is None or a == b

    def _same_group(self, group: list[_Source], source: _Source) -> bool:
        incoming_cves = {c.upper() for c in source.finding.cve}
        incoming_title = _norm_title(source.finding.title)
        for existing in group:
            if not self._compatible_port(existing.finding.port, source.finding.port):
                continue
            if (
                existing.finding.protocol
                and source.finding.protocol
                and existing.finding.protocol != source.finding.protocol
            ):
                continue
            existing_cves = {c.upper() for c in existing.finding.cve}
            if incoming_cves and existing_cves and incoming_cves.intersection(existing_cves):
                return True
            if not incoming_cves and not existing_cves:
                if existing.finding.category == source.finding.category and _norm_title(existing.finding.title) == incoming_title:
                    return True
        return False

    def _groups(self, asset: Asset) -> list[list[_Source]]:
        groups: list[list[_Source]] = []
        for tool, result in asset.tools.items():
            for finding in result.findings:
                source = _Source(tool=tool, finding=finding)
                matches = [group for group in groups if self._same_group(group, source)]
                if not matches:
                    groups.append([source])
                    continue
                primary = matches[0]
                primary.append(source)
                # Merge transitive groups (for findings carrying multiple overlapping CVEs).
                for extra in matches[1:]:
                    primary.extend(extra)
                    groups.remove(extra)
        return groups

    @staticmethod
    def _confidence(tools: set[str], cves: set[str], enriched: bool, kev: bool, port: int | None) -> tuple[int, str]:
        score = 35
        if len(tools) >= 2:
            score += 20
        if len(tools) >= 3:
            score += 10
        if cves:
            score += 15
        if enriched:
            score += 10
        if kev:
            score += 10
        if port is not None:
            score += 5
        score = min(score, 100)
        label = "high" if score >= 75 else "medium" if score >= 50 else "low"
        return score, label

    @staticmethod
    def _priority(severity: str, confidence: int, kev: bool) -> int:
        sev_points = {
            "critical": 60,
            "high": 45,
            "medium": 30,
            "low": 15,
            "info": 5,
            "unknown": 10,
        }.get(severity, 10)
        return min(100, sev_points + round(confidence * 0.3) + (20 if kev else 0))

    def correlate_asset(self, asset: Asset) -> list[CorrelatedFinding]:
        output: list[CorrelatedFinding] = []
        intel_cache: dict[str, CVEIntel] = {}

        for group in self._groups(asset):
            tools = {src.tool for src in group}
            cves = {c.upper() for src in group for c in src.finding.cve if c}
            ports = {src.finding.port for src in group if src.finding.port is not None}
            port = next(iter(ports)) if len(ports) == 1 else None
            protocols = {
                src.finding.protocol
                for src in group
                if src.finding.protocol is not None
            }
            protocol = next(iter(protocols)) if len(protocols) == 1 else None
            categories = [src.finding.category for src in group if src.finding.category]
            category = Counter(categories).most_common(1)[0][0] if categories else "vulnerability"
            source_severity = highest_severity(*(src.finding.severity for src in group))

            intel_records: list[CVEIntel] = []
            if self.intel:
                for cve in sorted(cves):
                    if cve not in intel_cache:
                        intel_cache[cve] = self.intel.enrich_cve(cve)
                    intel_records.append(intel_cache[cve])

            nvd_severity = highest_severity(*(item.cvss_severity for item in intel_records)) if intel_records else "unknown"
            severity = highest_severity(source_severity, nvd_severity)
            best_cvss = max((item.cvss_score for item in intel_records if item.cvss_score is not None), default=None)
            best_intel = next((item for item in intel_records if item.cvss_score == best_cvss), None) if best_cvss is not None else None
            description = next(
                (item.description for item in intel_records if item.description),
                None,
            )
            if description is None:
                description = next(
                    (
                        src.finding.evidence.get("description")
                        for src in group
                        if isinstance(src.finding.evidence.get("description"), str)
                    ),
                    None,
                )
            kev = any(item.kev for item in intel_records)
            cwes = sorted({cwe for item in intel_records for cwe in (item.cwes or [])})
            cpes = sorted({cpe for item in intel_records for cpe in (item.cpes or [])})
            enriched = any(item.description or item.cvss_score is not None or item.cwes or item.cpes for item in intel_records)
            confidence, confidence_label = self._confidence(tools, cves, enriched, kev, port)

            representative = max(
                group,
                key=lambda src: SEVERITY_RANK.get(normalize_severity(src.finding.severity), -1),
            ).finding

            evidence = []
            remediation = []
            source_findings = []
            for src in group:
                evidence.append({
                    "tool": src.tool,
                    "title": src.finding.title,
                    "severity": normalize_severity(src.finding.severity),
                    "port": src.finding.port,
                    "protocol": src.finding.protocol,
                    "detected_at": src.finding.detected_at.isoformat(),
                    "evidence": src.finding.evidence,
                })
                if src.finding.remediation and src.finding.remediation not in remediation:
                    remediation.append(src.finding.remediation)
                source_findings.append({
                    "tool": src.tool,
                    "title": src.finding.title,
                    "category": src.finding.category,
                    "port": src.finding.port,
                    "protocol": src.finding.protocol,
                    "cve": src.finding.cve,
                    "check_id": src.finding.check_id,
                    "policy_id": src.finding.policy_id,
                    "detected_at": src.finding.detected_at.isoformat(),
                })

            kev_details = [
                {
                    "cve": item.cve,
                    "date_added": item.kev_date_added,
                    "due_date": item.kev_due_date,
                    "known_ransomware_campaign_use": item.kev_ransomware,
                    "required_action": item.kev_required_action,
                }
                for item in intel_records if item.kev
            ]

            title = representative.title
            if len(cves) == 1:
                only_cve = next(iter(cves))
                if only_cve not in title.upper():
                    title = f"{title} ({only_cve})"

            correlated = CorrelatedFinding(
                finding_id=_stable_id(asset.ip, title, port, protocol, cves),
                asset_ip=asset.ip,
                title=title,
                description=description,
                category=category,
                severity=severity,
                source_severity=source_severity,
                confidence=confidence_label,
                confidence_score=confidence,
                priority_score=self._priority(severity, confidence, kev),
                tools=sorted(tools),
                port=port,
                protocol=protocol,
                cve=sorted(cves),
                cwe=cwes,
                cpe=cpes,
                cvss_score=best_cvss,
                cvss_vector=(best_intel.cvss_vector if best_intel else None),
                cvss_version=(best_intel.cvss_version if best_intel else None),
                kev=kev,
                kev_details=kev_details,
                evidence=evidence,
                remediation=remediation,
                source_findings=source_findings,
            )
            output.append(correlated)

        return sorted(output, key=lambda item: (-item.priority_score, item.finding_id))

    def analyze_assets(self, assets: list[Asset]) -> list[Asset]:
        for asset in assets:
            asset.correlated_findings = self.correlate_asset(asset)
            counts = Counter(item.severity for item in asset.correlated_findings)
            asset.risk_summary = {
                "total_correlated": len(asset.correlated_findings),
                "critical": counts.get("critical", 0),
                "high": counts.get("high", 0),
                "medium": counts.get("medium", 0),
                "low": counts.get("low", 0),
                "info": counts.get("info", 0),
                "unknown": counts.get("unknown", 0),
                "kev": sum(1 for item in asset.correlated_findings if item.kev),
                "high_confidence": sum(1 for item in asset.correlated_findings if item.confidence == "high"),
            }
        return assets
