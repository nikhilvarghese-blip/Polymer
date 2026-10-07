from __future__ import annotations

from typing import Iterable
from polymer.models.schema import Asset, CorrelatedFinding


def signature(finding: CorrelatedFinding) -> str:
    if finding.cve:
        identity = ",".join(sorted(finding.cve))
    else:
        identity = " ".join(finding.title.lower().split())
    return (
        f"{finding.asset_ip}|{finding.port or ''}|{finding.protocol or ''}|"
        f"{finding.category}|{identity}"
    )


def compare_assets(current: Iterable[Asset], baseline: Iterable[Asset]) -> dict:
    current_map = {
        signature(f): f
        for asset in current
        for f in asset.correlated_findings
    }
    baseline_map = {
        signature(f): f
        for asset in baseline
        for f in asset.correlated_findings
    }

    new_keys = sorted(set(current_map) - set(baseline_map))
    resolved_keys = sorted(set(baseline_map) - set(current_map))
    unchanged_keys = sorted(set(current_map) & set(baseline_map))

    return {
        "summary": {
            "new": len(new_keys),
            "resolved": len(resolved_keys),
            "unchanged": len(unchanged_keys),
        },
        "new": [current_map[key].model_dump(mode="json") for key in new_keys],
        "resolved": [baseline_map[key].model_dump(mode="json") for key in resolved_keys],
        "unchanged": [current_map[key].model_dump(mode="json") for key in unchanged_keys],
    }
