from __future__ import annotations

import json
from pathlib import Path
import tempfile
from typing import Any

from polymer.models.schema import Asset
from polymer.reporting.paths import (
    asset_folder_name,
    ensure_unique_asset_ips,
    tool_report_filename,
)


def _write_json(payload: Any, path: Path) -> None:
    """Write JSON atomically so interrupted runs do not leave corrupt reports."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(json.dumps(payload, indent=2) + "\n")
        temporary.replace(path)
    except Exception:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        raise


def write_ip_grouped_report(assets: list[Asset], path: Path) -> None:
    ensure_unique_asset_ips(assets)
    payload = {asset.ip: asset.model_dump(mode="json") for asset in assets}
    _write_json(payload, path)


def write_analysis_report(assets: list[Asset], path: Path) -> None:
    ensure_unique_asset_ips(assets)
    payload = {
        "summary": {
            "assets": len(assets),
            "correlated_findings": sum(len(a.correlated_findings) for a in assets),
            "critical": sum(a.risk_summary.get("critical", 0) for a in assets),
            "high": sum(a.risk_summary.get("high", 0) for a in assets),
            "medium": sum(a.risk_summary.get("medium", 0) for a in assets),
            "low": sum(a.risk_summary.get("low", 0) for a in assets),
            "kev": sum(a.risk_summary.get("kev", 0) for a in assets),
        },
        "assets": {
            asset.ip: {
                "risk_summary": asset.risk_summary,
                "correlated_findings": [
                    finding.model_dump(mode="json")
                    for finding in asset.correlated_findings
                ],
            }
            for asset in assets
        },
    }
    _write_json(payload, path)


def write_delta_report(payload: dict, path: Path) -> None:
    _write_json(payload, path)


def write_per_ip(assets: list[Asset], root: Path) -> None:
    ensure_unique_asset_ips(assets)
    for asset in assets:
        folder = root / asset_folder_name(asset.ip)
        _write_json(asset.model_dump(mode="json"), folder / "combined.json")
        _write_json(
            {
                "risk_summary": asset.risk_summary,
                "findings": [
                    finding.model_dump(mode="json")
                    for finding in asset.correlated_findings
                ],
            },
            folder / "correlated.json",
        )
        for name, result in asset.tools.items():
            _write_json(
                result.model_dump(mode="json"),
                folder / tool_report_filename(name),
            )
