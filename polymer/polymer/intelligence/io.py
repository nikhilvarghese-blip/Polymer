from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from polymer.models.schema import Asset
from polymer.reporting.paths import ensure_unique_asset_ips


def load_assets(path: Path) -> list[Asset]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid Polymer JSON in {path}: {exc}") from exc
    if isinstance(payload, dict) and "assets" in payload and isinstance(payload["assets"], dict):
        payload = payload["assets"]
    if isinstance(payload, dict):
        values = payload.values()
    elif isinstance(payload, list):
        values = payload
    else:
        raise ValueError(f"unsupported Polymer JSON structure in {path}")
    try:
        assets = [Asset.model_validate(value) for value in values]
    except ValidationError as exc:
        raise ValueError(f"invalid asset data in {path}: {exc}") from exc
    ensure_unique_asset_ips(assets)
    return assets
