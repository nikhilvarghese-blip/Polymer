from __future__ import annotations

import json
from pathlib import Path
from polymer.models.schema import Asset


def write_ip_grouped_report(assets: list[Asset], path: Path) -> None:
    payload = {asset.ip: asset.model_dump(mode="json") for asset in assets}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


def write_per_ip(assets: list[Asset], root: Path) -> None:
    for asset in assets:
        folder = root / asset.ip.replace(":", "_")
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "combined.json").write_text(json.dumps(asset.model_dump(mode="json"), indent=2))
        for name, result in asset.tools.items():
            (folder / f"{name}.json").write_text(json.dumps(result.model_dump(mode="json"), indent=2))
