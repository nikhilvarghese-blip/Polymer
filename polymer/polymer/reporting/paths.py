from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from typing import Protocol


TOOL_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class AssetLike(Protocol):
    ip: str


def validate_tool_name(value: str) -> str:
    if not TOOL_NAME_PATTERN.fullmatch(value) or value in {".", ".."}:
        raise ValueError(
            "tool name must contain only letters, numbers, '.', '_', or '-'"
        )
    return value


def asset_folder_name(value: str) -> str:
    """Return a collision-free, portable folder name for a validated IP."""
    if "%" in value:
        raise ValueError("scoped IPv6 addresses are not supported in reports")
    address = ipaddress.ip_address(value)
    if address.version == 4:
        return str(address)
    return "ipv6-" + address.exploded.replace(":", "-")


def tool_report_filename(value: str) -> str:
    return f"{validate_tool_name(value)}.json"


def ensure_unique_asset_ips(assets: Iterable[AssetLike]) -> None:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for asset in assets:
        if asset.ip in seen:
            duplicates.add(asset.ip)
        seen.add(asset.ip)
    if duplicates:
        raise ValueError(
            "duplicate asset IPs are not allowed: " + ", ".join(sorted(duplicates))
        )
