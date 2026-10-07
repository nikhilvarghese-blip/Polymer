from __future__ import annotations

SEVERITY_RANK = {
    "unknown": -1,
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

ALIASES = {
    "informational": "info",
    "moderate": "medium",
    "warning": "medium",
    "warn": "medium",
    "none": "info",
}


def normalize_severity(value: str | None) -> str:
    if not value:
        return "unknown"
    candidate = str(value).strip().lower()
    candidate = ALIASES.get(candidate, candidate)
    return candidate if candidate in SEVERITY_RANK else "unknown"


def severity_from_cvss(score: float | int | None) -> str:
    if score is None:
        return "unknown"
    value = float(score)
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    if value > 0.0:
        return "low"
    return "info"


def highest_severity(*values: str | None) -> str:
    normalized = [normalize_severity(value) for value in values]
    return max(normalized, key=lambda item: SEVERITY_RANK[item], default="unknown")
