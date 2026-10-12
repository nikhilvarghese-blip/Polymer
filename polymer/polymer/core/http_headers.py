from __future__ import annotations

import json
import os
import re


_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def api_headers(config: dict) -> list[str]:
    """Load optional API scan headers without requiring secrets in YAML.

    The configured environment variable must contain a JSON object, for example
    {"Authorization": "Bearer token", "X-API-Key": "secret"}.
    """

    env_name = config.get("headers_env")
    if not env_name:
        return []
    if not isinstance(env_name, str):
        raise ValueError("headers_env must be an environment variable name")
    raw = os.getenv(env_name)
    if not raw:
        return []
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{env_name} must contain a JSON object: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{env_name} must contain a JSON object")

    headers: list[str] = []
    for name, value in payload.items():
        if not isinstance(name, str) or not _HEADER_NAME.fullmatch(name):
            raise ValueError(f"{env_name} contains an invalid HTTP header name")
        if not isinstance(value, str):
            raise ValueError(f"{env_name} header values must be strings")
        if "\r" in value or "\n" in value:
            raise ValueError(f"{env_name} contains an unsafe HTTP header value")
        headers.append(f"{name}: {value}")
    return headers
