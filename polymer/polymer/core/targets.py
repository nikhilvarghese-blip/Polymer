from __future__ import annotations

import ipaddress
from pathlib import Path


def parse_targets(path: str | Path, max_hosts: int = 4096, allow_public: bool = False) -> list[str]:
    source = Path(path)
    if not source.exists():
        raise FileNotFoundError(source)

    output: set[str] = set()
    for lineno, raw in enumerate(source.read_text().splitlines(), start=1):
        value = raw.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            if "/" in value:
                net = ipaddress.ip_network(value, strict=False)
                members = list(net.hosts())
                if len(output) + len(members) > max_hosts:
                    raise ValueError(f"expanded scope exceeds max_hosts={max_hosts}")
                for ip in members:
                    _validate_scope(ip, allow_public, lineno)
                    output.add(str(ip))
            else:
                ip = ipaddress.ip_address(value)
                _validate_scope(ip, allow_public, lineno)
                output.add(str(ip))
        except ValueError as exc:
            raise ValueError(f"targets file line {lineno}: {exc}") from exc
    return sorted(output, key=lambda x: (ipaddress.ip_address(x).version, int(ipaddress.ip_address(x))))


def _validate_scope(ip: ipaddress._BaseAddress, allow_public: bool, lineno: int) -> None:
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback:
        raise ValueError(f"unsupported target {ip}")
    if not allow_public and not ip.is_private:
        raise ValueError(f"public target {ip} blocked by policy (line {lineno})")
