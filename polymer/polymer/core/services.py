from __future__ import annotations

HTTP_PORTS = {80, 8000, 8080, 8888}
HTTPS_PORTS = {443, 8443, 9443}
TLS_PORTS = {443, 465, 636, 853, 993, 995, 8443, 9443}
SMB_PORTS = {139, 445}
SSH_PORTS = {22}

HTTP_NAMES = {"http", "http-proxy", "http-alt", "www"}
HTTPS_NAMES = {"https", "ssl/http", "https-alt"}
SMB_NAMES = {"microsoft-ds", "netbios-ssn", "smb"}
SSH_NAMES = {"ssh"}


def service_name(service) -> str:
    return (service.name or "").lower()


def open_services(asset):
    return [s for s in asset.services if s.state == "open"]


def web_endpoints(asset) -> list[tuple[str, int]]:
    endpoints: list[tuple[str, int]] = []
    for svc in open_services(asset):
        name = service_name(svc)
        if svc.port in HTTPS_PORTS or name in HTTPS_NAMES or "https" in name:
            endpoints.append((f"https://{asset.ip}:{svc.port}", svc.port))
        elif svc.port in HTTP_PORTS or name in HTTP_NAMES or "http" in name:
            endpoints.append((f"http://{asset.ip}:{svc.port}", svc.port))
    return list(dict.fromkeys(endpoints))


def ssh_ports(asset) -> list[int]:
    return [s.port for s in open_services(asset) if s.port in SSH_PORTS or service_name(s) in SSH_NAMES]


def smb_present(asset) -> bool:
    return any(s.port in SMB_PORTS or service_name(s) in SMB_NAMES for s in open_services(asset))


def tls_ports(asset) -> list[int]:
    return [s.port for s in open_services(asset) if s.port in TLS_PORTS or "ssl" in service_name(s) or "tls" in service_name(s) or "https" in service_name(s)]
