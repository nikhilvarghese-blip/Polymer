from polymer.core.dispatcher import ScannerDispatcher
from polymer.models.schema import Asset, Service


def cfg():
    return {"scan": {k:{"enabled":True} for k in ["nuclei","wazuh","ssh_audit","testssl","nikto","enum4linux","greenbone"]}}


def test_ssh_routes_ssh_audit():
    a=Asset(ip="10.0.0.1",status="up",services=[Service(port=22,name="ssh")])
    s=ScannerDispatcher(cfg()).scanners_for_asset(a)
    assert "ssh_audit" in s and "nikto" not in s


def test_https_routes_web_tools():
    a=Asset(ip="10.0.0.2",status="up",services=[Service(port=443,name="https")])
    s=ScannerDispatcher(cfg()).scanners_for_asset(a)
    assert {"nuclei","nikto","testssl"}.issubset(set(s))


def test_smb_routes_enum4linux():
    a=Asset(ip="10.0.0.3",status="up",services=[Service(port=445,name="microsoft-ds")])
    assert "enum4linux" in ScannerDispatcher(cfg()).scanners_for_asset(a)
