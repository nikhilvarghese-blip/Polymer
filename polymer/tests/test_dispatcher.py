from polymer.core.dispatcher import ScannerDispatcher
from polymer.models.schema import Asset, Service


def cfg():
    return {
        "scan": {
            key: {"enabled": True}
            for key in [
                "kiterunner",
                "nuclei",
                "wazuh",
                "ssh_audit",
                "testssl",
                "nikto",
                "enum4linux",
                "greenbone",
            ]
        }
    }


def test_ssh_routes_ssh_audit():
    a=Asset(ip="10.0.0.1",status="up",services=[Service(port=22,name="ssh")])
    s=ScannerDispatcher(cfg()).scanners_for_asset(a)
    assert "ssh_audit" in s and "nikto" not in s


def test_https_routes_web_tools():
    a=Asset(ip="10.0.0.2",status="up",services=[Service(port=443,name="https")])
    s=ScannerDispatcher(cfg()).scanners_for_asset(a)
    assert {"kiterunner","nuclei","nikto","testssl"}.issubset(set(s))
    assert s.index("kiterunner") < s.index("nuclei")


def test_smb_routes_enum4linux():
    a=Asset(ip="10.0.0.3",status="up",services=[Service(port=445,name="microsoft-ds")])
    assert "enum4linux" in ScannerDispatcher(cfg()).scanners_for_asset(a)


def test_exhaustive_routing_accounts_for_every_enabled_profile_tool():
    config = cfg()
    config["scan"]["routing"] = "exhaustive"
    profile = {
        "nmap", "kiterunner", "nuclei", "wazuh", "ssh_audit", "testssl",
        "nikto", "enum4linux", "greenbone",
    }
    asset = Asset(
        ip="10.0.0.4",
        status="up",
        services=[Service(port=5060, name="sip")],
    )

    scanners = ScannerDispatcher(config, profile).scanners_for_asset(asset)

    assert scanners == [
        "wazuh_sca", "kiterunner", "nuclei", "nikto", "testssl",
        "ssh_audit", "enum4linux", "greenbone",
    ]


def test_nuclei_ip_scan_routes_hosts_without_http():
    config = cfg()
    config["scan"]["nuclei"]["scan_ip"] = True
    asset = Asset(ip="10.0.0.5", status="up", services=[])

    scanners = ScannerDispatcher(config).scanners_for_asset(asset)

    assert "nuclei" in scanners
