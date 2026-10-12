from pathlib import Path

from polymer.cli import load_config, load_profile


def test_full_profile_applies_exhaustive_routing_and_deep_discovery():
    config_path = Path("config/polymer.yaml")
    config = load_config(config_path)

    scanners = load_profile(config, "full", config_path)

    assert scanners is not None
    assert "greenbone" in scanners
    assert config["scan"]["routing"] == "exhaustive"
    assert "-p-" in config["scan"]["nmap"]["arguments"]
    assert config["scan"]["nuclei"]["scan_ip"] is True


def test_discovery_profile_selects_only_nmap():
    config_path = Path("config/polymer.yaml")
    config = load_config(config_path)

    scanners = load_profile(config, "discovery", config_path)

    assert scanners == {"nmap"}
    assert config["scan"]["routing"] == "adaptive"
