from polymer.intelligence.correlation import CorrelationEngine
from polymer.intelligence.enrichment import CVEIntel
from polymer.models.schema import Asset, Finding, ToolResult


class FakeIntel:
    def enrich_cve(self, cve: str) -> CVEIntel:
        return CVEIntel(
            cve=cve,
            description="Example vulnerability",
            cwes=["CWE-79"],
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_version="3.1",
            cvss_severity="critical",
            cpes=["cpe:2.3:a:example:server:1.0:*:*:*:*:*:*:*"],
            kev=True,
            kev_date_added="2026-01-01",
        )


def test_same_cve_cross_tool_is_correlated():
    asset = Asset(ip="10.0.0.10", status="up")
    asset.tools["nuclei"] = ToolResult(
        tool="nuclei",
        status="completed",
        findings=[Finding(tool="nuclei", title="Example RCE", severity="high", port=443, cve=["CVE-2026-1234"])],
    )
    asset.tools["greenbone"] = ToolResult(
        tool="greenbone",
        status="completed",
        findings=[Finding(tool="greenbone", title="Example remote code execution", severity="high", port=443, cve=["CVE-2026-1234"])],
    )

    findings = CorrelationEngine({}, intel=FakeIntel()).correlate_asset(asset)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.tools == ["greenbone", "nuclei"]
    assert finding.severity == "critical"
    assert finding.kev is True
    assert finding.confidence == "high"
    assert finding.cwe == ["CWE-79"]
    assert finding.description == "Example vulnerability"


def test_unrelated_config_finding_is_not_merged():
    asset = Asset(ip="10.0.0.11", status="up")
    asset.tools["wazuh_sca"] = ToolResult(
        tool="wazuh_sca",
        status="completed",
        findings=[Finding(tool="wazuh_sca", title="Disable root login", severity="unknown", category="configuration")],
    )
    asset.tools["ssh_audit"] = ToolResult(
        tool="ssh_audit",
        status="completed",
        findings=[Finding(tool="ssh_audit", title="Weak SSH cipher", severity="medium", category="ssh", port=22)],
    )

    findings = CorrelationEngine({}, intel=None).correlate_asset(asset)
    assert len(findings) == 2
