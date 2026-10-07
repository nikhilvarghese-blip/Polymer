from polymer.intelligence.delta import compare_assets
from polymer.models.schema import Asset, CorrelatedFinding


def cf(fid: str, ip: str, cve: str):
    return CorrelatedFinding(
        finding_id=fid,
        asset_ip=ip,
        title=cve,
        severity="high",
        cve=[cve],
    )


def test_delta_new_resolved_unchanged():
    old = Asset(ip="10.0.0.1", status="up", correlated_findings=[
        cf("OLD1", "10.0.0.1", "CVE-2026-0001"),
        cf("OLD2", "10.0.0.1", "CVE-2026-0002"),
    ])
    new = Asset(ip="10.0.0.1", status="up", correlated_findings=[
        cf("NEW1", "10.0.0.1", "CVE-2026-0002"),
        cf("NEW2", "10.0.0.1", "CVE-2026-0003"),
    ])
    delta = compare_assets([new], [old])
    assert delta["summary"] == {"new": 1, "resolved": 1, "unchanged": 1}
