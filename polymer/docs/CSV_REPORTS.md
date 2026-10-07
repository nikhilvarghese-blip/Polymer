# Polymer CSV report bundle

Every `polymer scan` and `polymer analyze` run writes a versioned CSV bundle in
addition to the lossless JSON reports. The CSV files use UTF-8, stable
snake-case headers, RFC-compatible quoting, atomic writes, and spreadsheet
formula-injection protection.

## Consolidated files

| File | Purpose |
| --- | --- |
| `polymer.csv` | Canonical final report. One correlated finding per row when Phase 3 is available, otherwise one raw finding per row. Targets with no findings receive an explicit `asset_summary` row. |
| `raw_findings.csv` | Every source-tool finding before correlation, retained for evidence review and scanner-level reconciliation. |
| `assets.csv` | Exactly one row per requested IP, including scan coverage, services, scanner failures, finding counts, highest severity, and maximum priority. |
| `services.csv` | Discovered ports, protocols, products, versions, and related finding counts. |
| `scanner_status.csv` | Per-IP execution status for each scanner, including partial results, errors, raw artifact paths, and finding counts. |

The `report_schema_version` column identifies the export contract. Version 1.0
includes Polymer priority and confidence scores, CVSS, CVE/CWE/CPE, CISA KEV,
affected ports, source scanners, evidence, remediation, scan completeness, and
scanner diagnostics.

`known_exploited=yes` means Polymer confirmed the CVE in CISA KEV.
`known_exploited=not_evaluated` is deliberately conservative: it does not claim
that a CVE is absent from KEV when intelligence was disabled, offline, or
unavailable. `count_basis` states whether severity totals are correlated or raw.

## Per-IP files

Each requested target also receives an isolated report bundle:

```text
by_ip/<IP>/
├── report.csv
├── raw_findings.csv
├── summary.csv
├── services.csv
└── scanner_status.csv
```

This guarantees that every IP supplied to the scan has an export, including
offline hosts, clean hosts, and hosts whose coverage was incomplete. A row with
`coverage_status=partial` or `assessment_complete=no` must not be interpreted as
a clean bill of health; consult `scanner_status.csv` and `scanner_messages`.

## Canonical versus raw findings

`polymer.csv` avoids double-counting. If correlation ran successfully, it emits
the deduplicated correlated findings. If intelligence was disabled, it falls
back to raw scanner findings. `raw_findings.csv` always contains the original
tool-level findings, regardless of correlation.
