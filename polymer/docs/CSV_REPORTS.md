# Polymer CSV report bundle

Every `polymer scan` and `polymer analyze` run writes a versioned CSV bundle in
addition to the lossless JSON reports. The CSV files use UTF-8, stable
snake-case headers, RFC-compatible quoting, atomic writes, and spreadsheet
formula-injection protection.

## Consolidated files

| File | Purpose |
| --- | --- |
| `consolidated_findings.csv` | Operational all-tools export. One row per raw tool finding, plus scanner-summary rows for tools with no findings and target-summary rows for requested IPs that were not started. Includes explicit IP, tool, status, service, finding, evidence, remediation, artifact, and message fields. |
| `polymer.csv` | Canonical final report. One correlated finding per row when Phase 3 is available, otherwise one raw finding per row. Targets with no findings receive an explicit `asset_summary` row. |
| `raw_findings.csv` | Every source-tool finding before correlation, retained for evidence review and scanner-level reconciliation. |
| `assets.csv` | Exactly one row per requested IP, including scan coverage, services, scanner failures, finding counts, highest severity, and maximum priority. |
| `services.csv` | Discovered ports, protocols, products, versions, and related finding counts. |
| `scanner_status.csv` | Per-IP execution status for each scanner, including partial results, errors, raw artifact paths, and finding counts. |

The `report_schema_version` column identifies the export contract. Version 1.0
includes Polymer priority and confidence scores, CVSS, CVE/CWE/CPE, CISA KEV,
affected ports, source scanners, evidence, remediation, scan completeness, and
scanner diagnostics.

The consolidated export uses `record_type=finding` for a source-tool finding,
`scanner_summary` when a recorded tool produced no finding rows, and
`target_summary` when a requested IP was never started. Its `scan_outcome`
values are `passed`, `failed`, and `not_started`. These values describe scan
execution coverage and must not be interpreted as vulnerability pass/fail.

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

Use `consolidated_findings.csv` for operational filtering by IP, tool, scanner
status, port, product, or severity. Use `polymer.csv` for deduplicated risk and
remediation reporting.

## Human-readable and evidence fields

The management-facing fields are `finding_title`/`title`, `description`,
`severity`, `category`, and `remediation`. These contain normalized text derived
from explicit scanner findings. Polymer does not turn arbitrary scanner objects
into titles, descriptions, or remediation advice. If a scanner does not supply
a recommendation, the remediation field remains empty.

The `evidence` column contains machine-readable scanner fields needed for
technical validation and auditability. It may contain nested scanner structure,
but it is not used as the management-facing finding narrative. The complete
scanner output remains in the path named by `raw_artifact`/`raw_artifacts`.

## Scanner normalization rules

| Scanner | Management finding source | Severity and recommendation handling |
| --- | --- | --- |
| Nmap | Host, port, protocol, service, product, and version inventory is written to `services.csv`; Nmap inventory is not mislabeled as a vulnerability. | Execution state is written to `scanner_status.csv`. |
| Kiterunner | Each in-scope method and URL is an `api_discovery` observation with its HTTP status. | Always informational; response chains remain technical evidence, not vulnerability prose. |
| Nuclei | Template name, description, matched target, template ID, and explicit CVE classification. | Uses the template's severity and remediation only when supplied by Nuclei. |
| Nikto | The scanner's vulnerability message, test ID, URL/method, references, and explicit CVEs. | Nikto does not provide a reliable severity in its JSON contract, so severity remains `unknown`; remediation stays empty unless the scanner supplies it. |
| testssl.sh | One row per explicit `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` result, with a readable check title and the exact scanner finding as its description. | `OK` and `INFO` are not vulnerabilities. `WARN` and `FATAL` are scanner/check failures and affect tool status instead of creating false findings. |
| ssh-audit | One row per affected algorithm, including algorithm class, scanner notes, source rating, and requested action. | Severity is mapped from ssh-audit's own rating. Remediation is emitted only for an explicit ssh-audit add/remove/change recommendation. |
| enum4linux-ng | Only exact boolean results for signing, SMBv1-only support, null sessions, and guest sessions become findings. | Severity remains `unknown` because enum4linux-ng does not assign one. General enumeration text cannot trigger a finding. |
| Wazuh SCA | Failed checks only, with policy/check ID, title, reason, and scanner-provided remediation. | Severity remains `unknown` unless a future source field supplies it; structured objects are never copied into narrative columns. |
| Greenbone/GVM | Result name, description, NVT OID, location/protocol, CVSS score, CVEs, QoD, and result ID. | Positive-CVSS results are vulnerabilities. CVSS 0/Greenbone Log inventory remains an `observation`. Solutions are copied only from Greenbone's explicit solution field/tag. |

Blank remediation is intentional: it means the source scanner did not provide
one. Polymer does not manufacture advice or vulnerability claims to fill empty
cells. Scanner warnings, corrupt artifacts, non-zero exits, and incomplete
checks are represented as scanner status/messages so an incomplete assessment
cannot be mistaken for a clean result.
