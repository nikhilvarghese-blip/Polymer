# Polymer Phase 3 - Correlation and Vulnerability Intelligence

Phase 3 runs after the Phase 2 scanner adapters. It does not replace or modify raw scanner evidence.

## Pipeline

1. Flatten scanner findings per asset/IP.
2. Normalize severity labels.
3. Deduplicate findings by CVE + compatible port, or exact normalized title/category/port when no CVE exists.
4. Correlate independent scanner evidence into one Polymer finding.
5. Enrich CVEs from NVD CVE API 2.0 (best effort, cached).
6. Add CWE, CPE, CVSS score/vector/version where NVD supplies them.
7. Mark CVEs present in the CISA Known Exploited Vulnerabilities catalog.
8. Calculate confidence and priority scores.
9. Produce `analysis.json` and per-IP `correlated.json`.
10. Optionally compare with an earlier Polymer result and produce `delta.json`.

## Files

A normal Phase 3 run contains:

```
output/run-<timestamp>/
  polymer.json
  polymer.csv                # canonical final CSV report
  raw_findings.csv           # source-tool findings
  assets.csv                 # one row per requested IP
  services.csv
  scanner_status.csv
  analysis.json
  delta.json                 # when --baseline is supplied
  cache/vuln_intel/          # run-local NVD/CISA cache
  raw/                       # Phase 2 raw scanner artifacts
  by_ip/<IP>/
    combined.json
    correlated.json
    report.csv
    summary.csv
    services.csv
    scanner_status.csv
    raw_findings.csv
    <tool>.json
```

## Commands

Run scan + Phase 3 analysis:

```bash
polymer scan --targets targets.txt --config config/polymer.yaml --profile standard
```

Compare against an earlier scan:

```bash
polymer scan --targets targets.txt --baseline output/run-OLD/polymer.json
```

Re-analyze an existing Phase 2/3 result without rescanning:

```bash
polymer analyze --input output/run-OLD/polymer.json
```

Without `--output`, re-analysis uses a unique
`analysis-<UTC timestamp>/` directory beside the input so older reports cannot
leave stale per-IP files in a later analysis.

Re-analyze and compare:

```bash
polymer analyze \
  --input output/run-NEW/polymer.json \
  --baseline output/run-OLD/polymer.json
```

Disable external enrichment but keep correlation by setting `intelligence.enrichment.offline: true`.
Use `--no-intelligence` on `polymer scan` to skip Phase 3 entirely.

## NVD API key

An NVD API key is optional but recommended for repeated or larger scans. Polymer reads it from `NVD_API_KEY` by default:

```bash
export NVD_API_KEY='...'
```

Never commit API keys to the repository.

## Confidence model

Confidence is deliberately separate from severity. It rises when multiple independent tools agree, a CVE identifier is present, authoritative enrichment is available, a concrete port is associated, or CISA KEV confirms known exploitation.

## Priority score

Priority combines severity, confidence and KEV status into a 0-100 triage value. It is a Polymer prioritization aid, not a replacement for CVSS.
