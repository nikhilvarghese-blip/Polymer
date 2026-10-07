# Polymer Architecture

## Guiding model

Polymer is asset-centric. The canonical object is an IP address. Every scanner adapter contributes normalized observations or findings to that asset.

```text
Authorized targets
      |
Target parser / scope guard
      |
      v
Nmap discovery + service inventory
      |
      +-----------------------+
      |                       |
Service-aware scanners    Host/config sources
Nuclei, TLS, SSH, SMB     Wazuh SCA
      |                       |
      +-----------+-----------+
                  v
          Normalized schema
                  |
                  v
      correlation + deduplication
                  |
                  v
      IP-grouped JSON / HTML / DB
```

## Five delivery phases

### Phase 1 — Core Orchestrator (current)
- IP/CIDR scope parser and safety guardrails
- canonical Asset / Service / Finding / ToolResult models
- Nmap adapter using XML
- Nuclei adapter using JSONL
- Wazuh SCA adapter using the Wazuh REST API
- per-IP and global JSON output
- Kali install script, Python package, Dockerfile, Compose file

Exit criterion: a fresh clone can validate a target file and execute the enabled adapters with results grouped by IP.

### Phase 2 — Scanner Expansion
- Greenbone/OpenVAS integration
- testssl.sh
- ssh-audit
- Nikto
- enum4linux-ng / SMB checks
- optional ZAP integration
- scanner capability registry and service-routing rules

Exit criterion: scanner selection is adaptive to discovered services and each adapter has fixtures/parser tests.

### Phase 3 — Correlation & Intelligence
- canonical fingerprints for deduplication
- CVE/CPE/CWE enrichment
- confidence scoring from multiple sources
- severity normalization
- Wazuh coverage status vs network scan coverage
- baseline/retest comparison

Exit criterion: Polymer creates one correlated asset view instead of merely concatenating results.

### Phase 4 — Platform & Reporting
- PostgreSQL persistence
- REST API
- background worker/queue
- web dashboard
- HTML/PDF/CSV exports
- scan history, remediation status and retest workflow

Exit criterion: multi-scan operational workflow is usable without reading raw scanner files.

### Phase 5 — Distribution & Hardening
- signed releases / pinned dependency strategy
- CI tests and integration test lab
- package/container release automation
- secrets handling and TLS defaults
- RBAC for Polymer UI/API
- plugin SDK and contributor docs
- upgrade/migration procedure

Exit criterion: predictable deployment from GitHub with documented upgrade and rollback paths.

## Scanner contract
Every adapter owns execution/retrieval and parsing, but returns the same `ToolResult`. Scanner-specific raw artifacts remain preserved under the run directory for evidence and debugging.

## Wazuh design
Polymer does not attempt to remotely run Wazuh SCA. It authenticates to an existing Wazuh manager, maps the target IP to an enrolled agent, and reads that agent's SCA policy/check state. No matching agent is represented explicitly as coverage information.

## Scope controls
Polymer accepts explicit IPs/CIDRs only in V1. Public IPs are blocked by default, expansion has a configurable host cap, and scanners receive only the canonical validated inventory.
