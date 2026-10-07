# Polymer

**Polymer** is an asset-centric security assessment orchestrator for authorized vulnerability and configuration assessments. It combines specialized tools behind one normalized data model and groups every result by target IP.

> Polymer is intended only for systems you own or are explicitly authorized to assess.

## Status

Phase 2 / v0.2.0. Adaptive routing is implemented for Nmap, Nuclei, Wazuh SCA, ssh-audit, testssl.sh, Nikto, enum4linux-ng and optional Greenbone/GVM. See `docs/PHASE2_INSTALL.md`.

## Why the architecture is IP-centric

```text
IP address
├── inventory / services (Nmap)
├── web findings (Nuclei)
├── host configuration findings (Wazuh SCA)
└── future adapters (Greenbone, TLS, SSH, SMB, ...)
```

Results are written both as one `polymer.json` keyed by IP and as `by_ip/<IP>/...` artifacts.

## Quick start on Kali

```bash
git clone <your-polymer-repository-url>
cd polymer
./scripts/install-kali.sh
cp targets.example.txt targets.txt
# edit targets.txt so it contains ONLY authorized IPs/CIDRs
source .venv/bin/activate
polymer validate --targets targets.txt --config config/polymer.yaml
polymer scan --targets targets.txt --config config/polymer.yaml
```

## Wazuh SCA

Edit `config/polymer.yaml`:

```yaml
scan:
  wazuh:
    enabled: true
    url: "https://wazuh-manager.example:55000"
    verify_tls: true
    username_env: "POLYMER_WAZUH_USERNAME"
    password_env: "POLYMER_WAZUH_PASSWORD"
```

Then export credentials instead of storing them in Git:

```bash
export POLYMER_WAZUH_USERNAME='polymer-reader'
export POLYMER_WAZUH_PASSWORD='...'
```

The account should have only the permissions required to list/match agents and read SCA results.

## Docker

Docker is included for reproducibility, but scanner networking may require deployment-specific settings. Start by creating:

```bash
cp config/polymer.example.yaml config/polymer.yaml
cp targets.example.txt targets.txt
docker compose build
docker compose run --rm polymer validate --targets /app/targets.txt --config /app/config/polymer.yaml
```

The base image currently includes Nmap. Nuclei is deliberately not installed from an unpinned curl pipe in the Dockerfile; Phase 5 will pin and verify third-party scanner releases. Until then, native Kali installation is the preferred Phase 1 path for Nuclei.

## Output

```text
output/run-<UTC timestamp>/
├── polymer.json
├── raw/
│   ├── nmap/
│   └── nuclei/
└── by_ip/
    └── 192.168.56.10/
        ├── combined.json
        ├── nmap.json
        ├── nuclei.json
        └── wazuh_sca.json
```

## Phase roadmap

1. Core orchestration and normalized IP-centric output.
2. Greenbone/OpenVAS, TLS, SSH, SMB, Nikto/ZAP and adaptive routing.
3. Correlation, deduplication, CVE/CPE enrichment and retesting.
4. PostgreSQL, API, workers, web dashboard and formal reporting.
5. CI/CD, release hardening, signed/pinned distribution and plugin SDK.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
cp config/polymer.example.yaml config/polymer.yaml
cp targets.example.txt targets.txt
polymer validate --targets targets.txt --config config/polymer.yaml
```


## Phase 2 commands

```bash
polymer doctor --config config/polymer.yaml
polymer plan --targets targets.txt --config config/polymer.yaml --profile standard
polymer scan --targets targets.txt --config config/polymer.yaml --profile standard
```
