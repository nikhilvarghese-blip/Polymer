# Polymer

Polymer is an asset-centric security assessment orchestrator for authorized
vulnerability and configuration testing. It discovers each target, selects
relevant scanners from the services it finds, normalizes their output, correlates
overlapping findings, enriches known vulnerabilities, and produces reports
organized by IP address.

Polymer does not replace scanner engines. It provides a consistent workflow and
data model across Nmap, Nuclei, Wazuh SCA, ssh-audit, testssl.sh, Nikto,
enum4linux-ng, and Greenbone/GVM.

> Use Polymer only against systems you own or are explicitly authorized to
> assess.

## What Polymer provides

- IP and CIDR validation with private-address safeguards.
- Nmap-led discovery and service-aware scanner selection.
- Quick, web, infrastructure, standard, and full scan profiles.
- Colored overall and per-scanner CLI progress.
- Failure isolation so one scanner error does not discard the scan.
- Cross-tool correlation and deduplication.
- CVE, CWE, CPE, CVSS, and CISA KEV enrichment.
- Confidence and priority scoring for remediation triage.
- Baseline comparison for new, resolved, and unchanged findings.
- Atomic JSON and CSV reports, including a bundle for every requested IP.
- Explicit coverage reporting so incomplete scans are not mistaken for clean
  targets.

## How it works

~~~text
Targets file
    |
    +-- Scope validation
    |
    +-- Nmap discovery
    |       +-- Host status, ports, protocols, products and versions
    |
    +-- Adaptive scanner routing
    |       +-- HTTP(S) -- Nuclei and Nikto
    |       +-- TLS ----- testssl.sh
    |       +-- SSH ----- ssh-audit
    |       +-- SMB ----- enum4linux-ng
    |       +-- Host SCA  Wazuh
    |       +-- General - Greenbone/GVM
    |
    +-- Normalization, correlation and enrichment
    |
    +-- Consolidated and per-IP JSON/CSV reports
~~~

Scanner selection is based on discovered services, configuration, and the
selected profile. Raw scanner artifacts remain available alongside normalized
results.

## Supported integrations

| Integration | Purpose | Default |
| --- | --- | --- |
| Nmap | Host and service discovery | Enabled |
| Nuclei | Template-based web and service checks | Enabled |
| Nikto | Web server assessment | Enabled |
| testssl.sh | TLS configuration assessment | Enabled |
| ssh-audit | SSH configuration assessment | Enabled |
| enum4linux-ng | SMB and NetBIOS enumeration | Enabled |
| Wazuh SCA | Agent-backed configuration findings | Disabled until configured |
| Greenbone/GVM | Broad vulnerability assessment | Disabled in the example configuration |
| NVD and CISA KEV | Vulnerability enrichment and exploitation context | Enabled, best effort |

Only scanners selected by the active profile and applicable to a target are run.
Use **polymer doctor** to see which configured dependencies are ready.

## Requirements

- Python 3.11 or newer.
- Linux is recommended; Kali Linux is the primary native environment.
- External scanner binaries required by the selected profile.
- Network access and privileges appropriate for the authorized assessment.
- Optional service credentials for Wazuh, Greenbone, and NVD.

## Installation

### Kali Linux

Run the installer as a normal user with sudo access:

~~~bash
git clone <your-polymer-repository-url>
cd polymer
./scripts/install-kali.sh
source .venv/bin/activate
~~~

The installer creates a virtual environment, installs Polymer, and attempts to
install the base discovery tools. Install any additional scanners required by
your profile, then verify the environment:

~~~bash
polymer doctor --config config/polymer.yaml
~~~

### Manual installation

~~~bash
git clone <your-polymer-repository-url>
cd polymer
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
cp config/polymer.example.yaml config/polymer.yaml
~~~

For development dependencies:

~~~bash
python -m pip install -e ".[dev]"
~~~

## Define the target scope

Create **targets.txt** from the example:

~~~bash
cp targets.example.txt targets.txt
~~~

The file accepts one IP address or CIDR range per line. Comments are supported:

~~~text
# Authorized application subnet
192.168.56.0/29

# Authorized standalone server
10.20.30.40
~~~

Public targets are blocked by default. The expanded target count is limited by
**scope.max_expanded_hosts** to prevent accidental oversized scans.

Always validate scope before scanning:

~~~bash
polymer validate \
  --targets targets.txt \
  --config config/polymer.yaml
~~~

## Configuration

The main configuration is **config/polymer.yaml**.

~~~yaml
project:
  name: Polymer
  output_dir: output

scope:
  allow_public_ips: false
  max_expanded_hosts: 4096

scan:
  profile: standard
  nmap:
    enabled: true
    binary: nmap
    arguments: ["-Pn", "-sV", "--version-light"]

intelligence:
  enabled: true
  enrichment:
    enabled: true
    offline: false
    nvd_api_key_env: NVD_API_KEY
~~~

Scanner-specific binary names, timeouts, connection details, and enablement
flags are configured under **scan**. Keep secrets in environment variables
rather than YAML files.

### Scan profiles

Profiles are defined in **config/profiles.yaml**:

| Profile | Intended use |
| --- | --- |
| quick | Discovery and lightweight Nuclei checks |
| standard | General-purpose assessment |
| full | All configured scanners, including Greenbone |
| web | Web and TLS-focused assessment |
| infrastructure | SSH, TLS, SMB, host configuration, and Greenbone |

Select a profile with **--profile**. If omitted, Polymer uses **scan.profile**
from the configuration.

## Commands

### Check scanner readiness

~~~bash
polymer doctor --config config/polymer.yaml
~~~

### Validate targets

~~~bash
polymer validate --targets targets.txt --config config/polymer.yaml
~~~

### Preview scanner routing

The plan command performs discovery and shows which scanners would run without
starting the secondary assessment tools:

~~~bash
polymer plan \
  --targets targets.txt \
  --config config/polymer.yaml \
  --profile standard
~~~

### Run a scan

~~~bash
polymer scan \
  --targets targets.txt \
  --config config/polymer.yaml \
  --profile standard
~~~

In an interactive terminal, Polymer displays the NTP-backed server time and
prompts for the scan end time in 24-hour **HH:MM** format. The command start is
captured when `polymer scan` begins. If the requested time has already passed
on that server day, Polymer uses the same time on the following day. For an
unattended run, provide the deadline explicitly:

~~~bash
polymer scan --targets targets.txt --config config/polymer.yaml --end-time 18:30
~~~

The deadline controls scanner work: Polymer does not start another scanner or
target after it expires, and external scanner timeouts are capped to the time
remaining. Correlation and report writing still finish so partial results are
preserved. Every new scan command creates a fresh timer.

Useful scan options:

- **--baseline PATH** compares results with an earlier **polymer.json**.
- **--end-time HH:MM** supplies the server-local scan deadline without a prompt.
- **--no-intelligence** skips correlation and external enrichment.
- **--fail-on-tool-error** returns exit status 2 if a selected scanner fails or
  is unavailable.

### Analyze an existing result

Run correlation, enrichment, CSV generation, or baseline comparison without
rescanning:

~~~bash
polymer analyze \
  --input output/run-OLD/polymer.json \
  --config config/polymer.yaml
~~~

Add **--baseline output/run-BASELINE/polymer.json** for a delta report or
**--output PATH** to choose the analysis directory. Without **--output**,
Polymer creates a unique timestamped analysis directory beside the input.

### Debug command failures

Place the global **--debug** option before the command:

~~~bash
polymer --debug scan --targets targets.txt --config config/polymer.yaml
~~~

## Reports

Each scan receives a unique UTC-timestamped directory:

~~~text
output/run-<UTC timestamp>/
├── scan.log                  # JSON-lines run/IP/scanner timeline and errors
├── polymer.json              # complete normalized result keyed by IP
├── polymer.csv               # canonical final findings report
├── analysis.json             # correlated risk report
├── delta.json                # present when a baseline is supplied
├── assets.csv                # exactly one row per requested IP
├── services.csv              # discovered ports, protocols and products
├── scanner_status.csv        # coverage, failures and partial results
├── raw_findings.csv          # original scanner findings
├── raw/                      # native scanner artifacts
└── by_ip/
    └── 192.168.56.10/
        ├── combined.json
        ├── correlated.json
        ├── report.csv
        ├── summary.csv
        ├── services.csv
        ├── scanner_status.csv
        ├── raw_findings.csv
        └── <scanner>.json
~~~

**polymer.csv** contains correlated findings when correlation is enabled and raw
findings otherwise. **raw_findings.csv** always preserves scanner-level
evidence. Targets without findings receive an explicit summary row, while
**assets.csv** guarantees exactly one row for every requested IP.

**scan.log** is flushed after every event. It records the command start and
deadline, NTP synchronization state, each IP and scanner start/finish timestamp,
elapsed seconds, status, finding count, raw artifact path, error/message text,
scanners triggered per IP, and targets not started before the deadline.

Important report fields include:

- Asset and service identity.
- Coverage status and assessment completeness.
- Stable finding ID, severity, category, confidence, and priority.
- CVE, CWE, CPE, CVSS, and confirmed CISA KEV data.
- Source scanners, scanner status, evidence, and remediation.
- Raw and correlated finding counts.

Treat **coverage_status=partial**, **coverage_status=not_assessed**, or
**assessment_complete=no** as incomplete coverage, not as a clean result.

The complete CSV schema is documented in **docs/CSV_REPORTS.md**.

## Compare scans

Use a prior **polymer.json** as the baseline:

~~~bash
polymer scan \
  --targets targets.txt \
  --config config/polymer.yaml \
  --baseline output/run-PREVIOUS/polymer.json
~~~

Polymer writes **delta.json** with new, resolved, and unchanged correlated
findings. The same comparison is available through **polymer analyze**.

## Vulnerability intelligence

Polymer can enrich CVEs using NVD and mark confirmed entries from the CISA Known
Exploited Vulnerabilities catalog. Enrichment is best effort; scanner results
remain usable if an external service is unavailable.

An NVD API key is optional but recommended:

~~~bash
export NVD_API_KEY='...'
~~~

For cache-only operation:

~~~yaml
intelligence:
  enabled: true
  enrichment:
    enabled: true
    offline: true
~~~

Polymer reports KEV as **yes** only when confirmed. Unavailable or unevaluated
intelligence is labeled **not_evaluated** instead of being reported as a
definitive negative.

## Wazuh configuration

Enable the integration in **config/polymer.yaml**:

~~~yaml
scan:
  wazuh:
    enabled: true
    url: "https://wazuh-manager.example:55000"
    verify_tls: true
    username_env: POLYMER_WAZUH_USERNAME
    password_env: POLYMER_WAZUH_PASSWORD
~~~

Provide credentials through the named environment variables:

~~~bash
export POLYMER_WAZUH_USERNAME='polymer-reader'
export POLYMER_WAZUH_PASSWORD='...'
~~~

Use a least-privilege account that can match agents and read SCA results.

## Greenbone configuration

Greenbone uses **python-gvm** and a local **gvmd** Unix socket. Configure the
socket, credentials, scan configuration ID, and scanner ID under
**scan.greenbone**.

~~~bash
export POLYMER_GVM_USERNAME='polymer'
export POLYMER_GVM_PASSWORD='...'
polymer doctor --config config/polymer.yaml
~~~

Greenbone is optional and can remain disabled when GVM is not installed.

## Docker

The Docker image includes Polymer, Nmap, and Nuclei:

~~~bash
cp config/polymer.example.yaml config/polymer.yaml
cp targets.example.txt targets.txt
docker compose build
docker compose run --rm polymer validate \
  --targets /app/targets.txt \
  --config /app/config/polymer.yaml
docker compose run --rm polymer scan \
  --targets /app/targets.txt \
  --config /app/config/polymer.yaml
~~~

Scanner networking, raw sockets, host access, and external service connections
may require deployment-specific Docker permissions or network settings.

## Exit behavior

- Successful commands return exit status 0.
- Runtime or configuration failures return exit status 1.
- **scan --fail-on-tool-error** returns exit status 2 for scanner failures or
  unavailable selected tools, after reports have been written.
- User interruption returns exit status 130.

Without **--fail-on-tool-error**, Polymer completes the report and highlights
scanner issues in the CLI, **polymer.json**, and **scanner_status.csv**.

## Troubleshooting

Start with:

~~~bash
polymer doctor --config config/polymer.yaml
~~~

Common checks:

- Activate the virtual environment before running Polymer.
- Confirm every enabled scanner is available in PATH.
- Verify scanner binary names and timeouts in **config/polymer.yaml**.
- Confirm the selected profile contains the expected scanner.
- Check that Wazuh and Greenbone credentials are exported.
- Verify the Greenbone socket exists and is accessible.
- Use **polymer --debug ...** for a full traceback.
- Review **scanner_status.csv** and per-tool JSON for partial failures.

## Development

~~~bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest -q
~~~

Useful Make targets:

~~~bash
make install
make validate
make scan
make test
make docker-build
~~~

## License

Apache-2.0.
