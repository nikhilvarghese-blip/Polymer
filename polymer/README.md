# Polymer

Polymer is an asset-centric security assessment orchestrator for authorized
vulnerability and configuration testing. It discovers each target, selects
relevant scanners from the services it finds, normalizes their output, correlates
overlapping findings, enriches known vulnerabilities, and produces reports
organized by IP address.

Polymer does not replace scanner engines. It provides a consistent workflow and
data model across Nmap, Kiterunner, Nuclei, Wazuh SCA, ssh-audit, testssl.sh, Nikto,
enum4linux-ng, and Greenbone/GVM.

> Use Polymer only against systems you own or are explicitly authorized to
> assess.

## What Polymer provides

- IP and CIDR validation with private-address safeguards.
- Nmap-led discovery and service-aware scanner selection.
- Discovery, quick, API, web, infrastructure, standard, and full scan profiles.
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
    |       +-- HTTP(S) -- Kiterunner API discovery
    |       |                 +-- discovered routes feed Nuclei VA
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

| Integration | What it assesses | When it runs |
| --- | --- | --- |
| Nmap | Live hosts, TCP services (plus UDP when configured), products, and versions | Always; depth depends on profile |
| Kiterunner | Hidden API routes, methods, parameters, and request bodies | HTTP(S) services |
| Nuclei | Template-driven CVEs, exposures, misconfigurations, web/API and network checks | IPs and discovered HTTP/API targets |
| Nikto | Dangerous files, outdated web components, headers, and web-server weaknesses | HTTP(S) services |
| testssl.sh | Protocols, ciphers, certificates, and known TLS weaknesses | TLS services |
| ssh-audit | SSH algorithms, key exchange, host keys, ciphers, and MAC weaknesses | SSH services |
| enum4linux-ng | SMB/NetBIOS exposure, anonymous access, and signing observations | SMB/NetBIOS services |
| Wazuh SCA | Authenticated operating-system and configuration policy findings | Hosts with a matched Wazuh agent |
| Greenbone/GVM | Broad network vulnerability assessment and CVT coverage | Full/infrastructure profiles when enabled |
| NVD and CISA KEV | CVE enrichment and confirmed known-exploitation context | Correlation phase, best effort |

Only scanners selected by the active profile are considered. Adaptive profiles
run applicable scanners; the full profile records an explicit result for every
enabled scanner. Use **polymer doctor** to see which configured dependencies are
ready.

## Requirements

- Python 3.11 or newer.
- Linux is recommended; Kali Linux is the primary native environment.
- External scanner binaries required by the selected profile.
- Kiterunner's `routes-small.kite` API route dataset.
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

The installer creates a virtual environment, installs Polymer, installs the
pinned and checksum-verified Kiterunner binary and API route dataset, and
installs the local CLI scanners used by the discovery, quick, API, web, and
standard profiles: Nmap, Nuclei when available from Kali, Nikto, testssl.sh,
enum4linux-ng, and ssh-audit. Verify the environment:

~~~bash
polymer doctor --config config/polymer.yaml
~~~

Greenbone/GVM and Wazuh are service integrations rather than standalone local
binaries. Configure their services, feeds, agents, socket/API access, and
credentials before expecting them to run in infrastructure or full scans.

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

Kiterunner is a Go binary rather than a Python dependency. On Kali, its pinned
binary and route dataset are installed as part of `./scripts/install-kali.sh`.
Manual Python installation does not install external scanner binaries.

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
  routing: adaptive
  nmap:
    enabled: true
    binary: nmap
    arguments: ["-Pn", "-sV", "--version-light"]
  kiterunner:
    enabled: true
    binary: kr
    wordlist: /usr/local/share/kiterunner/routes-small.kite
    max_connections_per_host: 3
    fail_status_codes: [404]
    headers_env: POLYMER_API_HEADERS
  nuclei:
    enabled: true
    scan_ip: true
    headers_env: POLYMER_API_HEADERS

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

### API discovery and vulnerability assessment

For every discovered HTTP(S) service, Polymer runs Kiterunner before Nuclei.
Kiterunner uses contextual routes, methods, parameters, and request bodies to
identify API endpoints. Polymer normalizes those results as `api_discovery`
observations and passes the original service URLs plus all in-scope discovered
API URLs to Nuclei through a target file. Nuclei findings matched beneath those
routes are categorized as `api` and retain `target_source: kiterunner` evidence.

Protected `401` and `403` routes are intentionally retained as discovered APIs;
only `404` is excluded by default. To perform an authenticated assessment,
provide headers as a JSON object through the configured environment variable:

~~~bash
export POLYMER_API_HEADERS='{"Authorization":"Bearer TOKEN","X-API-Key":"VALUE"}'
~~~

The same headers are supplied to both Kiterunner and Nuclei without being
written to configuration or scan logs. Tune Kiterunner concurrency and endpoint
limits under `scan.kiterunner` to match the authorized target's capacity.
Kiterunner's contextual dataset can send methods such as POST, PUT, PATCH, and
DELETE with generated values. For targets where state changes are unacceptable,
set `scan.kiterunner.force_method: GET`, understanding that this reduces
method-specific API coverage.

### Scan profiles

Profiles are defined in **config/profiles.yaml**:

| Profile | Scanner coverage | Intended use |
| --- | --- | --- |
| discovery | Nmap only | Inventory live hosts, ports, services, products, and versions |
| quick | Nmap + Nuclei | Fast initial exposure and template-based check |
| api | Nmap + Kiterunner + Nuclei | Discover API routes first, then assess the roots and discovered routes |
| web | Nmap + Kiterunner + Nuclei + Nikto + testssl.sh | Web, API, web-server, and TLS assessment |
| infrastructure | Nmap + Wazuh + ssh-audit + testssl.sh + enum4linux-ng + Greenbone | Server, network-service, SMB, SSH, TLS, and authenticated host configuration assessment |
| standard | Every service-specific scanner except Greenbone | General-purpose assessment with adaptive service routing |
| full | Every enabled scanner, including Greenbone | Deepest built-in assessment and explicit per-tool accounting |

Select a profile with **--profile**. If omitted, Polymer uses **scan.profile**
from the configuration. Adaptive profiles only start a scanner when Nmap finds
a compatible service. The **full** profile uses exhaustive routing: every
enabled scanner is scheduled for every live IP. A scanner that cannot apply to
that IP records **not_applicable** with a reason rather than disappearing from
coverage. Kiterunner still runs before Nuclei so discovered API routes are
included in the vulnerability assessment.

The **full** profile also changes Nmap discovery from the default most-common
ports to all 65,535 TCP ports, uses full version probing, and gives discovery a
longer timeout. Nuclei receives the IP itself for network templates plus every
HTTP root and in-scope API route. This profile can take many hours on a large
scope; use a realistic **--end-time** and review incomplete coverage before
treating any target as assessed.

Examples for every scan type:

~~~bash
# Inventory only
polymer scan --targets targets.txt --config config/polymer.yaml --profile discovery

# Fast first pass
polymer scan --targets targets.txt --config config/polymer.yaml --profile quick

# API discovery followed by API vulnerability assessment
polymer scan --targets targets.txt --config config/polymer.yaml --profile api

# Web, API, and TLS assessment
polymer scan --targets targets.txt --config config/polymer.yaml --profile web

# Server and network infrastructure assessment
polymer scan --targets targets.txt --config config/polymer.yaml --profile infrastructure

# Balanced general-purpose assessment
polymer scan --targets targets.txt --config config/polymer.yaml --profile standard

# Deepest built-in assessment; all enabled tools are accounted for
polymer scan --targets targets.txt --config config/polymer.yaml --profile full
~~~

Before **standard**, **infrastructure**, or **full**, run **polymer doctor**.
Tools disabled in **config/polymer.yaml**, missing from `PATH`, lacking required
credentials, or not applicable to the discovered service cannot produce
coverage. For authenticated API testing, export **POLYMER_API_HEADERS**. For
authenticated host checks, configure Wazuh agents. For broad VA, configure and
update Greenbone feeds and credentials.

### Coverage boundaries

No automated scanner can guarantee that it found every vulnerability. Results
depend on network visibility, credentials, scanner and template/feed freshness,
rate limits, application state, scan duration, and whether a weakness requires
business-logic or manual exploitation. Polymer deliberately performs assessment
and enumeration; it does not automatically exploit findings.

For the strongest defensible coverage:

1. Use **--profile full** with all dependencies ready and sufficient time for
   the all-TCP-port discovery and Greenbone task.
2. Supply authorized authentication for APIs, Wazuh, and Greenbone. Compare
   authenticated and unauthenticated results where permitted.
3. Update Nuclei templates, Greenbone feeds, Kiterunner routes, Nmap service
   data, and vulnerability intelligence before the run.
4. Review **scanner_status.csv** for failed, unavailable, skipped, or
   not-applicable tools, and treat **assessment_complete=no** as incomplete.
5. Add an authorized UDP discovery pass when UDP exposure is in scope; the
   built-in full profile scans all TCP ports but does not force a privileged
   all-UDP scan.
6. Supplement automation with authenticated application testing, source/code
   review, cloud configuration review, and manual business-logic testing.

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

At completion, the CLI prints a run-status table with requested, scanned,
not-scanned, passed, and failed IP totals, followed by a colored per-IP table
showing host state, open services, tools performed, tool issues, and raw versus
correlated finding counts. Green `PASS` and red `FAIL` describe scanner
execution coverage—not whether vulnerabilities were found.

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
├── consolidated_findings.csv # every tool finding and tool execution status
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

**consolidated_findings.csv** is the operational handoff for scan, server, and
network teams. It explicitly records IP, host and coverage state, tool name and
status, finding title and severity, affected service/product, CVEs, evidence,
remediation, scanner messages, and artifact paths. Tools with no findings still
receive a scanner-summary row, and requested IPs that were not started receive
a target-summary row.

**polymer.csv** contains deduplicated correlated findings when correlation is
enabled and raw findings otherwise. **raw_findings.csv** always preserves the
original scanner-level evidence. Targets without findings receive an explicit
summary row, while **assets.csv** guarantees exactly one row for every requested
IP.

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

The Docker image includes Polymer, Nmap, Kiterunner, its small API route dataset,
and Nuclei:

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
- Confirm `/usr/local/share/kiterunner/routes-small.kite` exists.
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
