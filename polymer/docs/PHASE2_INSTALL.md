# Polymer Phase 2 - Kali installation

Use only on systems you own or are explicitly authorized to assess.

## Base install

```bash
unzip Polymer-phase2.zip
cd polymer
chmod +x scripts/install-kali-phase2.sh
./scripts/install-kali-phase2.sh
source .venv/bin/activate
polymer doctor --config config/polymer.yaml
```

The installer installs Nmap, Nikto, testssl.sh and enum4linux-ng from Kali packages, installs Polymer in a Python venv, and installs ssh-audit in that venv. It attempts the Kali Nuclei package but leaves a clear warning if Nuclei is unavailable.

## Optional Greenbone / OpenVAS

Greenbone is a full service stack and should be installed separately:

```bash
sudo apt update
sudo apt install -y gvm
sudo gvm-setup
sudo gvm-check-setup
sudo gvm-start
```

Record the admin password printed by gvm-setup and wait for feeds to finish syncing before scanning. The default Kali gvmd socket is `/run/gvmd/gvmd.sock`.

Then:

```bash
export POLYMER_GVM_USERNAME='admin'
export POLYMER_GVM_PASSWORD='YOUR_PASSWORD'
```

Edit `config/polymer.yaml` and set `scan.greenbone.enabled: true`.

## Wazuh SCA

Polymer does not install Wazuh. Point it at an existing Wazuh manager API:

```bash
export POLYMER_WAZUH_USERNAME='polymer-reader'
export POLYMER_WAZUH_PASSWORD='YOUR_PASSWORD'
```

Set `scan.wazuh.enabled: true` and the manager URL in `config/polymer.yaml`.

## Validate

```bash
cp targets.example.txt targets.txt
# edit targets.txt to include only authorized IPs/CIDRs
polymer validate --targets targets.txt --config config/polymer.yaml
polymer doctor --config config/polymer.yaml
polymer plan --targets targets.txt --config config/polymer.yaml --profile standard
polymer scan --targets targets.txt --config config/polymer.yaml --profile standard
```

Profiles: `quick`, `standard`, `web`, `infrastructure`, `full`.
