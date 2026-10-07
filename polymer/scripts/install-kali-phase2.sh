#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -eq 0 ]]; then
  echo "Run this script as a normal user with sudo access, not as root." >&2
  exit 1
fi

echo "[+] Installing Polymer Phase 2 Kali dependencies"
sudo apt update
sudo apt install -y python3 python3-venv python3-pip pipx git curl ca-certificates nmap nikto testssl.sh enum4linux-ng

if ! command -v nuclei >/dev/null 2>&1; then
  echo "[+] Trying Kali package for nuclei"
  sudo apt install -y nuclei || true
fi

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .

# ssh-audit is installed inside Polymer's venv so the project remains self-contained.
python -m pip install --upgrade ssh-audit

if [[ ! -f config/polymer.yaml ]]; then
  cp config/polymer.example.yaml config/polymer.yaml
fi

echo
echo "[+] Base Phase 2 install complete."
echo "    Activate: source .venv/bin/activate"
echo "    Check:    polymer doctor --config config/polymer.yaml"
echo
if ! command -v nuclei >/dev/null 2>&1; then
  echo "[!] Nuclei is still missing. Install it using ProjectDiscovery's supported method before web scanning."
fi
echo "[i] Greenbone/GVM is optional and is NOT installed by this script. See docs/PHASE2_INSTALL.md."
