#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -eq 0 ]]; then
  echo "Run this script as a normal user with sudo access, not as root." >&2
  exit 1
fi

sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip nmap git curl ca-certificates

if ! command -v nuclei >/dev/null 2>&1; then
  sudo apt-get install -y nuclei || true
fi
if ! command -v nuclei >/dev/null 2>&1; then
  echo "[!] nuclei is not installed. Install the current ProjectDiscovery release using their supported installation method, then run: polymer doctor"
fi

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .

if [[ ! -f config/polymer.yaml ]]; then
  cp config/polymer.example.yaml config/polymer.yaml
fi

echo "Polymer installed. Activate with: source .venv/bin/activate"
echo "Then run: polymer doctor --config config/polymer.yaml\nThen run: polymer validate --targets targets.example.txt --config config/polymer.yaml"
