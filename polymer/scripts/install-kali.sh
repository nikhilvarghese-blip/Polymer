#!/usr/bin/env bash
set -euo pipefail

KITERUNNER_VERSION="1.0.2"
KITERUNNER_WORDLIST_URL="${KITERUNNER_WORDLIST_URL:-https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz}"
KITERUNNER_WORDLIST_SHA256="${KITERUNNER_WORDLIST_SHA256:-6f7249887cd66fdbb1220caa2281ee6290111ca444d49d4eafabfee2549e40d9}"
KITERUNNER_TMP_DIR=""

cleanup_kiterunner() {
  if [[ -n "${KITERUNNER_TMP_DIR}" && -d "${KITERUNNER_TMP_DIR}" ]]; then
    rm -rf -- "${KITERUNNER_TMP_DIR}"
  fi
}
trap cleanup_kiterunner EXIT

install_kiterunner() {
  local kr_arch
  local kr_sha256
  local kr_archive
  local kr_release_url

  case "$(uname -m)" in
    x86_64|amd64)
      kr_arch="amd64"
      kr_sha256="6f0b70aabf747de592445a690281897eebbc45927e9264185d34ffb11637613b"
      ;;
    aarch64|arm64)
      kr_arch="arm64"
      kr_sha256="ec763297e1a9da49c06fc7853418e5839b03b2326204e7d2dde592f521eddd28"
      ;;
    i386|i686)
      kr_arch="386"
      kr_sha256="bf29b4ed3da7b520937d212dfbc5bb7db8d88944851ec432a36c833b47caf69b"
      ;;
    *)
      echo "Unsupported Kiterunner architecture: $(uname -m)" >&2
      return 1
      ;;
  esac

  KITERUNNER_TMP_DIR="$(mktemp -d /tmp/polymer-kiterunner-install.XXXXXX)"
  kr_archive="kiterunner_${KITERUNNER_VERSION}_linux_${kr_arch}.tar.gz"
  kr_release_url="https://github.com/assetnote/kiterunner/releases/download/v${KITERUNNER_VERSION}/${kr_archive}"

  echo "[+] Installing Kiterunner v${KITERUNNER_VERSION} (${kr_arch})"
  curl -fsSL "${kr_release_url}" -o "${KITERUNNER_TMP_DIR}/${kr_archive}"
  (
    cd "${KITERUNNER_TMP_DIR}"
    echo "${kr_sha256}  ${kr_archive}" | sha256sum -c -
    tar -xzf "${kr_archive}" kr
  )

  echo "[+] Installing Kiterunner API route dataset"
  curl -fsSL "${KITERUNNER_WORDLIST_URL}" -o "${KITERUNNER_TMP_DIR}/routes-small.kite.tar.gz"
  echo "${KITERUNNER_WORDLIST_SHA256}  ${KITERUNNER_TMP_DIR}/routes-small.kite.tar.gz" | sha256sum -c -
  tar -xzf "${KITERUNNER_TMP_DIR}/routes-small.kite.tar.gz" \
    -C "${KITERUNNER_TMP_DIR}" routes-small.kite

  if [[ "${EUID}" -eq 0 ]]; then
    install -m 0755 "${KITERUNNER_TMP_DIR}/kr" /usr/local/bin/kr
    install -d -m 0755 /usr/local/share/kiterunner
    install -m 0644 "${KITERUNNER_TMP_DIR}/routes-small.kite" \
      /usr/local/share/kiterunner/routes-small.kite
  else
    sudo install -m 0755 "${KITERUNNER_TMP_DIR}/kr" /usr/local/bin/kr
    sudo install -d -m 0755 /usr/local/share/kiterunner
    sudo install -m 0644 "${KITERUNNER_TMP_DIR}/routes-small.kite" \
      /usr/local/share/kiterunner/routes-small.kite
  fi

  echo "[+] Kiterunner installed: $(command -v kr)"
  echo "[+] Wordlist installed: /usr/local/share/kiterunner/routes-small.kite"
}

if [[ "${1:-}" == "--kiterunner-only" ]]; then
  if [[ "$#" -ne 1 ]]; then
    echo "Usage: $0 [--kiterunner-only]" >&2
    exit 2
  fi
  install_kiterunner
  exit 0
elif [[ "$#" -ne 0 ]]; then
  echo "Usage: $0 [--kiterunner-only]" >&2
  exit 2
fi

if [[ "${EUID}" -eq 0 ]]; then
  echo "Run this script as a normal user with sudo access, not as root." >&2
  exit 1
fi

sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip nmap git curl ca-certificates

install_kiterunner

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
