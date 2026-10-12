#!/usr/bin/env bash
set -euo pipefail

KITERUNNER_VERSION="1.0.2"
KITERUNNER_WORDLIST_URL="${KITERUNNER_WORDLIST_URL:-https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz}"
KITERUNNER_WORDLIST_SHA256="${KITERUNNER_WORDLIST_SHA256:-6f7249887cd66fdbb1220caa2281ee6290111ca444d49d4eafabfee2549e40d9}"

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
    exit 1
    ;;
esac

kr_tmp_dir="$(mktemp -d /tmp/polymer-kiterunner-install.XXXXXX)"
trap 'rm -rf -- "${kr_tmp_dir}"' EXIT
kr_archive="kiterunner_${KITERUNNER_VERSION}_linux_${kr_arch}.tar.gz"
kr_release_url="https://github.com/assetnote/kiterunner/releases/download/v${KITERUNNER_VERSION}/${kr_archive}"

echo "[+] Installing Kiterunner v${KITERUNNER_VERSION} (${kr_arch})"
curl -fsSL "${kr_release_url}" -o "${kr_tmp_dir}/${kr_archive}"
(
  cd "${kr_tmp_dir}"
  echo "${kr_sha256}  ${kr_archive}" | sha256sum -c -
  tar -xzf "${kr_archive}" kr
)

echo "[+] Installing Kiterunner API route dataset"
curl -fsSL "${KITERUNNER_WORDLIST_URL}" -o "${kr_tmp_dir}/routes-small.kite.tar.gz"
echo "${KITERUNNER_WORDLIST_SHA256}  ${kr_tmp_dir}/routes-small.kite.tar.gz" | sha256sum -c -
tar -xzf "${kr_tmp_dir}/routes-small.kite.tar.gz" -C "${kr_tmp_dir}" routes-small.kite

if [[ "${EUID}" -eq 0 ]]; then
  install -m 0755 "${kr_tmp_dir}/kr" /usr/local/bin/kr
  install -d -m 0755 /usr/local/share/kiterunner
  install -m 0644 "${kr_tmp_dir}/routes-small.kite" /usr/local/share/kiterunner/routes-small.kite
else
  sudo install -m 0755 "${kr_tmp_dir}/kr" /usr/local/bin/kr
  sudo install -d -m 0755 /usr/local/share/kiterunner
  sudo install -m 0644 "${kr_tmp_dir}/routes-small.kite" /usr/local/share/kiterunner/routes-small.kite
fi

echo "[+] Kiterunner installed: $(command -v kr)"
echo "[+] Wordlist installed: /usr/local/share/kiterunner/routes-small.kite"
