#!/usr/bin/env bash
set -euo pipefail

echo "[i] install-kali-phase2.sh is retained as a compatibility wrapper."
echo "[i] All local scanner installation is now handled by scripts/install-kali.sh."
exec "$(dirname "$0")/install-kali.sh" "$@"
