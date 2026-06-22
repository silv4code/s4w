#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

echo "[s4w] Installer for Kali Linux and Debian-based systems"
echo

missing=()
for cmd in git python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    missing+=("$cmd")
  fi
done

if ! python3 -m venv --help >/dev/null 2>&1; then
  missing+=("python3-venv")
fi

if ! command -v whois >/dev/null 2>&1; then
  missing+=("whois")
fi

if ((${#missing[@]} > 0)); then
  echo "[s4w] Missing dependency hint: ${missing[*]}"
  echo "[s4w] On Kali, install the recommended packages with:"
  echo "      sudo apt update"
  echo "      sudo apt install git python3 python3-pip python3-venv whois -y"
  echo
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "[s4w] python3 is required. Aborting."
  exit 1
fi

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .

echo
echo "[s4w] Installation completed."
echo "[s4w] Activate with: source .venv/bin/activate"
echo "[s4w] Try: s4w -help"
