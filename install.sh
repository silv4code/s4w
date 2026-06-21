#!/usr/bin/env bash
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found. Install it with:"
  echo "sudo apt install python3 python3-venv python3-pip -y"
  exit 1
fi

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -e .

echo ""
echo "S4W installed successfully."
echo "To use it in this session:"
echo "source .venv/bin/activate"
echo ""
echo "Quick guide:"
echo "s4w -help"
