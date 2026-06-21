#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="S4W"
VENV_DIR=".venv"

echo ""
echo "Installing ${PROJECT_NAME}..."
echo ""

if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: python3 was not found."
  echo "Install it with:"
  echo "sudo apt install python3 python3-venv python3-pip -y"
  exit 1
fi

if ! python3 -m venv --help >/dev/null 2>&1; then
  echo "Error: python3 venv support is not available."
  echo "Install it with:"
  echo "sudo apt install python3-venv -y"
  exit 1
fi

if [ ! -d "$VENV_DIR" ]; then
  python3 -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

python -m pip install --upgrade pip setuptools wheel
pip install -e .

echo ""
echo "${PROJECT_NAME} installed successfully."
echo ""
echo "Activate the virtual environment:"
echo "source ${VENV_DIR}/bin/activate"
echo ""
echo "Check the installation:"
echo "s4w --version"
echo ""
echo "Open the quick guide:"
echo "s4w -help"
echo ""
