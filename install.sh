#!/usr/bin/env bash
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 não encontrado. Instale com: sudo apt install python3 python3-venv python3-pip -y"
  exit 1
fi

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .

echo ""
echo "s4w instalado com sucesso."
echo "Para usar nesta sessão: source .venv/bin/activate"
echo "Ajuda: s4w -help"
