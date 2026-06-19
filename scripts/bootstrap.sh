#!/usr/bin/env bash
set -euo pipefail

DEV=false
if [[ "${1:-}" == "--dev" ]]; then
  DEV=true
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

if [[ ! -x ".venv/bin/python" ]]; then
  python3 -m venv .venv
fi

.venv/bin/python -m pip install --upgrade pip

if [[ "$DEV" == "true" ]]; then
  .venv/bin/python -m pip install -r requirements-dev.txt
else
  .venv/bin/python -m pip install -r requirements.txt
fi

if [[ ! -f ".env" && -f ".env.example" ]]; then
  cp .env.example .env
fi

echo "Bootstrap complete."
echo "Run: ./scripts/run.sh"
