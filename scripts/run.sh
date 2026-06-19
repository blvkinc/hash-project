#!/usr/bin/env bash
set -euo pipefail

HOST_NAME="${HOST_NAME:-127.0.0.1}"
PORT="${PORT:-8000}"
RELOAD="${RELOAD:-false}"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

PYTHON=".venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then
  PYTHON="python3"
fi

ARGS=(-m uvicorn core.api:app --host "$HOST_NAME" --port "$PORT")
if [[ "$RELOAD" == "true" ]]; then
  ARGS+=(--reload)
fi

"$PYTHON" "${ARGS[@]}"
