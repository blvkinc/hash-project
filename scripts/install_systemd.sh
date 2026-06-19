#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-integrityguard}"
HOST_NAME="${HOST_NAME:-127.0.0.1}"
PORT="${PORT:-8000}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_USER="${RUN_USER:-${SUDO_USER:-${USER}}}"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run with sudo: sudo SERVICE_NAME=${SERVICE_NAME} scripts/install_systemd.sh"
  exit 1
fi

if [[ ! -x "${PROJECT_ROOT}/.venv/bin/python" ]]; then
  sudo -u "${RUN_USER}" "${PROJECT_ROOT}/scripts/bootstrap.sh"
fi

if [[ ! -f "${PROJECT_ROOT}/.env" && -f "${PROJECT_ROOT}/.env.example" ]]; then
  sudo -u "${RUN_USER}" cp "${PROJECT_ROOT}/.env.example" "${PROJECT_ROOT}/.env"
fi

cat > "${SERVICE_FILE}" <<SERVICE
[Unit]
Description=IntegrityGuard File Integrity Monitor
After=network.target

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${PROJECT_ROOT}
EnvironmentFile=${PROJECT_ROOT}/.env
ExecStart=${PROJECT_ROOT}/.venv/bin/python -m uvicorn core.api:app --host ${HOST_NAME} --port ${PORT}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}"
systemctl --no-pager status "${SERVICE_NAME}"
