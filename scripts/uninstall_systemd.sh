#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-integrityguard}"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run with sudo: sudo SERVICE_NAME=${SERVICE_NAME} scripts/uninstall_systemd.sh"
  exit 1
fi

if systemctl list-unit-files | grep -q "^${SERVICE_NAME}.service"; then
  systemctl disable --now "${SERVICE_NAME}" || true
fi

rm -f "${SERVICE_FILE}"
systemctl daemon-reload
echo "Removed ${SERVICE_NAME}."
