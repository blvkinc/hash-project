# Deployment Guide

This guide describes how to install IntegrityGuard on a new workstation or
server and run it as a local monitoring service.

## Requirements

- Python 3.10 or newer
- Git
- Optional: Ollama for local model-backed analysis
- Optional: SMTP credentials for email notifications

## Install On Windows

```powershell
git clone https://github.com/blvkinc/hash-project.git
cd hash-project
powershell -ExecutionPolicy Bypass -File scripts/bootstrap.ps1 -Dev
copy .env.example .env
powershell -ExecutionPolicy Bypass -File scripts/run.ps1
```

The dashboard is available at `http://localhost:8000`.

## Install On Linux Or macOS

```bash
git clone https://github.com/blvkinc/hash-project.git
cd hash-project
./scripts/bootstrap.sh --dev
cp .env.example .env
./scripts/run.sh
```

The dashboard is available at `http://localhost:8000`.

## Configuration

Edit `.env` before deployment. The most commonly changed settings are:

| Setting | Purpose |
| --- | --- |
| `FIM_DATABASE_PATH` | SQLite database path. |
| `FIM_BASELINE_HASH_WORKERS` | Number of baseline hash workers. |
| `FIM_HASH_ALGORITHM` | Fast comparison hash, normally `xxh3_128`. |
| `FIM_SECURITY_HASH_ALGORITHM` | Security hash, normally `blake3`. |
| `OLLAMA_MODEL` | Local model used when Ollama is enabled. |
| `FIM_MEMPALACE_PATH` | Persistent MemPalace memory store. |
| `FIM_AGENT_INVESTIGATION_MIN_RISK` | Minimum risk score for deeper agent review. |
| `FIM_EMAIL_ENABLED` | Enables SMTP alerts when set to `true`. |

## Running With Uvicorn

Development:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run.ps1 -Reload
```

Production-style local run:

```powershell
.venv\Scripts\python.exe -m uvicorn core.api:app --host 127.0.0.1 --port 8000
```

On Linux or macOS:

```bash
.venv/bin/python -m uvicorn core.api:app --host 127.0.0.1 --port 8000
```

Bind to `0.0.0.0` only when the host is on a trusted network or protected by a
reverse proxy and authentication boundary.

## Windows Service Option

For a workstation deployment, Task Scheduler is usually enough:

```powershell
$Action = New-ScheduledTaskAction `
  -Execute "powershell.exe" `
  -Argument "-ExecutionPolicy Bypass -File `"$PWD\scripts\run.ps1`""
$Trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "IntegrityGuard" -Action $Action -Trigger $Trigger
```

For server deployments, use a service wrapper such as NSSM and point it at:

```powershell
.venv\Scripts\python.exe -m uvicorn core.api:app --host 127.0.0.1 --port 8000
```

## Linux systemd Example

Create `/etc/systemd/system/integrityguard.service`:

```ini
[Unit]
Description=IntegrityGuard File Integrity Monitor
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/hash-project
EnvironmentFile=/opt/hash-project/.env
ExecStart=/opt/hash-project/.venv/bin/python -m uvicorn core.api:app --host 127.0.0.1 --port 8000
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Then run:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now integrityguard
sudo systemctl status integrityguard
```

## Smoke Checks

Windows:

```powershell
Invoke-RestMethod http://localhost:8000/api/stats
Invoke-RestMethod http://localhost:8000/api/agent/activity
```

Linux or macOS:

```bash
curl http://localhost:8000/api/stats
curl http://localhost:8000/api/agent/activity
```

Expected result: both endpoints return JSON and the dashboard loads in the
browser.

## Runtime State And Backups

Back up these paths if you need to preserve monitoring history:

- `file_monitor.db`
- `.mempalace_fim/`
- any custom `.env` file

Do not commit runtime state to Git. The repository ignores database files,
MemPalace runtime memory, local environment files, caches, logs, and virtual
environments.

## Resetting A Local Test Environment

Stop the server first, then remove project-owned runtime state:

```powershell
Remove-Item -Force file_monitor.db,file_monitor.db-wal,file_monitor.db-shm -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force .mempalace_fim -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force .pytest_cache -ErrorAction SilentlyContinue
```

This does not remove `.external/`, which is used for dependency source and local
inspection work.
