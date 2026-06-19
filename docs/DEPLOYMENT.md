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

To install it as a user logon task:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/install_windows_task.ps1
```

To remove the task later:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/uninstall_windows_task.ps1
```

## Install On Linux Or macOS

```bash
git clone https://github.com/blvkinc/hash-project.git
cd hash-project
./scripts/bootstrap.sh --dev
cp .env.example .env
./scripts/run.sh
```

The dashboard is available at `http://localhost:8000`.

To install it as a systemd service:

```bash
sudo scripts/install_systemd.sh
```

To remove the service later:

```bash
sudo scripts/uninstall_systemd.sh
```

## Docker Deployment

Docker is useful when you want a repeatable application runtime. It cannot scan
arbitrary host paths unless those paths are mounted into the container.

```bash
mkdir -p watched
docker compose up --build
```

Open `http://localhost:8000` and scan `/watched` to inspect the mounted
directory. To scan another host path, edit the bind mount in
`docker-compose.yml`:

```yaml
volumes:
  - integrityguard-data:/app/data
  - /absolute/host/path:/watched
```

The named `integrityguard-data` volume stores `file_monitor.db` and
`.mempalace_fim/`.

Common commands:

```bash
docker compose ps
docker compose logs -f
docker compose down
docker compose down -v
```

Use `docker compose down -v` only when you want to remove the persisted
database and MemPalace state.

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

The helper script above registers a Task Scheduler task. The manual equivalent
is:

```powershell
$Action = New-ScheduledTaskAction `
  -Execute "powershell.exe" `
  -Argument "-ExecutionPolicy Bypass -File `"$PWD\scripts\run.ps1`""
$Trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "IntegrityGuard" -Action $Action -Trigger $Trigger
```

For server deployments that require a true Windows service, use a service
wrapper such as NSSM and point it at:

```powershell
.venv\Scripts\python.exe -m uvicorn core.api:app --host 127.0.0.1 --port 8000
```

## Linux systemd Example

The helper script above writes and enables the service. The manual equivalent is
to create `/etc/systemd/system/integrityguard.service`:

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
Invoke-RestMethod http://localhost:8000/api/health
Invoke-RestMethod http://localhost:8000/api/stats
Invoke-RestMethod http://localhost:8000/api/agent/activity
```

Linux or macOS:

```bash
curl http://localhost:8000/api/health
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
