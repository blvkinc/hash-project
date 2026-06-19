# Hash Project

IntegrityGuard is a local file integrity monitoring system for Windows, Linux,
and macOS. It builds a fast baseline of file hashes, records change history in
SQLite, enriches changes with a persistent file registry, and uses an embedded
MemPalace agent for high-context review of important events.

## What It Does

- Scans directories and records a baseline hash for each file.
- Uses hybrid hashing: XXH3 for fast comparison and BLAKE3 for security-grade
  verification.
- Watches selected directories for creates, modifies, deletes, and renames.
- Maintains a persistent file registry with tier, semantic role, and change
  history.
- Runs content analysis with local heuristics, optional Ollama, optional Gemini,
  and MemPalace context retrieval.
- Shows monitored files, timeline events, severity counts, notifications, scan
  speed, and agent activity in the web dashboard.

## Quick Start

### Windows

```powershell
git clone https://github.com/blvkinc/hash-project.git
cd hash-project
powershell -ExecutionPolicy Bypass -File scripts/bootstrap.ps1 -Dev
powershell -ExecutionPolicy Bypass -File scripts/run.ps1
```

### Linux or macOS

```bash
git clone https://github.com/blvkinc/hash-project.git
cd hash-project
./scripts/bootstrap.sh --dev
./scripts/run.sh
```

Open the dashboard at [http://localhost:8000](http://localhost:8000).

## Optional Local LLM

The system works without an LLM by using the built-in analysis engine. For
local model-backed analysis, install Ollama and pull a supported model:

```bash
ollama pull gemma4:latest
```

Then set `OLLAMA_MODEL` in `.env` if you want a different model.

## Development Checks

```powershell
.venv\Scripts\python.exe -m pytest tests -q
.venv\Scripts\python.exe -m compileall -q core tests
```

For Linux or macOS, replace `.venv\Scripts\python.exe` with
`.venv/bin/python`.

## Runtime State

The following local state is intentionally ignored by Git:

- `file_monitor.db` and SQLite sidecar files
- `.mempalace_fim/`
- `.external/`
- `.env`
- caches, logs, virtual environments, and test artifacts

Use `docs/DEPLOYMENT.md` for production deployment notes, service examples, and
operational checks.
