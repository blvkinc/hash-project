# File Integrity Monitor — How to Run

## Prerequisites

- **Python 3.10+**
- **Ollama** (optional) — for LLM-powered analysis. Without it, the tool uses the built-in heuristic engine automatically.

## 1. Install Dependencies

```bash
pip install fastapi uvicorn sqlalchemy watchdog requests
```

For running tests:

```bash
pip install pytest
```

## 2. Start the Server

```bash
# From the project root directory
python -m uvicorn core.api:app --host 0.0.0.0 --port 8000 --reload
```

The web dashboard will be available at **http://localhost:8000**.

## 3. Using the API

### Scan a directory (baseline + change detection)

```bash
curl -X POST http://localhost:8000/api/scan -H "Content-Type: application/json" -d "{\"path\": \"C:\\\\path\\\\to\\\\monitor\"}"
```

### Initialize baseline + start real-time file watching (recommended)

```bash
curl -X POST http://localhost:8000/api/initialize-watch -H "Content-Type: application/json" -d "{\"path\": \"C:\\\\path\\\\to\\\\monitor\"}"
```

### Start real-time file watching (watch-only)

```bash
curl -X POST http://localhost:8000/api/watch/start -H "Content-Type: application/json" -d "{\"path\": \"C:\\\\path\\\\to\\\\monitor\"}"
```

### Stop watching

```bash
curl -X POST http://localhost:8000/api/watch/stop
```

### View stats / logs / files

```
GET  http://localhost:8000/api/stats
GET  http://localhost:8000/api/logs?limit=100&priority=critical
GET  http://localhost:8000/api/files
GET  http://localhost:8000/api/watch/status
GET  http://localhost:8000/api/platform       ← shows detected OS + recommended monitoring paths
```

## 4. LLM Analysis (Optional — Enhanced Analysis)

The analyser tries providers in order: **local Ollama → Gemini API → built-in heuristic engine** (200+ patterns).

### Ollama (primary, recommended)

```bash
# Install Ollama from https://ollama.com
ollama pull gemma4:latest    # or any gemma3 / qwen2.5-coder / mistral / llama3.2
ollama serve
```

### Gemini API (fallback, optional)

Set `GEMINI_API_KEY` to enable Gemini as a fallback whenever Ollama is unreachable or returns invalid JSON. Without the key the chain skips Gemini and goes straight to the heuristic floor.

```powershell
$env:GEMINI_API_KEY = "your_key_here"
$env:GEMINI_MODEL   = "gemini-2.5-flash"    # optional override
```

Get a key from https://aistudio.google.com/apikey.

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_URL` | `http://localhost:11434/api/generate` | Ollama API endpoint |
| `OLLAMA_MODEL` | `gemma4:latest` | Model to use (gemma4 / gemma3:* / qwen2.5-coder / mistral / llama3.2 — auto-selector picks gemma family first) |
| `FIM_OLLAMA_TIMEOUT` | `45` | Per-request timeout (seconds) |
| `GEMINI_API_KEY` | _(empty — Gemini disabled)_ | Google AI Studio key |
| `GEMINI_MODEL` | `gemini-2.5-flash` | Gemini model name |
| `GEMINI_URL` | `https://generativelanguage.googleapis.com/v1beta/models` | API base |
| `FIM_GEMINI_TIMEOUT` | `30` | Per-request timeout (seconds) |

## 5. Running Tests

```bash
# All tests
python -m pytest tests/ -v

# Just the core tests
python -m pytest tests/test_core.py -v

# Cross-platform module tests
python -m pytest tests/test_platform_paths.py -v

# Heuristic engine verification (script-based)
python tests/test_heuristic.py
python tests/test_expanded.py
```

## 6. Cross-Platform Notes

The tool auto-detects the OS and adjusts its behaviour:

| OS | File Watcher | Update Log Checks | Registry Monitoring |
|----|-------------|-------------------|---------------------|
| **Linux** | inotify (via watchdog) | dpkg, yum, pacman, dnf | N/A |
| **Windows** | ReadDirectoryChangesW (via watchdog) | Windows Update, MSI logs | Via `HIGH_RISK_PATHS` patterns |
| **macOS** | FSEvents (via watchdog) | install.log, Homebrew | N/A |

The `GET /api/platform` endpoint returns the detected OS and the recommended tiered monitoring paths (Tier 1 = critical, Tier 4 = low priority).

## Project Structure

```
Hash-project/
├── core/
│   ├── api.py                 # FastAPI REST API + static frontend
│   ├── background_analysis.py # Background thread for pending event analysis
│   ├── database.py            # SQLite database setup (SQLAlchemy)
│   ├── hasher.py              # SHA-256 file hashing + metadata extraction
│   ├── llm_analyzer.py        # Ollama LLM + heuristic threat engine (200+ patterns)
│   ├── models.py              # SQLAlchemy models (FileRecord, FileLog)
│   ├── os_context.py          # OS detection + system update context signals
│   ├── platform_paths.py      # Cross-platform tiered monitoring paths
│   ├── scanner.py             # Directory scanning + baseline comparison
│   └── watcher.py             # Real-time filesystem monitoring (watchdog)
├── tests/
│   ├── test_core.py           # Core module unit tests
│   ├── test_platform_paths.py # Cross-platform module tests
│   ├── test_heuristic.py      # Heuristic engine smoke tests
│   └── test_expanded.py       # Expanded threat pattern verification
└── web/
    ├── index.html             # Dashboard frontend
    ├── style.css              # Styles
    └── app.js                 # Frontend logic
```
