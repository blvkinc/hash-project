"""
config.py — central configuration for the Hash Monitor.

Single source of truth for every env-var the project reads. Each consumer
should `from core.config import settings` rather than calling
`os.environ.get(...)` directly — that way the evaluation harness can run
the same code with different LLM models / batch intervals without touching
implementation files.

Settings are mutable so the Ollama auto-selector can write back the chosen
model. Call `settings.reload()` after deliberately mutating env vars.
"""
import os
from dataclasses import dataclass, field
from typing import Optional


def _project_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def _default_database_path() -> str:
    return os.path.join(_project_root(), 'file_monitor.db')


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass
class Settings:
    """Process-wide configuration. Instantiate once per process."""

    # ── Database ───────────────────────────────────────────────
    database_path: str = field(default_factory=_default_database_path)

    # ── Hashing ────────────────────────────────────────────────
    # Hybrid mode records a very fast comparison hash first, then keeps a
    # cryptographic security hash available for deeper verification.
    hash_mode: str = field(default_factory=lambda: os.environ.get(
        "FIM_HASH_MODE", "hybrid").strip().lower())
    hash_algorithm: str = field(default_factory=lambda: os.environ.get(
        "FIM_HASH_ALGORITHM", "xxh3_128"))
    security_hash_algorithm: str = field(default_factory=lambda: os.environ.get(
        "FIM_SECURITY_HASH_ALGORITHM", "blake3"))
    hash_chunk_size: int = field(
        default_factory=lambda: _env_int("FIM_HASH_CHUNK_SIZE", 4 * 1024 * 1024))
    blake3_max_threads: str = field(default_factory=lambda: os.environ.get(
        "FIM_BLAKE3_MAX_THREADS", "1").strip().lower())

    # ── Ollama (primary LLM provider) ──────────────────────────
    ollama_url: str = field(default_factory=lambda: os.environ.get(
        "OLLAMA_URL", "http://localhost:11434/api/generate"))
    ollama_model: str = field(default_factory=lambda: os.environ.get(
        "OLLAMA_MODEL", "gemma4:latest"))
    ollama_timeout: float = field(default_factory=lambda: float(
        os.environ.get("FIM_OLLAMA_TIMEOUT", "45")))

    # ── Gemini API (fallback when Ollama is unreachable) ───────
    # Leave gemini_api_key empty to disable Gemini fallback entirely.
    gemini_api_key: str = field(default_factory=lambda: os.environ.get(
        "GEMINI_API_KEY", ""))
    gemini_model: str = field(default_factory=lambda: os.environ.get(
        "GEMINI_MODEL", "gemini-2.5-flash"))
    gemini_url: str = field(default_factory=lambda: os.environ.get(
        "GEMINI_URL", "https://generativelanguage.googleapis.com/v1beta/models"))
    gemini_timeout: float = field(default_factory=lambda: float(
        os.environ.get("FIM_GEMINI_TIMEOUT", "30")))

    # ── Notification dispatch (Stage C) ────────────────────────
    smtp_host: str = field(default_factory=lambda: os.environ.get("FIM_SMTP_HOST", ""))
    smtp_port: int = field(default_factory=lambda: _env_int("FIM_SMTP_PORT", 587))
    smtp_user: str = field(default_factory=lambda: os.environ.get("FIM_SMTP_USER", ""))
    smtp_password: str = field(default_factory=lambda: os.environ.get("FIM_SMTP_PASSWORD", ""))
    email_from: str = field(default_factory=lambda: os.environ.get("FIM_EMAIL_FROM", "fim@localhost"))
    email_to: str = field(default_factory=lambda: os.environ.get("FIM_EMAIL_TO", ""))
    batch_interval_seconds: int = field(default_factory=lambda: _env_int("FIM_BATCH_INTERVAL", 3600))

    # ── Background analysis throttling ─────────────────────────
    analysis_backlog_threshold: int = field(
        default_factory=lambda: _env_int("FIM_ANALYSIS_BACKLOG_THRESHOLD", 500))
    analysis_batch_size: int = field(
        default_factory=lambda: _env_int("FIM_ANALYSIS_BATCH", 15))
    analysis_coalesce_window_seconds: int = field(
        default_factory=lambda: _env_int("FIM_ANALYSIS_COALESCE_WINDOW_SECONDS", 120))
    analysis_pending_hard_cap: int = field(
        default_factory=lambda: _env_int("FIM_ANALYSIS_PENDING_HARD_CAP", 5000))
    analysis_low_priority_demote_batch: int = field(
        default_factory=lambda: _env_int("FIM_ANALYSIS_LOW_PRIORITY_DEMOTE_BATCH", 1000))
    analysis_low_priority_demote_risk_threshold: int = field(
        default_factory=lambda: _env_int("FIM_ANALYSIS_LOW_PRIORITY_DEMOTE_RISK_THRESHOLD", 2))
    baseline_analysis_mode: str = field(default_factory=lambda: os.environ.get(
        "FIM_BASELINE_ANALYSIS_MODE", "suspicious").lower())
    baseline_capture_mode: str = field(default_factory=lambda: os.environ.get(
        "FIM_BASELINE_CAPTURE_MODE", "hash_first").lower())
    baseline_commit_batch_size: int = field(
        default_factory=lambda: _env_int("FIM_BASELINE_COMMIT_BATCH_SIZE", 1000))
    baseline_hash_workers: int = field(default_factory=lambda: _env_int(
        "FIM_BASELINE_HASH_WORKERS", min(16, max(1, os.cpu_count() or 4))))
    baseline_deferred_analysis_limit: int = field(
        default_factory=lambda: _env_int("FIM_BASELINE_DEFERRED_ANALYSIS_LIMIT", 5000))
    baseline_analysis_risk_threshold: int = field(
        default_factory=lambda: _env_int("FIM_BASELINE_ANALYSIS_RISK_THRESHOLD", 7))
    baseline_analysis_max_bytes: int = field(
        default_factory=lambda: _env_int("FIM_BASELINE_ANALYSIS_MAX_BYTES", 1_000_000))

    def reload(self) -> None:
        """Re-read every field from os.environ. Used after env mutation."""
        fresh = Settings()
        for f in fresh.__dataclass_fields__:
            setattr(self, f, getattr(fresh, f))


# Module-level singleton. Consumers do: `from core.config import settings`.
settings = Settings()
