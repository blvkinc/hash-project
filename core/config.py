"""
Central configuration for the Hash Project runtime.

All runtime settings are read through this module so tests, scripts, and the
application use the same environment contract.
"""
import os
from dataclasses import dataclass, field
from typing import Optional


def _project_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def _default_database_path() -> str:
    configured = os.environ.get("FIM_DATABASE_PATH", "").strip()
    if configured:
        expanded = os.path.expanduser(configured)
        if os.path.isabs(expanded):
            return expanded
        return os.path.join(_project_root(), expanded)
    return os.path.join(_project_root(), 'file_monitor.db')


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    """Process-wide configuration. Instantiate once per process."""
    database_path: str = field(default_factory=_default_database_path)
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
    ollama_url: str = field(default_factory=lambda: os.environ.get(
        "OLLAMA_URL", "http://localhost:11434/api/generate"))
    ollama_model: str = field(default_factory=lambda: os.environ.get(
        "OLLAMA_MODEL", "gemma4:latest"))
    ollama_timeout: float = field(default_factory=lambda: float(
        os.environ.get("FIM_OLLAMA_TIMEOUT", "45")))
    # Leave gemini_api_key empty to disable Gemini fallback entirely.
    gemini_api_key: str = field(default_factory=lambda: os.environ.get(
        "GEMINI_API_KEY", ""))
    gemini_model: str = field(default_factory=lambda: os.environ.get(
        "GEMINI_MODEL", "gemini-2.5-flash"))
    gemini_url: str = field(default_factory=lambda: os.environ.get(
        "GEMINI_URL", "https://generativelanguage.googleapis.com/v1beta/models"))
    gemini_timeout: float = field(default_factory=lambda: float(
        os.environ.get("FIM_GEMINI_TIMEOUT", "30")))

    # Embedded MemPalace agent modes:
    #   local: deterministic typed agent only
    #   auto:  inspect locally and call Ollama for meaningful changes
    #   llm:   call the LLM adapter whenever possible
    mempalace_agent_mode: str = field(default_factory=lambda: os.environ.get(
        "FIM_MEMPALACE_AGENT_MODE", "auto").strip().lower())
    mempalace_agent_llm_enabled: bool = field(
        default_factory=lambda: _env_bool("FIM_MEMPALACE_AGENT_LLM", True))
    mempalace_agent_model: str = field(default_factory=lambda: os.environ.get(
        "FIM_MEMPALACE_AGENT_MODEL", os.environ.get("OLLAMA_MODEL", "gemma4:latest")))
    mempalace_enabled: bool = field(
        default_factory=lambda: _env_bool("FIM_MEMPALACE_ENABLED", True))
    mempalace_path: str = field(default_factory=lambda: os.environ.get(
        "FIM_MEMPALACE_PATH", os.path.join(_project_root(), ".mempalace_fim")))
    mempalace_backend: str = field(default_factory=lambda: os.environ.get(
        "FIM_MEMPALACE_BACKEND", "sqlite_exact").strip().lower())
    mempalace_collection: str = field(default_factory=lambda: os.environ.get(
        "FIM_MEMPALACE_COLLECTION", "fim_file_memories"))
    mempalace_embedding_model: str = field(default_factory=lambda: os.environ.get(
        "FIM_MEMPALACE_EMBEDDING_MODEL", "minilm").strip().lower())
    mempalace_search_limit: int = field(
        default_factory=lambda: _env_int("FIM_MEMPALACE_SEARCH_LIMIT", 5))
    mempalace_min_store_risk: int = field(
        default_factory=lambda: _env_int("FIM_MEMPALACE_MIN_STORE_RISK", 4))
    mempalace_store_baseline_info: bool = field(
        default_factory=lambda: _env_bool("FIM_MEMPALACE_STORE_BASELINE_INFO", False))
    mempalace_baseline_enabled: bool = field(
        default_factory=lambda: _env_bool("FIM_MEMPALACE_BASELINE_ENABLED", True))
    mempalace_baseline_max_entries: int = field(
        default_factory=lambda: _env_int("FIM_MEMPALACE_BASELINE_MAX_ENTRIES", 5000))
    mempalace_baseline_batch_size: int = field(
        default_factory=lambda: _env_int("FIM_MEMPALACE_BASELINE_BATCH_SIZE", 64))
    mempalace_baseline_include_tier4: bool = field(
        default_factory=lambda: _env_bool("FIM_MEMPALACE_BASELINE_INCLUDE_TIER4", False))
    agent_investigation_enabled: bool = field(
        default_factory=lambda: _env_bool("FIM_AGENT_INVESTIGATION_ENABLED", True))
    agent_investigation_min_risk: int = field(
        default_factory=lambda: _env_int("FIM_AGENT_INVESTIGATION_MIN_RISK", 7))
    agent_investigation_max_per_batch: int = field(
        default_factory=lambda: _env_int("FIM_AGENT_INVESTIGATION_MAX_PER_BATCH", 8))
    agent_investigation_backlog_threshold: int = field(
        default_factory=lambda: _env_int("FIM_AGENT_INVESTIGATION_BACKLOG_THRESHOLD", 500))
    agent_investigation_backlog_critical_only: bool = field(
        default_factory=lambda: _env_bool("FIM_AGENT_INVESTIGATION_BACKLOG_CRITICAL_ONLY", True))
    agent_investigation_signature_check: bool = field(
        default_factory=lambda: _env_bool("FIM_AGENT_INVESTIGATION_SIGNATURE_CHECK", True))
    agent_investigation_signature_timeout_seconds: float = field(
        default_factory=lambda: _env_float("FIM_AGENT_INVESTIGATION_SIGNATURE_TIMEOUT_SECONDS", 3.0))
    trusted_maintenance_windows: str = field(default_factory=lambda: os.environ.get(
        "FIM_TRUSTED_MAINTENANCE_WINDOWS", ""))
    desktop_notifications_enabled: bool = field(
        default_factory=lambda: _env_bool("FIM_DESKTOP_NOTIFICATIONS", True))
    email_enabled: bool = field(
        default_factory=lambda: _env_bool("FIM_EMAIL_ENABLED", False))
    smtp_host: str = field(default_factory=lambda: os.environ.get("FIM_SMTP_HOST", ""))
    smtp_port: int = field(default_factory=lambda: _env_int("FIM_SMTP_PORT", 587))
    smtp_user: str = field(default_factory=lambda: os.environ.get("FIM_SMTP_USER", ""))
    smtp_password: str = field(default_factory=lambda: os.environ.get("FIM_SMTP_PASSWORD", ""))
    email_from: str = field(default_factory=lambda: os.environ.get("FIM_EMAIL_FROM", "fim@localhost"))
    email_to: str = field(default_factory=lambda: os.environ.get("FIM_EMAIL_TO", ""))
    batch_interval_seconds: int = field(default_factory=lambda: _env_int("FIM_BATCH_INTERVAL", 3600))
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
