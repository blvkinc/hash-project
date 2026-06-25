"""Logging setup for console and optional JSON output.

Default behaviour is unchanged (human-readable text). Set FIM_LOG_JSON=1
to emit one JSON object per log line, suitable for `jq`, ElasticSearch,
or the dissertation's results tables.

Usage in an entry point:

    from core.logging_config import configure_logging
    configure_logging()
"""
import json
import logging
import os
import sys
import time
from typing import Any, Dict


_DEFAULT_LEVEL = os.environ.get("FIM_LOG_LEVEL", "INFO").upper()
_TEXT_FORMAT = '%(asctime)s [%(name)s] %(levelname)s: %(message)s'

# Reserved attributes on logging.LogRecord  -  we don't want these spilling
# into the structured payload as "extra fields".
_RESERVED_RECORD_ATTRS = {
    'name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 'filename',
    'module', 'exc_info', 'exc_text', 'stack_info', 'lineno', 'funcName',
    'created', 'msecs', 'relativeCreated', 'thread', 'threadName',
    'processName', 'process', 'message', 'taskName',
}


class JSONFormatter(logging.Formatter):
    """Emit one JSON object per record. Extra keys passed via `logger.info(..., extra={...})` are merged."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "ts":       time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(record.created)),
            "ts_epoch": round(record.created, 3),
            "level":    record.levelname,
            "logger":   record.name,
            "message":  record.getMessage(),
        }
        # Merge structured extras.
        for key, value in record.__dict__.items():
            if key in _RESERVED_RECORD_ATTRS or key.startswith('_'):
                continue
            try:
                json.dumps(value)
                payload[key] = value
            except (TypeError, ValueError):
                payload[key] = repr(value)

        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


def configure_logging(force_json: bool | None = None) -> None:
    """
    Idempotent root-logger configuration.

    JSON output is enabled when FIM_LOG_JSON is truthy (1, true, yes)
    or when `force_json=True`. Otherwise the existing text format is kept.
    """
    if force_json is None:
        raw = os.environ.get("FIM_LOG_JSON", "").lower()
        use_json = raw in ("1", "true", "yes", "on")
    else:
        use_json = bool(force_json)

    root = logging.getLogger()
    root.setLevel(_DEFAULT_LEVEL)

    # Drop any handlers we previously installed so re-calls don't duplicate.
    for h in list(root.handlers):
        if getattr(h, '_hashmon_owned', False):
            root.removeHandler(h)

    handler = logging.StreamHandler(sys.stderr)
    handler._hashmon_owned = True  # type: ignore[attr-defined]

    if use_json:
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(_TEXT_FORMAT))

    root.addHandler(handler)
