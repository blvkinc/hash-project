"""Content/context analysis cache helpers."""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from .models import AnalysisCache

_CACHE_VERSION = 1
_UNCACHEABLE_EVENTS = {"deleted", "renamed"}
_VERDICT_CONTEXT_KEYS = {
    "event_context",
    "change_summary",
    "analysis_cache_hit",
    "analysis_cache_key",
    "cached_at",
}


def build_analysis_cache_meta(
    path: str,
    event_type: str,
    new_hash: str | None,
    old_hash: str | None,
    contextual_payload: str | None,
    metadata: dict | None,
) -> dict[str, str] | None:
    """Build a deterministic cache key for content-driven analysis."""
    normalized_event = (event_type or "").lower()
    if normalized_event in _UNCACHEABLE_EVENTS:
        return None

    payload = contextual_payload or ""
    metadata = metadata if isinstance(metadata, dict) else {}
    content_hash = new_hash or metadata.get("content_hash")
    if not content_hash and payload:
        content_hash = _sha256(payload)
    if not content_hash:
        return None

    context_hash = ""
    if normalized_event == "modified":
        # A modified-file verdict depends on before/after context, not only
        # the final content hash.
        context_hash = _sha256(payload)

    extension = os.path.splitext(path.lower())[1]
    material = {
        "v": _CACHE_VERSION,
        "event_type": normalized_event,
        "content_hash": str(content_hash),
        "context_hash": context_hash,
        "extension": extension,
        "file_category": str(metadata.get("file_category") or ""),
        "is_baseline": bool(metadata.get("is_baseline")),
    }
    cache_key = _sha256(json.dumps(material, sort_keys=True, separators=(",", ":")))
    return {
        "cache_key": cache_key,
        "content_hash": str(content_hash),
        "context_hash": context_hash,
        "event_type": normalized_event,
    }


def get_cached_analysis(session: Session, cache_meta: dict[str, str] | None) -> dict | None:
    """Return a cached verdict and update its hit counters."""
    if not cache_meta:
        return None
    row = (
        session.query(AnalysisCache)
        .filter(AnalysisCache.cache_key == cache_meta["cache_key"])
        .first()
    )
    if not row:
        return None
    row.hit_count = int(row.hit_count or 0) + 1
    row.last_hit_at = datetime.utcnow()
    row.updated_at = datetime.utcnow()
    verdict = dict(row.verdict_json or {})
    verdict["analysis_cache_hit"] = True
    verdict["analysis_cache_key"] = row.cache_key
    return verdict


def store_analysis_cache(
    session: Session,
    cache_meta: dict[str, str] | None,
    analysis: dict | None,
) -> None:
    """Store or refresh a reusable verdict."""
    if not cache_meta or not isinstance(analysis, dict):
        return

    verdict = _cacheable_verdict(analysis)
    if not verdict:
        return

    now = datetime.utcnow()
    row = (
        session.query(AnalysisCache)
        .filter(AnalysisCache.cache_key == cache_meta["cache_key"])
        .first()
    )
    if row is None:
        row = AnalysisCache(
            cache_key=cache_meta["cache_key"],
            content_hash=cache_meta.get("content_hash"),
            context_hash=cache_meta.get("context_hash"),
            event_type=cache_meta.get("event_type") or "",
            created_at=now,
        )
        session.add(row)

    row.verdict_json = verdict
    row.analysis_source = verdict.get("analysis_source")
    row.priority = verdict.get("priority")
    row.risk_score = verdict.get("risk_score")
    row.updated_at = now


def _cacheable_verdict(analysis: dict[str, Any]) -> dict[str, Any]:
    verdict = {
        key: value
        for key, value in analysis.items()
        if key not in _VERDICT_CONTEXT_KEYS
    }
    verdict["cached_at"] = datetime.utcnow().isoformat()
    return verdict


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()
