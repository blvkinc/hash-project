"""Bridge to the real MemPalace package.

The file registry remains the fast SQL source of truth for every monitored
file. This bridge uses the actual ``mempalace`` library as the agent memory
layer: selected file-intelligence events are written as drawers and related
drawers are retrieved before the MemPalace agent produces a verdict.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from core.config import settings

logger = logging.getLogger(__name__)

MEMORY_WING = "IntegrityGuard"
MEMORY_TYPE_EVENT = "fim_event"
MEMORY_TYPE_BASELINE = "fim_baseline_identity"


@dataclass(frozen=True)
class MemPalaceMemoryHit:
    """Normalized search hit returned by the actual MemPalace backend."""

    id: str
    text: str
    metadata: dict[str, Any]
    distance: float | None = None
    similarity: float | None = None
    matched_via: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "text": self.text,
            "metadata": self.metadata,
            "distance": self.distance,
            "similarity": self.similarity,
            "matched_via": self.matched_via,
        }


@dataclass(frozen=True)
class MemPalaceSearchQuery:
    """One scoped memory retrieval strategy."""

    strategy: str
    query: str
    room: str


class MemPalaceUnavailable(RuntimeError):
    """Raised internally when the real MemPalace package cannot be used."""


def enabled() -> bool:
    """Return whether the external MemPalace memory layer is enabled."""
    return bool(getattr(settings, "mempalace_enabled", True))


def backend_status() -> dict[str, Any]:
    """Small runtime status payload for UI/debugging."""
    if not enabled():
        return {"enabled": False, "backend": "disabled"}
    try:
        _import_mempalace_collection()
    except MemPalaceUnavailable as exc:
        return {
            "enabled": True,
            "available": False,
            "backend": str(getattr(settings, "mempalace_backend", "")),
            "error": str(exc),
        }
    return {
        "enabled": True,
        "available": True,
        "backend": str(getattr(settings, "mempalace_backend", "")),
        "palace_path": _palace_path(),
        "collection": str(getattr(settings, "mempalace_collection", "")),
    }


def search_related_memories(
    *,
    path: str,
    event_type: str,
    registry: dict[str, Any] | None,
    content_excerpt: str = "",
    analysis: dict[str, Any] | None = None,
    limit: int | None = None,
) -> tuple[list[MemPalaceMemoryHit], dict[str, Any]]:
    """Search the actual MemPalace palace for related file memories."""
    if not enabled():
        return [], {"enabled": False, "searched": False, "backend": "disabled"}

    n_results = max(1, int(limit or getattr(settings, "mempalace_search_limit", 5) or 5))
    query_specs = _related_queries(
        path=path,
        event_type=event_type,
        registry=registry,
        content_excerpt=content_excerpt,
        analysis=analysis,
    )
    primary_query = query_specs[0].query if query_specs else ""
    primary_room = query_specs[0].room if query_specs else _room_for_registry(registry)
    try:
        search_memories = _import_mempalace_search()
        _configure_environment()
        all_hits: list[MemPalaceMemoryHit] = []
        query_status: list[dict[str, Any]] = []
        errors: list[str] = []
        per_query_limit = max(1, min(n_results, 5))

        for spec in query_specs:
            try:
                result = search_memories(
                    query=spec.query,
                    palace_path=_palace_path(),
                    wing=MEMORY_WING,
                    room=spec.room,
                    n_results=per_query_limit,
                    collection_name=_collection_name(),
                )
            except Exception as exc:  # noqa: BLE001 - MemPalace backends vary.
                errors.append(f"{spec.strategy}: {exc}")
                query_status.append({
                    "strategy": spec.strategy,
                    "query": spec.query,
                    "room": spec.room,
                    "hits": 0,
                    "error": str(exc),
                })
                continue

            fallback = None
            if isinstance(result, dict) and result.get("error"):
                fallback_hits = _lexical_fallback(query=spec.query, room=spec.room, limit=per_query_limit)
                fallback = "lexical" if fallback_hits else None
                hits = fallback_hits
                if not fallback_hits:
                    errors.append(f"{spec.strategy}: {result.get('error')}")
            else:
                hits = _hits_from_search_result(result)

            annotated = [_annotate_hit(hit, spec, fallback=fallback) for hit in hits]
            all_hits.extend(annotated)
            query_status.append({
                "strategy": spec.strategy,
                "query": spec.query,
                "room": spec.room,
                "hits": len(annotated),
                **({"fallback": fallback} if fallback else {}),
            })

        hits = _merge_search_hits(all_hits)[:n_results]
        searched = bool(query_status) and (bool(hits) or len(errors) < len(query_status))
        strategies = _dedupe([
            strategy
            for hit in hits
            for strategy in _hit_strategies(hit)
        ])
        return hits, {
            "enabled": True,
            "searched": searched,
            "backend": str(getattr(settings, "mempalace_backend", "")),
            "palace_path": _palace_path(),
            "collection": _collection_name(),
            "query": primary_query,
            "room": primary_room,
            "hits": len(hits),
            "query_count": len(query_specs),
            "queries": query_status,
            "retrieval_strategies": strategies,
            **({"errors": errors[:5]} if errors and not hits else {}),
        }
    except MemPalaceUnavailable as exc:
        return [], {
            "enabled": True,
            "searched": False,
            "backend": str(getattr(settings, "mempalace_backend", "")),
            "error": str(exc),
        }
    except Exception as exc:  # noqa: BLE001 - MemPalace backends vary.
        logger.debug("MemPalace search failed", exc_info=True)
        return [], {
            "enabled": True,
            "searched": False,
            "backend": str(getattr(settings, "mempalace_backend", "")),
            "error": str(exc),
        }


def upsert_event_memory(
    *,
    log_id: int | None,
    file_id: int | None,
    path: str,
    event_type: str,
    old_hash: str | None,
    new_hash: str | None,
    registry: dict[str, Any] | None,
    analysis: dict[str, Any],
    content_excerpt: str = "",
) -> dict[str, Any]:
    """Write one file-intelligence drawer using the actual MemPalace API."""
    if not enabled():
        return {"enabled": False, "stored": False, "backend": "disabled"}
    if not _should_store(analysis, registry):
        return {
            "enabled": True,
            "stored": False,
            "backend": str(getattr(settings, "mempalace_backend", "")),
            "reason": "below_mempalace_store_threshold",
        }

    try:
        get_collection = _import_mempalace_collection()
        _configure_environment()
        collection = get_collection(
            _palace_path(),
            collection_name=_collection_name(),
            create=True,
            backend=str(getattr(settings, "mempalace_backend", "sqlite_exact") or "sqlite_exact"),
        )
        memory_id = _event_memory_id(log_id, file_id, path, event_type, old_hash, new_hash)
        document = build_event_memory_document(
            path=path,
            event_type=event_type,
            old_hash=old_hash,
            new_hash=new_hash,
            registry=registry,
            analysis=analysis,
            content_excerpt=content_excerpt,
        )
        metadata = build_event_memory_metadata(
            log_id=log_id,
            file_id=file_id,
            path=path,
            event_type=event_type,
            old_hash=old_hash,
            new_hash=new_hash,
            registry=registry,
            analysis=analysis,
        )
        collection.upsert(
            documents=[document],
            ids=[memory_id],
            metadatas=[_sanitize_metadata(metadata)],
        )
        return {
            "enabled": True,
            "stored": True,
            "backend": str(getattr(settings, "mempalace_backend", "")),
            "palace_path": _palace_path(),
            "collection": _collection_name(),
            "memory_id": memory_id,
            "wing": MEMORY_WING,
            "room": metadata.get("room"),
        }
    except MemPalaceUnavailable as exc:
        return {
            "enabled": True,
            "stored": False,
            "backend": str(getattr(settings, "mempalace_backend", "")),
            "error": str(exc),
        }
    except Exception as exc:  # noqa: BLE001 - MemPalace backends vary.
        logger.debug("MemPalace write failed", exc_info=True)
        return {
            "enabled": True,
            "stored": False,
            "backend": str(getattr(settings, "mempalace_backend", "")),
            "error": str(exc),
        }


def upsert_baseline_memories(memories: list[dict[str, Any]]) -> dict[str, Any]:
    """Batch-write baseline identity drawers using the actual MemPalace API."""
    if not enabled():
        return {"enabled": False, "stored": 0, "backend": "disabled"}
    if not memories:
        return {
            "enabled": True,
            "stored": 0,
            "backend": str(getattr(settings, "mempalace_backend", "")),
            "reason": "no_memories",
        }

    try:
        get_collection = _import_mempalace_collection()
        _configure_environment()
        collection = get_collection(
            _palace_path(),
            collection_name=_collection_name(),
            create=True,
            backend=str(getattr(settings, "mempalace_backend", "sqlite_exact") or "sqlite_exact"),
        )
        documents = [str(item["document"]) for item in memories]
        ids = [str(item["id"]) for item in memories]
        metadatas = [_sanitize_metadata(dict(item.get("metadata") or {})) for item in memories]
        collection.upsert(documents=documents, ids=ids, metadatas=metadatas)
        return {
            "enabled": True,
            "stored": len(ids),
            "backend": str(getattr(settings, "mempalace_backend", "")),
            "palace_path": _palace_path(),
            "collection": _collection_name(),
        }
    except MemPalaceUnavailable as exc:
        return {
            "enabled": True,
            "stored": 0,
            "backend": str(getattr(settings, "mempalace_backend", "")),
            "error": str(exc),
        }
    except Exception as exc:  # noqa: BLE001 - MemPalace backends vary.
        logger.debug("MemPalace baseline write failed", exc_info=True)
        return {
            "enabled": True,
            "stored": 0,
            "backend": str(getattr(settings, "mempalace_backend", "")),
            "error": str(exc),
        }


def build_event_memory_document(
    *,
    path: str,
    event_type: str,
    old_hash: str | None,
    new_hash: str | None,
    registry: dict[str, Any] | None,
    analysis: dict[str, Any],
    content_excerpt: str = "",
) -> str:
    """Create the event memory document stored in MemPalace."""
    registry = registry or {}
    mem_palace = analysis.get("mem_palace") if isinstance(analysis, dict) else {}
    if not isinstance(mem_palace, dict):
        mem_palace = {}
    lines = [
        "File Integrity Memory",
        f"Path: {path}",
        f"Event: {event_type}",
        f"Hash: {old_hash or 'none'} -> {new_hash or 'none'}",
        f"Registry Tier: {registry.get('tier', 'unknown')} {registry.get('tier_label', '')}".strip(),
        f"Semantic Role: {registry.get('semantic_role') or analysis.get('semantic_role') or 'unknown'}",
        f"Asset Type: {registry.get('asset_type') or analysis.get('asset_type') or 'unknown'}",
        f"Priority: {analysis.get('priority', 'unknown')} / Risk: {analysis.get('risk_score', 'unknown')}",
        f"Threat Type: {analysis.get('threat_type', 'unknown')}",
        f"Threat Classification: {analysis.get('threat_classification', 'unknown')}",
        f"Reasoning: {analysis.get('reasoning', '')}",
    ]
    if mem_palace.get("identity_summary"):
        lines.append(f"Agent Identity Summary: {mem_palace.get('identity_summary')}")
    if mem_palace.get("change_interpretation"):
        lines.append(f"Agent Change Interpretation: {mem_palace.get('change_interpretation')}")
    if mem_palace.get("agent_content"):
        agent_content = mem_palace.get("agent_content") or {}
        if isinstance(agent_content, dict):
            lines.append(
                "Agent Content: "
                f"{agent_content.get('threat_classification') or agent_content.get('summary') or ''}"
            )
    agent_investigation = analysis.get("agent_investigation") if isinstance(analysis, dict) else {}
    if isinstance(agent_investigation, dict) and agent_investigation.get("ran"):
        lines.append(f"Agent Investigation: {agent_investigation.get('notification_summary') or agent_investigation.get('reason') or ''}")
        lines.append(f"Trusted Change: {agent_investigation.get('trusted_change') or 'unknown'}")
    if content_excerpt:
        lines.extend([
            "",
            "Captured Change Payload:",
            str(content_excerpt)[:4000],
        ])
    return "\n".join(str(line) for line in lines if line is not None)


def build_baseline_memory(
    *,
    registry: dict[str, Any],
    root_path: str | None = None,
    scan_session_id: int | None = None,
) -> dict[str, Any]:
    """Build one baseline identity memory payload for MemPalace."""
    memory_id = _baseline_memory_id(
        file_id=registry.get("file_id"),
        path=str(registry.get("path") or ""),
    )
    metadata = build_baseline_memory_metadata(
        registry=registry,
        root_path=root_path,
        scan_session_id=scan_session_id,
    )
    return {
        "id": memory_id,
        "document": build_baseline_memory_document(registry=registry),
        "metadata": metadata,
    }


def build_baseline_memory_document(*, registry: dict[str, Any]) -> str:
    """Create the baseline identity drawer text stored in MemPalace."""
    expected_sources = registry.get("expected_change_sources") or []
    if not isinstance(expected_sources, list):
        expected_sources = [str(expected_sources)]
    lines = [
        "File Baseline Identity Memory",
        f"Path: {registry.get('path', 'unknown')}",
        f"File ID: {registry.get('file_id', 'unknown')}",
        f"Path History: {_format_path_history(registry.get('path_history'))}",
        f"Tier: {registry.get('tier', 'unknown')} {registry.get('tier_label', '')}".strip(),
        f"Semantic Role: {registry.get('semantic_role') or 'unknown'}",
        f"Asset Type: {registry.get('asset_type') or 'unknown'}",
        f"File Category: {registry.get('file_category') or 'unknown'}",
        f"Last Known Good Hash: {registry.get('last_known_good_hash') or 'unknown'}",
        f"Current Fast Hash: {registry.get('current_fast_hash') or registry.get('current_hash') or 'unknown'}",
        f"Security Hash: {registry.get('current_security_hash') or 'pending'}",
        f"Hash Algorithm: {registry.get('hash_algorithm') or 'unknown'}",
        f"Security Hash Algorithm: {registry.get('security_hash_algorithm') or 'unknown'}",
        f"Expected Change Sources: {', '.join(str(item) for item in expected_sources) or 'unknown'}",
        f"Reasoning: {registry.get('reasoning') or 'No registry reasoning recorded.'}",
        (
            "Agent Instruction: If this file changes, compare the event against "
            "this baseline identity, its tier, semantic role, expected change "
            "sources, and last-known-good hashes before assigning severity."
        ),
    ]
    return "\n".join(str(line) for line in lines if line is not None)


def build_baseline_memory_metadata(
    *,
    registry: dict[str, Any],
    root_path: str | None = None,
    scan_session_id: int | None = None,
) -> dict[str, Any]:
    """Metadata stored beside a baseline identity drawer."""
    path = str(registry.get("path") or "")
    role = str(registry.get("semantic_role") or "general_file")
    return {
        "memory_type": MEMORY_TYPE_BASELINE,
        "wing": MEMORY_WING,
        "room": _room_for_registry(registry),
        "source_file": path,
        "source_file_full": path,
        "file_path": path,
        "file_name": os.path.basename(path),
        "path_history": registry.get("path_history") or [],
        "root_path": root_path,
        "scan_session_id": scan_session_id,
        "file_id": registry.get("file_id"),
        "tier": registry.get("tier"),
        "tier_label": registry.get("tier_label"),
        "semantic_role": role,
        "asset_type": registry.get("asset_type"),
        "file_category": registry.get("file_category"),
        "last_known_good_hash": registry.get("last_known_good_hash"),
        "current_hash": registry.get("current_hash"),
        "current_fast_hash": registry.get("current_fast_hash"),
        "current_security_hash": registry.get("current_security_hash"),
        "hash_algorithm": registry.get("hash_algorithm"),
        "security_hash_algorithm": registry.get("security_hash_algorithm"),
        "is_active": registry.get("is_active", True),
        "filed_at": datetime.utcnow().isoformat(),
    }


def build_event_memory_metadata(
    *,
    log_id: int | None,
    file_id: int | None,
    path: str,
    event_type: str,
    old_hash: str | None,
    new_hash: str | None,
    registry: dict[str, Any] | None,
    analysis: dict[str, Any],
) -> dict[str, Any]:
    """Metadata stored beside the drawer for scoped MemPalace search."""
    registry = registry or {}
    role = str(registry.get("semantic_role") or analysis.get("semantic_role") or "general_file")
    room = _room_for_registry(registry) or _room_from_role(role)
    return {
        "memory_type": MEMORY_TYPE_EVENT,
        "wing": MEMORY_WING,
        "room": room,
        "source_file": path,
        "source_file_full": path,
        "file_path": path,
        "file_name": os.path.basename(path),
        "path_history": registry.get("path_history") or [],
        "log_id": log_id,
        "file_id": file_id,
        "event_type": event_type,
        "old_hash": old_hash,
        "new_hash": new_hash,
        "tier": registry.get("tier") or analysis.get("tier"),
        "tier_label": registry.get("tier_label"),
        "semantic_role": role,
        "asset_type": registry.get("asset_type") or analysis.get("asset_type"),
        "priority": analysis.get("priority"),
        "risk_score": analysis.get("risk_score"),
        "threat_type": analysis.get("threat_type"),
        "threat_classification": analysis.get("threat_classification"),
        "analysis_source": analysis.get("analysis_source"),
        "filed_at": datetime.utcnow().isoformat(),
    }


def _import_mempalace_collection():
    try:
        from mempalace.palace import get_collection
    except Exception as exc:  # noqa: BLE001
        raise MemPalaceUnavailable(
            "The real 'mempalace' package is not importable. "
            "Install it with 'python -m pip install mempalace'."
        ) from exc
    return get_collection


def _import_mempalace_search():
    try:
        from mempalace.searcher import search_memories
    except Exception as exc:  # noqa: BLE001
        raise MemPalaceUnavailable(
            "The real 'mempalace' package is not importable. "
            "Install it with 'python -m pip install mempalace'."
        ) from exc
    return search_memories


def _configure_environment() -> None:
    os.environ.setdefault(
        "MEMPALACE_BACKEND",
        str(getattr(settings, "mempalace_backend", "sqlite_exact") or "sqlite_exact"),
    )
    os.environ.setdefault(
        "MEMPALACE_BACKEND_EXPLICIT",
        str(getattr(settings, "mempalace_backend", "sqlite_exact") or "sqlite_exact"),
    )
    os.environ.setdefault(
        "MEMPALACE_EMBEDDING_MODEL",
        str(getattr(settings, "mempalace_embedding_model", "minilm") or "minilm"),
    )
    os.makedirs(_palace_path(), exist_ok=True)


def _palace_path() -> str:
    return os.path.abspath(os.path.expanduser(str(getattr(settings, "mempalace_path", ""))))


def _collection_name() -> str:
    return str(getattr(settings, "mempalace_collection", "fim_file_memories") or "fim_file_memories")


def _room_for_registry(registry: dict[str, Any] | None) -> str:
    registry = registry or {}
    role = str(registry.get("semantic_role") or "general_file")
    asset = str(registry.get("asset_type") or registry.get("file_category") or "unknown")
    tier = registry.get("tier")
    if tier in (1, "1"):
        return "critical/" + _room_from_role(role)
    if tier in (2, "2"):
        return "high/" + _room_from_role(role)
    return f"{asset}/{_room_from_role(role)}"


def _room_from_role(role: str) -> str:
    clean = "".join(ch if ch.isalnum() or ch in ("_", "-") else "_" for ch in (role or "general"))
    return clean.strip("_").lower() or "general"


def _related_query(
    path: str,
    event_type: str,
    registry: dict[str, Any] | None,
    content_excerpt: str,
) -> str:
    registry = registry or {}
    role = registry.get("semantic_role") or "unknown role"
    tier = registry.get("tier") or "unknown tier"
    classification_hint = " ".join(
        token for token in [
            os.path.basename(path),
            event_type,
            str(role),
            str(tier),
            str(registry.get("asset_type") or ""),
            _content_keywords(content_excerpt),
        ]
        if token
    )
    return classification_hint[:1200]


def _related_queries(
    *,
    path: str,
    event_type: str,
    registry: dict[str, Any] | None,
    content_excerpt: str,
    analysis: dict[str, Any] | None = None,
) -> list[MemPalaceSearchQuery]:
    registry = registry or {}
    analysis = analysis or {}
    room = _room_for_registry(registry)
    role = str(registry.get("semantic_role") or analysis.get("semantic_role") or "unknown_role")
    tier = str(registry.get("tier") or analysis.get("tier") or "unknown_tier")
    asset = str(registry.get("asset_type") or registry.get("file_category") or analysis.get("asset_type") or "")
    file_name = os.path.basename(path)
    content_keywords = _content_keywords(content_excerpt)
    strategies = [
        MemPalaceSearchQuery(
            strategy="exact_path",
            room=room,
            query=" ".join(token for token in [
                "exact path",
                path,
                file_name,
                event_type,
                role,
                tier,
                asset,
            ] if token)[:1200],
        ),
        MemPalaceSearchQuery(
            strategy="role_tier",
            room=room,
            query=" ".join(token for token in [
                "same semantic role tier",
                role,
                f"tier {tier}",
                asset,
                str(registry.get("tier_label") or ""),
                "expected sources",
                " ".join(str(item) for item in registry.get("expected_change_sources") or []),
            ] if token)[:1200],
        ),
    ]

    history_terms = _path_history_terms(registry.get("path_history"))
    if history_terms:
        strategies.append(MemPalaceSearchQuery(
            strategy="path_history",
            room=room,
            query=f"path history renamed moved {' '.join(history_terms)} {role} {tier}"[:1200],
        ))

    verdict_terms = " ".join(str(item) for item in [
        analysis.get("priority"),
        analysis.get("risk_score"),
        analysis.get("threat_type"),
        analysis.get("threat_classification"),
    ] if item)
    if verdict_terms.strip():
        strategies.append(MemPalaceSearchQuery(
            strategy="previous_verdict",
            room=room,
            query=f"prior verdict {verdict_terms} role {role} tier {tier}"[:1200],
        ))

    if content_keywords:
        strategies.append(MemPalaceSearchQuery(
            strategy="content_indicators",
            room=room,
            query=f"similar content indicators {content_keywords} {role} {file_name}"[:1200],
        ))

    return _dedupe_queries(strategies)


def _content_keywords(text: str) -> str:
    value = (text or "").lower()
    keywords = []
    for token in (
        "reverse shell",
        "credential",
        "keylog",
        "getasynckeystate",
        "telegram",
        "scheduled task",
        "registry",
        "powershell",
        "processbuilder",
        "runtime.exec",
        "sudo",
        "ssh",
        "systemd",
    ):
        if token in value:
            keywords.append(token)
    return " ".join(keywords)


def _path_history_terms(history: Any) -> list[str]:
    if isinstance(history, str):
        try:
            history = json.loads(history)
        except json.JSONDecodeError:
            return [history[:200]]
    if not isinstance(history, list):
        return []
    terms: list[str] = []
    for item in history[-5:]:
        if not isinstance(item, dict):
            continue
        for key in ("old_path", "new_path"):
            value = item.get(key)
            if value:
                terms.append(str(value))
                terms.append(os.path.basename(str(value)))
    return _dedupe(terms)[:12]


def _format_path_history(history: Any) -> str:
    terms = _path_history_terms(history)
    return " -> ".join(terms[:8]) if terms else "none"


def _dedupe_queries(queries: list[MemPalaceSearchQuery]) -> list[MemPalaceSearchQuery]:
    seen: set[tuple[str, str, str]] = set()
    result: list[MemPalaceSearchQuery] = []
    for query in queries:
        key = (query.strategy, query.room, query.query)
        if not query.query.strip() or key in seen:
            continue
        seen.add(key)
        result.append(query)
    return result


def _annotate_hit(
    hit: MemPalaceMemoryHit,
    spec: MemPalaceSearchQuery,
    fallback: str | None = None,
) -> MemPalaceMemoryHit:
    metadata = dict(hit.metadata or {})
    strategies = _dedupe(list(_hit_strategies(hit)) + [spec.strategy])
    metadata["retrieval_strategy"] = spec.strategy
    metadata["retrieval_strategies"] = strategies
    metadata["retrieval_room"] = spec.room
    metadata["retrieval_query"] = spec.query
    if fallback:
        metadata["retrieval_fallback"] = fallback
    return MemPalaceMemoryHit(
        id=hit.id,
        text=hit.text,
        metadata=metadata,
        distance=hit.distance,
        similarity=hit.similarity,
        matched_via=hit.matched_via or spec.strategy,
    )


def _merge_search_hits(hits: list[MemPalaceMemoryHit]) -> list[MemPalaceMemoryHit]:
    merged: dict[str, MemPalaceMemoryHit] = {}
    for hit in hits:
        key = _hit_key(hit)
        existing = merged.get(key)
        if existing is None:
            merged[key] = hit
            continue
        metadata = dict(existing.metadata or {})
        metadata["retrieval_strategies"] = _dedupe(
            list(_hit_strategies(existing)) + list(_hit_strategies(hit))
        )
        metadata["retrieval_strategy"] = ", ".join(metadata["retrieval_strategies"])
        distance = _best_distance(existing.distance, hit.distance)
        similarity = _best_similarity(existing.similarity, hit.similarity)
        merged[key] = MemPalaceMemoryHit(
            id=existing.id or hit.id,
            text=existing.text if len(existing.text or "") >= len(hit.text or "") else hit.text,
            metadata=metadata,
            distance=distance,
            similarity=similarity,
            matched_via=", ".join(metadata["retrieval_strategies"]),
        )
    return sorted(
        merged.values(),
        key=lambda item: (
            item.distance if item.distance is not None else 999.0,
            -(item.similarity if item.similarity is not None else 0.0),
            item.id,
        ),
    )


def _hit_key(hit: MemPalaceMemoryHit) -> str:
    metadata = hit.metadata or {}
    if hit.id:
        return f"id:{hit.id}"
    for key in ("log_id", "file_id", "source_file_full", "file_path", "source_file"):
        if metadata.get(key):
            return f"{key}:{metadata.get(key)}"
    raw = f"{hit.text[:200]}|{metadata.get('semantic_role') or ''}"
    return "hash:" + hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _hit_strategies(hit: MemPalaceMemoryHit) -> list[str]:
    metadata = hit.metadata or {}
    strategies = metadata.get("retrieval_strategies")
    if isinstance(strategies, str):
        try:
            parsed = json.loads(strategies)
            if isinstance(parsed, list):
                return [str(item) for item in parsed if item]
        except json.JSONDecodeError:
            return [item.strip() for item in strategies.split(",") if item.strip()]
    if isinstance(strategies, list):
        return [str(item) for item in strategies if item]
    strategy = metadata.get("retrieval_strategy") or hit.matched_via
    return [str(strategy)] if strategy else []


def _best_distance(left: float | None, right: float | None) -> float | None:
    values = [item for item in (left, right) if item is not None]
    return min(values) if values else None


def _best_similarity(left: float | None, right: float | None) -> float | None:
    values = [item for item in (left, right) if item is not None]
    return max(values) if values else None


def _hits_from_search_result(result: dict[str, Any] | None) -> list[MemPalaceMemoryHit]:
    if not isinstance(result, dict):
        return []
    raw_hits = result.get("results")
    if isinstance(raw_hits, list):
        hits = []
        for item in raw_hits:
            if not isinstance(item, dict):
                continue
            text = str(item.get("text") or "")
            metadata = dict(item.get("metadata") or {}) if isinstance(item.get("metadata"), dict) else {}
            for key in ("wing", "room", "source_file", "created_at", "matched_via"):
                if item.get(key) is not None and key not in metadata:
                    metadata[key] = item.get(key)
            hit_id = str(
                item.get("id")
                or metadata.get("log_id")
                or metadata.get("source_file")
                or metadata.get("file_path")
                or ""
            )
            hits.append(MemPalaceMemoryHit(
                id=hit_id,
                text=text[:2000],
                metadata=metadata,
                distance=_as_float(item.get("distance")),
                similarity=_as_float(item.get("similarity")),
                matched_via=str(item.get("matched_via") or "") or None,
            ))
        return hits
    return []


def _lexical_fallback(query: str, room: str, limit: int) -> list[MemPalaceMemoryHit]:
    try:
        get_collection = _import_mempalace_collection()
        _configure_environment()
        collection = get_collection(
            _palace_path(),
            collection_name=_collection_name(),
            create=False,
            backend=str(getattr(settings, "mempalace_backend", "sqlite_exact") or "sqlite_exact"),
        )
        where = {"$and": [{"wing": MEMORY_WING}, {"room": room}]}
        results = collection.lexical_search(query=query, n_results=limit, where=where)
        hits = getattr(results, "hits", []) or []
        return [
            MemPalaceMemoryHit(
                id=str(hit.id),
                text=str(hit.document or "")[:2000],
                metadata=dict(hit.metadata or {}),
                similarity=_as_float(getattr(hit, "score", None)),
                matched_via="lexical",
            )
            for hit in hits
        ]
    except Exception:  # noqa: BLE001
        return []


def _should_store(analysis: dict[str, Any], registry: dict[str, Any] | None) -> bool:
    if not isinstance(analysis, dict):
        return False
    event_context = analysis.get("event_context") if isinstance(analysis.get("event_context"), dict) else {}
    metadata = event_context.get("metadata") if isinstance(event_context.get("metadata"), dict) else {}
    is_baseline = bool(metadata.get("is_baseline") or event_context.get("is_baseline"))
    score = _as_int(analysis.get("risk_score")) or 0
    tier = (registry or {}).get("tier") or analysis.get("tier")
    if is_baseline and not bool(getattr(settings, "mempalace_store_baseline_info", False)):
        return score >= max(1, int(getattr(settings, "mempalace_min_store_risk", 4) or 4))
    if tier in (1, 2, "1", "2"):
        return True
    return score >= max(0, int(getattr(settings, "mempalace_min_store_risk", 4) or 4))


def _event_memory_id(
    log_id: int | None,
    file_id: int | None,
    path: str,
    event_type: str,
    old_hash: str | None,
    new_hash: str | None,
) -> str:
    if log_id is not None:
        return f"fim-log-{log_id}"
    raw = "|".join(str(item or "") for item in (file_id, path, event_type, old_hash, new_hash))
    return "fim-" + hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:24]


def _baseline_memory_id(file_id: Any, path: str) -> str:
    if file_id is not None:
        return f"fim-baseline-file-{file_id}"
    raw = os.path.normcase(os.path.abspath(path)) if path else ""
    return "fim-baseline-path-" + hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:24]


def _sanitize_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in (metadata or {}).items():
        if value is None:
            continue
        if isinstance(value, (str, int, float, bool)):
            clean[str(key)] = value
        else:
            clean[str(key)] = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return clean


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _dedupe(items: list[Any]) -> list[Any]:
    values: list[Any] = []
    for item in items:
        if item and item not in values:
            values.append(item)
    return values
