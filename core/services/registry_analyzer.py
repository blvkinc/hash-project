"""Registry-aware change analysis helpers."""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from core.models import FileLog
from core.services.agent_investigator import run_agent_investigation
from core.services.file_registry import (
    get_registry_entry,
    registry_context,
    upsert_registry_entry,
)
from core.services.mempalace_agent import (
    MemPalaceAgentCore,
    build_mempalace_event,
    merge_mempalace_verdict,
)
from core.services.mempalace_bridge import (
    search_related_memories,
    upsert_event_memory,
)


PRIORITY_BY_SCORE = [
    (9, "critical"),
    (7, "high"),
    (4, "medium"),
    (2, "low"),
    (0, "info"),
]


def prepare_registry_analysis(
    session: Session,
    log: FileLog,
    event_context: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """
    Attach registry context to an event and return any identity-risk signal.

    This is intentionally deterministic and in-process. The LLM receives the
    context in metadata, but the minimum severity comes from local policy.
    """
    metadata = event_context.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {"_raw_metadata": metadata}
        event_context["metadata"] = metadata

    entry = get_registry_entry(session, file_id=log.file_id, path=log.path)
    if entry is None and log.event_type != "deleted":
        entry = upsert_registry_entry(
            session=session,
            path=log.path,
            metadata=metadata,
            file_hash=log.new_hash or log.old_hash,
            fast_hash=log.new_hash or log.old_hash,
            file_id=log.file_id,
            is_baseline=bool(metadata.get("is_baseline")),
        )

    context = registry_context(entry)
    if context is None:
        entry = upsert_registry_entry(
            session=session,
            path=log.path,
            metadata=metadata,
            file_hash=log.new_hash or log.old_hash,
            fast_hash=log.new_hash or log.old_hash,
            file_id=log.file_id,
            is_baseline=bool(metadata.get("is_baseline")),
            active=log.event_type != "deleted",
        )
        context = registry_context(entry)

    if context:
        event_context["registry"] = context
        metadata["registry"] = context

    signal = build_registry_signal(log.event_type, context, bool(metadata.get("is_baseline")))
    if signal:
        event_context["registry_signal"] = signal
        metadata["registry_signal"] = signal
    return context, signal


def build_registry_signal(
    event_type: str,
    context: dict[str, Any] | None,
    is_baseline: bool = False,
) -> dict[str, Any] | None:
    """Return a risk floor for identity-sensitive changes."""
    if not context or is_baseline:
        return None

    tier = context.get("tier")
    role = context.get("semantic_role") or "unknown_role"
    asset_type = context.get("asset_type") or context.get("file_category") or "unknown"
    tier_label = context.get("tier_label") or "Unclassified"

    if tier == 1:
        score = 10 if event_type == "deleted" else 9
        if event_type == "new":
            score = 8
        classification = "Critical Asset Change"
    elif tier == 2:
        score = 8 if event_type in {"modified", "deleted"} else 7
        if event_type == "renamed":
            score = 6
        classification = "High-Value Asset Change"
    else:
        return None

    priority = _priority_for_score(score)
    reasoning = (
        f"Registry identity analysis classified this file as Tier {tier} "
        f"{str(tier_label).lower()} with semantic role '{role}'. A {event_type} "
        f"event on this asset type ({asset_type}) can materially affect system "
        f"integrity even when file content is empty, binary, or otherwise unreadable. "
        f"No trusted update/package-manager context is currently attached to this "
        f"event, so the alert keeps a minimum {priority.upper()} severity."
    )

    return {
        "risk_score": score,
        "minimum_risk_score": score,
        "priority": priority,
        "is_malicious": False,
        "threat_type": "identity_risk",
        "threat_classification": classification,
        "confidence": context.get("confidence") or "medium",
        "reasoning": reasoning,
        "analysis_source": "registry_agent",
        "registry_agent": True,
        "identity_risk": True,
        "tier": tier,
        "semantic_role": role,
        "asset_type": asset_type,
        "registry": context,
        "findings": [{
            "category": "file_identity",
            "severity": score,
            "description": f"{event_type} event on {role}",
            "matches": 1,
        }],
        "context_notes": [
            "Severity was derived from persistent file identity, not content alone."
        ],
        "recommended_actions": _recommended_actions(priority, role, event_type),
    }


def analysis_from_registry_signal(signal: dict[str, Any] | None) -> dict[str, Any] | None:
    """Build a complete analysis payload from an identity-risk signal."""
    if not signal:
        return None
    return {
        "risk_score": signal.get("risk_score"),
        "priority": signal.get("priority"),
        "is_malicious": signal.get("is_malicious", False),
        "threat_type": signal.get("threat_type", "identity_risk"),
        "threat_classification": signal.get("threat_classification", "Identity Risk"),
        "mitre_attack": [],
        "iocs": [],
        "confidence": signal.get("confidence", "medium"),
        "reasoning": signal.get("reasoning", ""),
        "analysis_source": "registry_agent",
        "context_notes": signal.get("context_notes", []),
        "findings": signal.get("findings", []),
        "recommended_actions": signal.get("recommended_actions", []),
        "registry_agent": True,
        "identity_risk": True,
        "tier": signal.get("tier"),
        "semantic_role": signal.get("semantic_role"),
        "asset_type": signal.get("asset_type"),
        "registry": signal.get("registry"),
    }


def apply_registry_floor(
    analysis: dict[str, Any] | None,
    signal: dict[str, Any] | None,
) -> dict[str, Any]:
    """Ensure identity-risk semantics are not lost after content analysis."""
    if not analysis:
        return analysis_from_registry_signal(signal) or {}
    if not signal:
        return analysis

    current_score = int(analysis.get("risk_score") or 0)
    minimum_score = int(signal.get("minimum_risk_score") or signal.get("risk_score") or 0)
    merged = dict(analysis)
    merged["registry"] = signal.get("registry")
    merged["registry_agent"] = True
    merged["identity_risk"] = True
    merged["tier"] = signal.get("tier")
    merged["semantic_role"] = signal.get("semantic_role")
    merged["asset_type"] = signal.get("asset_type")

    notes = list(merged.get("context_notes") or [])
    notes.append(
        "Registry identity context was evaluated before final severity was assigned."
    )
    merged["context_notes"] = notes

    if minimum_score <= current_score:
        return merged

    merged["risk_score"] = minimum_score
    merged["priority"] = _priority_for_score(minimum_score)
    merged["threat_type"] = (
        merged.get("threat_type")
        if current_score >= 7 else signal.get("threat_type", "identity_risk")
    )
    merged["threat_classification"] = (
        signal.get("threat_classification")
        or merged.get("threat_classification")
        or "Identity Risk"
    )
    merged["confidence"] = _stronger_confidence(
        merged.get("confidence"), signal.get("confidence")
    )
    merged["analysis_source"] = _combine_sources(
        merged.get("analysis_source"), signal.get("analysis_source")
    )
    merged["reasoning"] = (
        f"{signal.get('reasoning', '')} Content analysis result: "
        f"{merged.get('reasoning', '')}"
    ).strip()
    merged["findings"] = list(signal.get("findings") or []) + list(merged.get("findings") or [])
    merged["recommended_actions"] = _merge_unique(
        signal.get("recommended_actions") or [],
        merged.get("recommended_actions") or [],
    )
    return merged


def run_mempalace_context_analysis(
    *,
    log: FileLog,
    event_context: dict[str, Any],
    content_payload: str,
    content_analysis: dict[str, Any],
    registry_signal: dict[str, Any] | None = None,
    previous_snippet_available: bool = False,
    change_summary: dict[str, Any] | str | None = None,
    performance_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the MemPalace-backed agent and merge its typed verdict."""
    metadata = event_context.get("metadata") if isinstance(event_context.get("metadata"), dict) else {}
    registry_context = (
        event_context.get("registry")
        or metadata.get("registry")
        or content_analysis.get("registry")
        or {}
    )
    related_hits, memory_status = search_related_memories(
        path=log.path,
        event_type=log.event_type,
        registry=registry_context if isinstance(registry_context, dict) else {},
        content_excerpt=content_payload,
        analysis=content_analysis,
    )
    related_memories = [hit.as_dict() for hit in related_hits]
    event = build_mempalace_event(
        path=log.path,
        event_type=log.event_type,
        event_context=event_context,
        content_excerpt=content_payload,
        content_analysis=content_analysis,
        registry_signal=registry_signal,
        previous_snippet_available=previous_snippet_available,
        change_summary=change_summary,
        memory_status=memory_status,
        related_memories=related_memories,
    )
    verdict = MemPalaceAgentCore().evaluate(event)
    merged = merge_mempalace_verdict(content_analysis, verdict)
    investigation = run_agent_investigation(
        log=log,
        event_context=event_context,
        analysis=merged,
        content_payload=content_payload,
        registry_context=registry_context if isinstance(registry_context, dict) else {},
        performance_context=performance_context,
    )
    if isinstance(investigation, dict):
        merged["agent_investigation"] = investigation
        if investigation.get("ran"):
            merged["agent_notification"] = {
                "title": investigation.get("notification_title", ""),
                "summary": investigation.get("notification_summary", ""),
                "trusted_change": investigation.get("trusted_change", "unknown"),
                "confidence": investigation.get("confidence", "medium"),
            }
            merged["recommended_actions"] = _merge_unique(
                list(investigation.get("recommended_actions") or []),
                list(merged.get("recommended_actions") or []),
            )
            notes = list(merged.get("context_notes") or [])
            notes.append(
                "MemPalace investigation tools evaluated file state, trusted-change context, content findings, and memory evidence."
            )
            merged["context_notes"] = _merge_unique(notes, [])
            merged["analysis_source"] = _combine_sources(
                merged.get("analysis_source"), "agent_investigation"
            )
    write_status = upsert_event_memory(
        log_id=log.id,
        file_id=log.file_id,
        path=log.path,
        event_type=log.event_type,
        old_hash=log.old_hash,
        new_hash=log.new_hash,
        registry=registry_context if isinstance(registry_context, dict) else {},
        analysis=merged,
        content_excerpt=content_payload,
    )
    merged["mempalace_memory"] = {
        "search": memory_status,
        "write": write_status,
        "related_count": len(related_memories),
    }
    if isinstance(merged.get("mem_palace"), dict):
        merged["mem_palace"]["memory_status"] = memory_status
        merged["mem_palace"]["memory_write"] = write_status
        merged["mem_palace"]["related_memories"] = related_memories[:5]
    return merged


def _priority_for_score(score: int) -> str:
    for threshold, priority in PRIORITY_BY_SCORE:
        if score >= threshold:
            return priority
    return "info"


def _combine_sources(primary: str | None, secondary: str | None) -> str:
    sources = [item for item in (primary, secondary) if item]
    if not sources:
        return "registry_agent"
    deduped = []
    for source in sources:
        if source not in deduped:
            deduped.append(source)
    return "+".join(deduped)


def _stronger_confidence(left: str | None, right: str | None) -> str:
    rank = {"low": 1, "medium": 2, "high": 3}
    left_key = (left or "low").lower()
    right_key = (right or "low").lower()
    return left_key if rank.get(left_key, 1) >= rank.get(right_key, 1) else right_key


def _merge_unique(first: list[Any], second: list[Any]) -> list[Any]:
    merged = []
    for item in first + second:
        if item and item not in merged:
            merged.append(item)
    return merged[:8]


def _recommended_actions(priority: str, role: str, event_type: str) -> list[str]:
    if priority == "critical":
        return [
            f"Verify whether the {role} {event_type} event matches an approved maintenance window.",
            "Check package manager, update, or deployment logs around the event timestamp.",
            "Preserve the file and surrounding logs for incident review.",
            "Restore from the last known good state if the change is unauthorized.",
        ]
    return [
        f"Review the {role} {event_type} event against expected deployment activity.",
        "Correlate with user, process, and package manager activity near the timestamp.",
        "Record as expected only after confirming the operational change source.",
    ]
