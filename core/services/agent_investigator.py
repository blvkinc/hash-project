"""Tool-oriented MemPalace investigation for high-value file events."""
from __future__ import annotations

import base64
import json
import os
import subprocess
from typing import Any, Literal

from pydantic import BaseModel, Field

from core.config import settings
from core.models import FileLog
from core.services.mempalace_agent import infer_os_family
from core.services.trusted_change import correlate_trusted_change


ObservationStatus = Literal["ok", "warn", "unknown", "error", "skipped"]
TrustedChange = Literal["confirmed", "unknown", "suspicious"]
Confidence = Literal["low", "medium", "high"]

HIGH_PRIORITIES = {"critical", "high"}
EXECUTABLE_EXTENSIONS = {
    ".bat", ".cat", ".cmd", ".cpl", ".dll", ".drv", ".exe", ".msi",
    ".ocx", ".ps1", ".psm1", ".scr", ".sys",
}
class AgentToolObservation(BaseModel):
    """A single bounded tool/check result from the agent investigation."""

    tool: str
    status: ObservationStatus = "unknown"
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)
    confidence: Confidence = "medium"


class AgentInvestigationReport(BaseModel):
    """Dashboard and notification-safe output from the investigation stage."""

    ran: bool = False
    agent_name: str = "MemPalace Investigation Agent"
    reason: str = ""
    severity_driver: str = ""
    trusted_change: TrustedChange = "unknown"
    trusted_change_sources: list[str] = Field(default_factory=list)
    tools_used: list[str] = Field(default_factory=list)
    observations: list[AgentToolObservation] = Field(default_factory=list)
    notification_title: str = ""
    notification_summary: str = ""
    recommended_actions: list[str] = Field(default_factory=list)
    confidence: Confidence = "medium"


class AgentInvestigationBudget(BaseModel):
    """Per-analysis-loop budget for deep embedded agent checks."""

    pending_depth: int = 0
    investigations_used: int = 0
    max_per_batch: int = 0
    backlog_threshold: int = 0
    backlog_critical_only: bool = True


def should_run_agent_investigation(
    *,
    log: FileLog,
    event_context: dict[str, Any] | None,
    analysis: dict[str, Any] | None,
    registry_context: dict[str, Any] | None,
    performance_context: dict[str, Any] | AgentInvestigationBudget | None = None,
) -> tuple[bool, str]:
    """Return whether a high-touch agent investigation should run."""
    if not bool(getattr(settings, "agent_investigation_enabled", True)):
        return False, "agent_investigation_disabled"

    metadata = _metadata(event_context)
    if bool(metadata.get("is_baseline")):
        return False, "baseline_event"

    analysis = analysis or {}
    registry_context = registry_context or {}
    priority = str(analysis.get("priority") or log.priority or "info").lower()
    score = _safe_int(analysis.get("risk_score") if analysis.get("risk_score") is not None else log.risk_score)
    tier = _safe_int(registry_context.get("tier") or analysis.get("tier"))
    agent_content = ((analysis.get("mem_palace") or {}).get("agent_content") or {})
    agent_content_score = _safe_int(agent_content.get("risk_score"))
    min_risk = int(getattr(settings, "agent_investigation_min_risk", 7) or 7)

    if priority in HIGH_PRIORITIES:
        candidate_reason = f"{priority}_priority_event"
    elif score >= min_risk:
        candidate_reason = f"risk_score_{score}_meets_threshold"
    elif tier in {1, 2} and log.event_type != "new":
        candidate_reason = f"tier_{tier}_identity_event"
    elif agent_content_score >= min_risk:
        candidate_reason = f"agent_content_score_{agent_content_score}_meets_threshold"
    else:
        return False, "below_investigation_threshold"

    budget = _investigation_budget(performance_context)
    critical_driver = _is_critical_investigation_driver(
        priority=priority,
        score=score,
        tier=tier,
        agent_content_score=agent_content_score,
    )
    if (
        budget.backlog_threshold > 0
        and budget.pending_depth >= budget.backlog_threshold
        and budget.backlog_critical_only
        and not critical_driver
    ):
        return False, "performance_backlog_guard"
    if (
        budget.max_per_batch > 0
        and budget.investigations_used >= budget.max_per_batch
        and not critical_driver
    ):
        return False, "performance_batch_budget_exhausted"
    return True, candidate_reason


def run_agent_investigation(
    *,
    log: FileLog,
    event_context: dict[str, Any] | None,
    analysis: dict[str, Any] | None,
    content_payload: str,
    registry_context: dict[str, Any] | None,
    performance_context: dict[str, Any] | AgentInvestigationBudget | None = None,
) -> dict[str, Any]:
    """
    Run bounded local agent tools for a high-value change.

    This is intentionally deterministic and embedded. It gives the agent its
    own visible observations today, while leaving clear extension points for deeper
    package-manager, process, and event-log tools later.
    """
    should_run, reason = should_run_agent_investigation(
        log=log,
        event_context=event_context,
        analysis=analysis,
        registry_context=registry_context,
        performance_context=performance_context,
    )
    if not should_run:
        return AgentInvestigationReport(ran=False, reason=reason).model_dump()

    analysis = analysis or {}
    registry_context = registry_context or {}
    observations = [
        _observe_current_file_state(log, registry_context),
        _observe_trusted_change_context(log, event_context, registry_context),
        _observe_agent_content(analysis, content_payload),
        _observe_mempalace_memory(analysis),
        _observe_windows_signature(log.path),
    ]
    trusted_change, trusted_sources = _trusted_change_from_observations(
        observations,
        analysis=analysis,
    )
    priority = str(analysis.get("priority") or log.priority or "info").lower()
    score = _safe_int(analysis.get("risk_score") if analysis.get("risk_score") is not None else log.risk_score)
    os_family = infer_os_family(log.path)
    role = str(registry_context.get("semantic_role") or analysis.get("semantic_role") or "file")
    notification_title = _notification_title(priority, score, log, role)
    notification_summary = _notification_summary(
        log=log,
        analysis=analysis,
        registry_context=registry_context,
        observations=observations,
        trusted_change=trusted_change,
    )
    actions = _investigation_actions(
        priority=priority,
        os_family=os_family,
        role=role,
        event_type=log.event_type,
        trusted_change=trusted_change,
        observations=observations,
    )

    report = AgentInvestigationReport(
        ran=True,
        reason=reason,
        severity_driver=_severity_driver(analysis, registry_context),
        trusted_change=trusted_change,
        trusted_change_sources=trusted_sources,
        tools_used=[item.tool for item in observations],
        observations=observations,
        notification_title=notification_title,
        notification_summary=notification_summary,
        recommended_actions=actions,
        confidence=_investigation_confidence(observations, trusted_change, score),
    )
    return report.model_dump()


def _observe_current_file_state(
    log: FileLog,
    registry_context: dict[str, Any],
) -> AgentToolObservation:
    path = log.path
    if _looks_non_filesystem(path):
        return AgentToolObservation(
            tool="current_file_state",
            status="skipped",
            summary="Path is not a normal filesystem object, so live stat inspection was skipped.",
            details={"path": path},
            confidence="medium",
        )

    expected_hash = log.new_hash or registry_context.get("current_hash")
    last_good = registry_context.get("last_known_good_hash")
    try:
        if not os.path.exists(path):
            return AgentToolObservation(
                tool="current_file_state",
                status="warn" if log.event_type != "deleted" else "ok",
                summary="Current file is not present on disk.",
                details={"path": path, "event_type": log.event_type},
                confidence="high",
            )
        stat = os.stat(path)
        hash_state = "changed_from_last_good" if last_good and expected_hash and last_good != expected_hash else "not_compared"
        if last_good and expected_hash and last_good == expected_hash:
            hash_state = "matches_last_good"
        return AgentToolObservation(
            tool="current_file_state",
            status="ok",
            summary=f"Current file exists; size={stat.st_size} bytes, hash_state={hash_state}.",
            details={
                "path": path,
                "size": stat.st_size,
                "mtime": stat.st_mtime,
                "event_type": log.event_type,
                "observed_hash": expected_hash,
                "last_known_good_hash": last_good,
                "hash_state": hash_state,
            },
            confidence="high",
        )
    except OSError as exc:
        return AgentToolObservation(
            tool="current_file_state",
            status="error",
            summary=f"Could not inspect current file state: {exc}",
            details={"path": path, "error": str(exc)},
            confidence="low",
        )


def _observe_trusted_change_context(
    log: FileLog,
    event_context: dict[str, Any] | None,
    registry_context: dict[str, Any],
) -> AgentToolObservation:
    report = correlate_trusted_change(
        file_path=log.path,
        event_type=log.event_type,
        event_context=event_context,
        registry_context=registry_context,
        event_timestamp=log.timestamp,
        os_family=infer_os_family(log.path),
    )
    result = str(report.get("result") or "unknown")
    status: ObservationStatus = "ok" if result == "confirmed" else "warn"
    if result == "unknown":
        status = "unknown"
    return AgentToolObservation(
        tool="trusted_change_context",
        status=status,
        summary=str(report.get("summary") or "Trusted-change correlation completed."),
        details={
            "trusted_change_result": result,
            "trusted_sources": list(report.get("trusted_sources") or []),
            "matched_sources": list(report.get("matched_sources") or []),
            "expected_change_sources": list(report.get("expected_change_sources") or []),
            "evidence": list(report.get("evidence") or []),
            "maintenance_window_active": bool(report.get("maintenance_window_active")),
        },
        confidence="high" if result == "confirmed" else "medium",
    )


def _observe_agent_content(
    analysis: dict[str, Any],
    content_payload: str,
) -> AgentToolObservation:
    agent_content = ((analysis.get("mem_palace") or {}).get("agent_content") or {})
    inspected = bool(agent_content.get("inspected"))
    risk_score = _safe_int(agent_content.get("risk_score"))
    if inspected:
        status: ObservationStatus = "warn" if risk_score >= 7 else "ok"
        return AgentToolObservation(
            tool="agent_content_inspection",
            status=status,
            summary=str(agent_content.get("summary") or "Agent inspected the captured change payload."),
            details={
                "risk_score": risk_score,
                "priority": agent_content.get("priority"),
                "threat_type": agent_content.get("threat_type"),
                "classification": agent_content.get("threat_classification"),
                "iocs": agent_content.get("iocs") or [],
            },
            confidence="high" if risk_score >= 7 else "medium",
        )
    if (content_payload or "").strip() and content_payload not in {"Binary/Unreadable", "File deleted"}:
        return AgentToolObservation(
            tool="agent_content_inspection",
            status="unknown",
            summary="Readable content was captured, but no agent content verdict was available.",
            details={"payload_bytes": len(content_payload.encode("utf-8", errors="ignore"))},
            confidence="low",
        )
    return AgentToolObservation(
        tool="agent_content_inspection",
        status="skipped",
        summary="No readable content was available for agent inspection.",
        details={},
        confidence="medium",
    )


def _observe_mempalace_memory(analysis: dict[str, Any]) -> AgentToolObservation:
    mem = analysis.get("mem_palace") or {}
    memory = analysis.get("mempalace_memory") or {}
    search = mem.get("memory_status") or memory.get("search") or {}
    related = mem.get("related_memories") or []
    hits = _safe_int(search.get("hits"))
    searched = bool(search.get("searched") or hits or related)
    strategies = _memory_strategies(search, related)
    if related or hits:
        closest = _memory_source(related[0]) if related else "prior event"
        strategy_text = f" via {', '.join(strategies[:3])}" if strategies else ""
        return AgentToolObservation(
            tool="mempalace_related_memory_search",
            status="ok",
            summary=f"MemPalace returned {max(hits, len(related))} related memory item(s){strategy_text}; closest: {closest}.",
            details={"hits": max(hits, len(related)), "closest": closest, "retrieval_strategies": strategies},
            confidence="medium",
        )
    if searched:
        return AgentToolObservation(
            tool="mempalace_related_memory_search",
            status="unknown",
            summary="MemPalace search ran, but no related prior memory was found.",
            details={"hits": 0},
            confidence="medium",
        )
    return AgentToolObservation(
        tool="mempalace_related_memory_search",
        status="skipped",
        summary="MemPalace related-memory search was not available for this event.",
        details=search if isinstance(search, dict) else {},
        confidence="low",
    )


def _observe_windows_signature(path: str) -> AgentToolObservation:
    if not bool(getattr(settings, "agent_investigation_signature_check", True)):
        return AgentToolObservation(
            tool="windows_authenticode_signature",
            status="skipped",
            summary="Windows signature inspection is disabled by configuration.",
            details={},
            confidence="medium",
        )
    if infer_os_family(path) != "windows":
        return AgentToolObservation(
            tool="windows_authenticode_signature",
            status="skipped",
            summary="Authenticode inspection applies only to Windows filesystem paths.",
            details={"os_family": infer_os_family(path)},
            confidence="medium",
        )
    ext = os.path.splitext(path)[1].lower()
    if ext not in EXECUTABLE_EXTENSIONS:
        return AgentToolObservation(
            tool="windows_authenticode_signature",
            status="skipped",
            summary="File type does not normally carry an Authenticode signature.",
            details={"extension": ext or "(none)"},
            confidence="medium",
        )
    if not os.path.exists(path):
        return AgentToolObservation(
            tool="windows_authenticode_signature",
            status="unknown",
            summary="File is not present, so Authenticode signature could not be checked.",
            details={"path": path},
            confidence="low",
        )

    try:
        payload = _run_authenticode_signature(path)
    except Exception as exc:
        return AgentToolObservation(
            tool="windows_authenticode_signature",
            status="error",
            summary=f"Authenticode signature check failed: {exc}",
            details={"path": path, "error": str(exc)},
            confidence="low",
        )

    status_value = str(payload.get("Status") or payload.get("status") or "Unknown")
    signer = str(payload.get("Signer") or payload.get("signer") or "")
    status: ObservationStatus = "ok" if status_value.lower() == "valid" else "warn"
    return AgentToolObservation(
        tool="windows_authenticode_signature",
        status=status,
        summary=(
            f"Authenticode status is {status_value}"
            + (f" from {signer}." if signer else ".")
        ),
        details=payload,
        confidence="high" if status == "ok" else "medium",
    )


def _run_authenticode_signature(path: str) -> dict[str, Any]:
    path_b64 = base64.b64encode(path.encode("utf-8")).decode("ascii")
    script = f"""
$ErrorActionPreference = 'Stop'
$path = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{path_b64}'))
$sig = Get-AuthenticodeSignature -LiteralPath $path
$signer = $null
if ($sig.SignerCertificate) {{ $signer = $sig.SignerCertificate.Subject }}
[PSCustomObject]@{{
  Status = "$($sig.Status)";
  StatusMessage = "$($sig.StatusMessage)";
  Signer = "$signer"
}} | ConvertTo-Json -Compress
"""
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            encoded,
        ],
        capture_output=True,
        text=True,
        timeout=max(0.5, float(getattr(settings, "agent_investigation_signature_timeout_seconds", 3.0) or 3.0)),
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "PowerShell returned an error").strip())
    parsed = json.loads(result.stdout or "{}")
    return parsed if isinstance(parsed, dict) else {}


def _trusted_change_from_observations(
    observations: list[AgentToolObservation],
    *,
    analysis: dict[str, Any],
) -> tuple[TrustedChange, list[str]]:
    source_obs = _find_observation(observations, "trusted_change_context")
    sources = []
    if source_obs:
        sources = list(source_obs.details.get("trusted_sources") or [])
        if source_obs.details.get("trusted_change_result") == "confirmed":
            return "confirmed", sources

    priority = str(analysis.get("priority") or "info").lower()
    score = _safe_int(analysis.get("risk_score"))
    if priority in HIGH_PRIORITIES or score >= 7:
        return "suspicious", sources
    return "unknown", sources


def _investigation_actions(
    *,
    priority: str,
    os_family: str,
    role: str,
    event_type: str,
    trusted_change: TrustedChange,
    observations: list[AgentToolObservation],
) -> list[str]:
    actions: list[str] = []
    if trusted_change != "confirmed":
        actions.append("Confirm whether an approved deployment, package update, or administrator action covers this event.")
    if os_family == "windows":
        actions.append("Check Windows Update, installer, Event Viewer, Defender, and Sysmon/process logs around the event time.")
    elif os_family == "linux":
        actions.append("Check apt/yum/dnf, journalctl, auth logs, cron, and service-manager logs around the event time.")
    elif os_family == "darwin":
        actions.append("Check softwareupdate, launchd, quarantine, and endpoint security logs around the event time.")
    else:
        actions.append("Correlate the change with OS update, deployment, process, and user activity logs.")
    actions.append(f"Compare the changed {role} {event_type} event against the last known good registry state.")
    if any(obs.tool == "agent_content_inspection" and obs.status == "warn" for obs in observations):
        actions.append("Review the agent content findings and isolate the file if the behavior is unauthorized.")
    if priority == "critical":
        actions.append("Preserve the changed file, adjacent logs, and related MemPalace timeline evidence for incident review.")
    return _dedupe(actions)[:6]


def _notification_title(priority: str, score: int, log: FileLog, role: str) -> str:
    severity = "SEV-1" if priority == "critical" or score >= 9 else "SEV-2"
    name = os.path.basename(log.path) or log.path
    return f"{severity}: {role.replace('_', ' ')} {log.event_type} - {name}"


def _notification_summary(
    *,
    log: FileLog,
    analysis: dict[str, Any],
    registry_context: dict[str, Any],
    observations: list[AgentToolObservation],
    trusted_change: TrustedChange,
) -> str:
    role = str(registry_context.get("semantic_role") or analysis.get("semantic_role") or "file").replace("_", " ")
    tier = registry_context.get("tier") or analysis.get("tier") or "unclassified"
    trust_phrase = {
        "confirmed": "a trusted change source was attached",
        "suspicious": "no trusted change source was confirmed",
        "unknown": "trusted change source is unknown",
    }.get(trusted_change, "trusted change source is unknown")
    content_obs = _find_observation(observations, "agent_content_inspection")
    content_phrase = content_obs.summary if content_obs and content_obs.status == "warn" else "No high-confidence content indicator was added by the agent."
    return (
        f"Agent investigated Tier {tier} {role} event at {log.path}; "
        f"{trust_phrase}. {content_phrase}"
    )


def _severity_driver(
    analysis: dict[str, Any],
    registry_context: dict[str, Any],
) -> str:
    mem = analysis.get("mem_palace") or {}
    agent_content = mem.get("agent_content") or {}
    if _safe_int(agent_content.get("risk_score")) >= 7:
        return "agent_content_indicator"
    if bool(analysis.get("identity_risk") or mem.get("identity_risk")):
        return "registry_identity"
    if registry_context.get("tier") in {1, 2}:
        return "high_value_registry_tier"
    return "analysis_score"


def _investigation_confidence(
    observations: list[AgentToolObservation],
    trusted_change: TrustedChange,
    score: int,
) -> Confidence:
    high_signal = any(obs.status == "warn" and obs.confidence == "high" for obs in observations)
    has_file_state = any(obs.tool == "current_file_state" and obs.status in {"ok", "warn"} for obs in observations)
    if high_signal or (score >= 9 and has_file_state and trusted_change != "unknown"):
        return "high"
    if has_file_state or score >= 7:
        return "medium"
    return "low"


def _metadata(event_context: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(event_context, dict):
        return {}
    metadata = event_context.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def _investigation_budget(
    performance_context: dict[str, Any] | AgentInvestigationBudget | None,
) -> AgentInvestigationBudget:
    if isinstance(performance_context, AgentInvestigationBudget):
        return performance_context
    context = performance_context if isinstance(performance_context, dict) else {}
    return AgentInvestigationBudget(
        pending_depth=_safe_int(context.get("pending_depth")),
        investigations_used=_safe_int(context.get("investigations_used")),
        max_per_batch=_safe_int(
            context.get(
                "max_per_batch",
                getattr(settings, "agent_investigation_max_per_batch", 8),
            )
        ),
        backlog_threshold=_safe_int(
            context.get(
                "backlog_threshold",
                getattr(settings, "agent_investigation_backlog_threshold", 500),
            )
        ),
        backlog_critical_only=bool(
            context.get(
                "backlog_critical_only",
                getattr(settings, "agent_investigation_backlog_critical_only", True),
            )
        ),
    )


def _is_critical_investigation_driver(
    *,
    priority: str,
    score: int,
    tier: int,
    agent_content_score: int,
) -> bool:
    return priority == "critical" or score >= 9 or tier == 1 or agent_content_score >= 9


def _looks_non_filesystem(path: str) -> bool:
    low = (path or "").lower().replace("/", "\\")
    return low.startswith(("hklm\\", "hkcu\\", "hkcr\\", "hku\\", "hkcc\\", "registry::"))


def _find_observation(
    observations: list[AgentToolObservation],
    tool: str,
) -> AgentToolObservation | None:
    for item in observations:
        if item.tool == tool:
            return item
    return None


def _memory_source(memory: dict[str, Any]) -> str:
    if not isinstance(memory, dict):
        return "prior event"
    metadata = memory.get("metadata") if isinstance(memory.get("metadata"), dict) else {}
    return str(
        metadata.get("source_file")
        or metadata.get("file_path")
        or memory.get("id")
        or "prior event"
    )


def _memory_strategies(
    search_status: dict[str, Any],
    related_memories: list[dict[str, Any]],
) -> list[str]:
    values: list[str] = []
    raw_status = search_status.get("retrieval_strategies") if isinstance(search_status, dict) else []
    if isinstance(raw_status, list):
        values.extend(str(item) for item in raw_status if item)
    for memory in related_memories or []:
        if not isinstance(memory, dict):
            continue
        metadata = memory.get("metadata") if isinstance(memory.get("metadata"), dict) else {}
        raw = metadata.get("retrieval_strategies") or metadata.get("retrieval_strategy")
        if isinstance(raw, list):
            values.extend(str(item) for item in raw if item)
        elif isinstance(raw, str):
            values.extend(item.strip() for item in raw.replace("[", "").replace("]", "").replace('"', "").split(",") if item.strip())
    return _dedupe(values)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _dedupe(items: list[Any]) -> list[Any]:
    values: list[Any] = []
    for item in items:
        if item and item not in values:
            values.append(item)
    return values
