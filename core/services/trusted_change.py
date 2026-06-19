"""Trusted-change correlation for agent investigations.

This module turns update/deployment/maintenance signals into structured
evidence that the MemPalace investigation agent can use before alerting.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

from core.config import settings
from core.os_context import get_recent_system_updates
from core.services.mempalace_agent import infer_os_family


CorrelationResult = Literal["confirmed", "unknown", "suspicious"]
EvidenceStatus = Literal["confirmed", "mismatch", "unknown"]
EvidenceConfidence = Literal["low", "medium", "high"]

METADATA_SOURCE_KEYS = {
    "trusted_change_source",
    "trusted_source",
    "change_source",
    "update_source",
    "package_manager",
    "package_manager_event",
    "os_update",
    "windows_update",
    "installer",
    "signed_installer",
    "msi_product",
    "deployment_id",
    "deployment_tool",
    "ci_pipeline_id",
    "approved_change_id",
    "administrator_action",
}

MAINTENANCE_KEYS = {
    "maintenance_window",
    "maintenance_window_id",
    "maintenance_window_start",
    "maintenance_window_end",
}

PACKAGE_MARKERS = (
    "apt", "dpkg", "yum", "dnf", "rpm", "pacman", "zypper", "apk",
    "brew", "homebrew", "winget", "choco", "chocolatey", "scoop",
)
WINDOWS_UPDATE_MARKERS = ("windows_update", "windows update", "wu", "microsoft update")
INSTALLER_MARKERS = ("installer", "msi", "setup", "pkg", "dmg")
DEPLOYMENT_MARKERS = ("deployment", "deploy", "ci", "pipeline", "release", "gitops")

EXPECTED_ALIASES = {
    "os_update": {"os_update", "package_manager", "windows_update", "installer"},
    "package_manager": {"package_manager", "os_update"},
    "windows_update": {"windows_update", "os_update", "installer"},
    "administrator_maintenance": {
        "administrator_maintenance",
        "maintenance_window",
        "approved_change",
        "administrator_action",
    },
    "service_deployment": {"service_deployment", "application_deployment", "deployment", "installer"},
    "application_deployment": {"application_deployment", "deployment", "developer_change"},
    "developer_change": {"developer_change", "application_deployment", "deployment"},
    "application_runtime": {"application_runtime"},
    "log_rotation": {"log_rotation", "application_runtime"},
    "cache_cleanup": {"cache_cleanup", "application_runtime"},
    "user_change": {"user_change", "developer_change", "administrator_action"},
}


class TrustedChangeEvidence(BaseModel):
    """One trusted-change evidence item."""

    source: str
    category: str
    status: EvidenceStatus = "unknown"
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)
    confidence: EvidenceConfidence = "medium"


class TrustedChangeReport(BaseModel):
    """Structured trusted-change correlation report."""

    result: CorrelationResult = "unknown"
    summary: str
    expected_change_sources: list[str] = Field(default_factory=list)
    trusted_sources: list[str] = Field(default_factory=list)
    matched_sources: list[str] = Field(default_factory=list)
    evidence: list[TrustedChangeEvidence] = Field(default_factory=list)
    maintenance_window_active: bool = False


def correlate_trusted_change(
    *,
    file_path: str,
    event_type: str,
    event_context: dict[str, Any] | None,
    registry_context: dict[str, Any] | None,
    event_timestamp: datetime | None = None,
    os_family: str | None = None,
) -> dict[str, Any]:
    """Correlate a file event with trusted update/deployment context."""
    registry = registry_context or {}
    expected = [str(item) for item in registry.get("expected_change_sources") or []]
    metadata = _metadata(event_context)
    target_os = os_family or infer_os_family(file_path)
    timestamp = _event_time(event_timestamp)

    evidence: list[TrustedChangeEvidence] = []
    evidence.extend(_metadata_evidence(metadata, expected))
    evidence.extend(_maintenance_evidence(metadata, expected, timestamp))
    evidence.extend(_os_update_evidence(target_os, expected))

    matched = [
        item.source for item in evidence
        if item.status == "confirmed" and _category_matches_expected(item.category, expected)
    ]
    trusted_sources = [item.source for item in evidence if item.status == "confirmed"]
    maintenance_active = any(
        item.category == "maintenance_window" and item.status == "confirmed"
        for item in evidence
    )

    if matched:
        result: CorrelationResult = "confirmed"
        summary = f"Trusted change confirmed by {', '.join(matched[:3])}."
    elif evidence:
        result = "unknown"
        summary = (
            "Trusted activity was found, but it did not match this file's expected "
            "change sources."
        )
    else:
        result = "suspicious"
        summary = "No trusted package, update, deployment, or maintenance source was correlated."

    report = TrustedChangeReport(
        result=result,
        summary=summary,
        expected_change_sources=expected,
        trusted_sources=trusted_sources,
        matched_sources=matched,
        evidence=evidence,
        maintenance_window_active=maintenance_active,
    )
    return report.model_dump()


def _metadata_evidence(
    metadata: dict[str, Any],
    expected_sources: list[str],
) -> list[TrustedChangeEvidence]:
    evidence: list[TrustedChangeEvidence] = []
    for key in sorted(METADATA_SOURCE_KEYS):
        value = metadata.get(key)
        if value is None or value == "":
            continue
        for label, raw_value in _flatten_metadata_value(key, value):
            category = _category_for_source(label, raw_value)
            status: EvidenceStatus = (
                "confirmed" if _category_matches_expected(category, expected_sources)
                else "mismatch"
            )
            evidence.append(TrustedChangeEvidence(
                source=label,
                category=category,
                status=status,
                summary=f"Metadata supplied trusted-change source {label}.",
                details={"key": key, "value": raw_value},
                confidence="high",
            ))
    return evidence


def _maintenance_evidence(
    metadata: dict[str, Any],
    expected_sources: list[str],
    timestamp: datetime,
) -> list[TrustedChangeEvidence]:
    evidence: list[TrustedChangeEvidence] = []
    metadata_window = _metadata_maintenance_window(metadata, timestamp)
    if metadata_window is not None:
        status: EvidenceStatus = "confirmed" if metadata_window["active"] else "unknown"
        evidence.append(TrustedChangeEvidence(
            source=metadata_window["source"],
            category="maintenance_window",
            status=status,
            summary=(
                "Event timestamp falls inside the supplied maintenance window."
                if metadata_window["active"]
                else "A maintenance window was supplied, but the event timestamp is outside it."
            ),
            details=metadata_window,
            confidence="high",
        ))

    env_windows = _configured_maintenance_windows()
    for idx, window in enumerate(env_windows):
        active = _timestamp_in_window(timestamp, window)
        evidence.append(TrustedChangeEvidence(
            source=f"configured_maintenance_window:{window.get('id') or idx + 1}",
            category="maintenance_window",
            status="confirmed" if active else "unknown",
            summary=(
                "Event timestamp falls inside a configured maintenance window."
                if active else
                "Configured maintenance window exists but does not cover the event timestamp."
            ),
            details=window,
            confidence="high" if active else "medium",
        ))

    if not _category_matches_expected("maintenance_window", expected_sources):
        for item in evidence:
            if item.status == "confirmed":
                item.status = "mismatch"
                item.summary = (
                    "Maintenance activity was found, but this file role does not list "
                    "maintenance as an expected source."
                )
    return evidence


def _os_update_evidence(
    target_os: str,
    expected_sources: list[str],
) -> list[TrustedChangeEvidence]:
    if target_os not in {"linux", "windows", "darwin"}:
        return []
    try:
        context = get_recent_system_updates(target_os=target_os)
    except Exception as exc:
        return [TrustedChangeEvidence(
            source=f"os_update_probe:{target_os}",
            category="os_update",
            status="unknown",
            summary=f"OS update probe failed: {exc}",
            details={"error": str(exc), "target_os": target_os},
            confidence="low",
        )]

    if not context.get("recent_updates"):
        return []
    package_manager = str(context.get("package_manager") or f"{target_os}_update")
    category = _category_for_source("runtime_update_context", package_manager)
    status: EvidenceStatus = (
        "confirmed" if _category_matches_expected(category, expected_sources)
        else "mismatch"
    )
    return [TrustedChangeEvidence(
        source=f"os_update_context:{package_manager}",
        category=category,
        status=status,
        summary=f"Recent {package_manager} activity was detected on the host.",
        details={
            "target_os": target_os,
            "package_manager": package_manager,
            "details": list(context.get("details") or []),
        },
        confidence="medium",
    )]


def _metadata(event_context: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(event_context, dict):
        return {}
    metadata = event_context.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def _flatten_metadata_value(key: str, value: Any) -> list[tuple[str, Any]]:
    if isinstance(value, bool):
        return [(key, value)] if value else []
    if isinstance(value, dict):
        return [
            (f"{key}:{subkey}={item}", item)
            for subkey, item in value.items()
            if item not in (None, "", False)
        ]
    if isinstance(value, list):
        return [
            (f"{key}:{item}", item)
            for item in value
            if item not in (None, "", False)
        ]
    return [(f"{key}:{value}", value)]


def _metadata_maintenance_window(
    metadata: dict[str, Any],
    timestamp: datetime,
) -> dict[str, Any] | None:
    value = metadata.get("maintenance_window")
    start = metadata.get("maintenance_window_start")
    end = metadata.get("maintenance_window_end")
    window_id = metadata.get("maintenance_window_id")

    if isinstance(value, dict):
        start = value.get("start") or value.get("from") or start
        end = value.get("end") or value.get("to") or end
        window_id = value.get("id") or window_id
    elif isinstance(value, str) and ".." in value:
        start, end = value.split("..", 1)
    elif value is True and not (start and end):
        return {
            "source": f"metadata_maintenance_window:{window_id or 'approved'}",
            "active": True,
            "id": window_id,
            "start": None,
            "end": None,
        }

    if not (start and end):
        return None
    parsed = {"id": window_id, "start": str(start), "end": str(end)}
    parsed["active"] = _timestamp_in_window(timestamp, parsed)
    parsed["source"] = f"metadata_maintenance_window:{window_id or parsed['start']}"
    return parsed


def _configured_maintenance_windows() -> list[dict[str, Any]]:
    raw = str(getattr(settings, "trusted_maintenance_windows", "") or os.environ.get(
        "FIM_TRUSTED_MAINTENANCE_WINDOWS", ""
    )).strip()
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = None
    windows: list[dict[str, Any]] = []
    if isinstance(parsed, list):
        for item in parsed:
            if isinstance(item, dict) and item.get("start") and item.get("end"):
                windows.append(dict(item))
        return windows
    for idx, item in enumerate(raw.split(";"), 1):
        if ".." not in item:
            continue
        start, end = item.split("..", 1)
        windows.append({"id": f"env-{idx}", "start": start.strip(), "end": end.strip()})
    return windows


def _timestamp_in_window(timestamp: datetime, window: dict[str, Any]) -> bool:
    start = _parse_datetime(window.get("start"))
    end = _parse_datetime(window.get("end"))
    if start is None or end is None:
        return False
    current = _event_time(timestamp)
    if start.tzinfo is None:
        start = start.replace(tzinfo=current.tzinfo)
    if end.tzinfo is None:
        end = end.replace(tzinfo=current.tzinfo)
    return start <= current <= end


def _event_time(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _category_for_source(source: str, value: Any) -> str:
    text = f"{source} {value}".lower().replace("-", "_")
    if any(marker in text for marker in WINDOWS_UPDATE_MARKERS):
        return "windows_update"
    if any(marker in text for marker in PACKAGE_MARKERS):
        return "package_manager"
    if any(marker in text for marker in INSTALLER_MARKERS):
        return "installer"
    if any(marker in text for marker in DEPLOYMENT_MARKERS):
        return "application_deployment"
    if "approved_change" in text:
        return "approved_change"
    if "administrator" in text or "admin" in text:
        return "administrator_action"
    if "os_update" in text or "update_source" in text:
        return "os_update"
    return "trusted_source"


def _category_matches_expected(category: str, expected_sources: list[str]) -> bool:
    if not expected_sources:
        return True
    normalized = category.lower().replace("-", "_")
    for expected in expected_sources:
        expected_norm = str(expected).lower().replace("-", "_")
        aliases = EXPECTED_ALIASES.get(expected_norm, {expected_norm})
        if normalized in aliases or expected_norm == normalized:
            return True
    return False
