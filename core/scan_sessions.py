"""Helpers for persisted scan session summaries."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from .models import ScanSession


def create_scan_session(
    session: Session,
    root_path: str,
    trigger: str,
    mode: str = "metadata_first",
) -> ScanSession:
    """Create a queued scan session row."""
    now = datetime.utcnow()
    scan = ScanSession(
        root_path=root_path,
        trigger=trigger,
        mode=mode,
        status="queued",
        started_at=now,
        updated_at=now,
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


def mark_scan_running(session: Session, scan_id: int) -> None:
    """Mark a scan session as running."""
    scan = session.get(ScanSession, scan_id)
    if not scan:
        return
    scan.status = "running"
    scan.updated_at = datetime.utcnow()
    session.commit()


def complete_scan_session(
    session: Session,
    scan_id: int,
    baseline: dict[str, Any],
    changes: dict[str, Any],
) -> None:
    """Persist final counters for a completed scan."""
    scan = session.get(ScanSession, scan_id)
    if not scan:
        return

    now = datetime.utcnow()
    scan.status = "complete"
    scan.updated_at = now
    scan.completed_at = now
    scan.total_discovered = _int(baseline.get("total_files"))
    scan.baseline_new = _int(baseline.get("new_baselined"))
    scan.baseline_updated = _int(baseline.get("updated"))
    scan.baseline_reanalyzed = _int(baseline.get("reanalyzed"))
    scan.baseline_reanalyze_skipped = _int(baseline.get("reanalyze_skipped"))
    scan.baseline_analysis_checked = _int(baseline.get("baseline_analysis_checked"))
    scan.baseline_analysis_queued = _int(baseline.get("baseline_analysis_queued"))
    scan.baseline_analysis_skipped = _int(baseline.get("baseline_analysis_skipped"))
    scan.changes_new = _int(changes.get("new"))
    scan.changes_modified = _int(changes.get("modified"))
    scan.changes_deleted = _int(changes.get("deleted"))
    scan.changes_renamed = _int(changes.get("renamed"))
    scan.hashed = _int(changes.get("hashed"))
    scan.metadata_skipped = _int(changes.get("metadata_skipped"))
    scan.platform_renames = _int(changes.get("platform_renames"))
    scan.errors = 0
    scan.error = None
    scan.result_json = {"baseline": baseline, "changes": changes}
    session.commit()


def fail_scan_session(session: Session, scan_id: int, error: str) -> None:
    """Mark a scan session as failed and store the error text."""
    scan = session.get(ScanSession, scan_id)
    if not scan:
        return
    now = datetime.utcnow()
    scan.status = "error"
    scan.updated_at = now
    scan.completed_at = now
    scan.errors = max(_int(scan.errors), 1)
    scan.error = error
    session.commit()


def serialize_scan_session(scan: ScanSession | None) -> dict[str, Any] | None:
    """Convert a scan row to API JSON."""
    if scan is None:
        return None
    return {
        "id": scan.id,
        "root_path": scan.root_path,
        "trigger": scan.trigger,
        "mode": scan.mode,
        "status": scan.status,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "updated_at": scan.updated_at.isoformat() if scan.updated_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "total_discovered": scan.total_discovered or 0,
        "baseline_new": scan.baseline_new or 0,
        "baseline_updated": scan.baseline_updated or 0,
        "baseline_reanalyzed": scan.baseline_reanalyzed or 0,
        "baseline_reanalyze_skipped": scan.baseline_reanalyze_skipped or 0,
        "baseline_analysis_checked": scan.baseline_analysis_checked or 0,
        "baseline_analysis_queued": scan.baseline_analysis_queued or 0,
        "baseline_analysis_skipped": scan.baseline_analysis_skipped or 0,
        "changes_new": scan.changes_new or 0,
        "changes_modified": scan.changes_modified or 0,
        "changes_deleted": scan.changes_deleted or 0,
        "changes_renamed": scan.changes_renamed or 0,
        "hashed": scan.hashed or 0,
        "metadata_skipped": scan.metadata_skipped or 0,
        "platform_renames": scan.platform_renames or 0,
        "errors": scan.errors or 0,
        "error": scan.error,
        "result": scan.result_json,
    }


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0
