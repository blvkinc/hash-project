"""
api.py — FastAPI backend for the File Integrity Monitor.

Serves the REST API and the static frontend.
On startup, initialises the DB, starts the real-time watcher,
and starts the background LLM analysis thread.
"""
import os
import sys
import threading
import logging
from datetime import datetime
from typing import List, Optional, Dict

from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import func, case, or_

# Ensure project root is importable when run as `python -m uvicorn core.api:app`
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.database import SessionLocal, init_db
from core.config import settings
from core.models import DirectoryNode, FileIdentity, FileRecord, FileLog, ScanSession
from core.scanner import scan_and_baseline, compare_and_log
from core.scan_sessions import (
    complete_scan_session,
    create_scan_session,
    fail_scan_session,
    mark_scan_running,
    serialize_scan_session,
)
from core.background_analysis import run_analysis_loop, dispatcher, update_monitor_state
from core.platform_paths import detect_os, get_paths_summary, get_noisy_dirs
from core.registry_watcher import RegistryWatcher, is_registry_supported
from core.services.ollama_config import configure_preferred_ollama_model
from core.services.system_monitor import (
    collect_system_monitor_paths,
    collect_system_registry_paths,
    handle_registry_change,
)
from core.services.watch_manager import WatchManager
from core.logging_config import configure_logging

# Logging (honours FIM_LOG_JSON / FIM_LOG_LEVEL env vars).
configure_logging()
logger = logging.getLogger(__name__)

# Initialise DB
init_db()

# FastAPI app
app = FastAPI(title="File Integrity Monitor", version="2.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_watch_manager = WatchManager()
_system_monitor_enabled = False
_system_monitored_paths: List[str] = []
_system_started_paths: List[str] = []
_system_registry_paths: List[str] = []
_registry_watcher: Optional[RegistryWatcher] = None
_scan_state_lock = threading.Lock()
_scan_state = {
    "active": False,
    "scan_session_id": None,
    "stage": "idle",
    "path": None,
    "processed": 0,
    "total": 0,
    "message": "Idle",
    "started_at": None,
    "updated_at": None,
    "completed_at": None,
    "result": None,
    "error": None,
    "scan_mode": None,
    "elapsed_seconds": 0,
    "files_per_second": 0,
    "bytes_processed": 0,
    "bytes_per_second": 0,
    "mb_per_second": 0,
    "hash_seconds": 0,
    "db_commit_seconds": 0,
    "commit_count": 0,
    "last_commit_seconds": 0,
    "errors": 0,
    "current_file": None,
    "hash_workers": 0,
}


def _create_persisted_scan(path: str, trigger: str, mode: str | None = None) -> int:
    session = SessionLocal()
    try:
        scan = create_scan_session(
            session=session,
            root_path=os.path.abspath(path),
            trigger=trigger,
            mode=mode or settings.baseline_capture_mode,
        )
        return scan.id
    finally:
        session.close()


def _mark_persisted_scan_running(scan_id: int) -> None:
    session = SessionLocal()
    try:
        mark_scan_running(session, scan_id)
    finally:
        session.close()


def _complete_persisted_scan(scan_id: int, baseline: dict, changes: dict) -> None:
    session = SessionLocal()
    try:
        complete_scan_session(session, scan_id, baseline, changes)
    finally:
        session.close()


def _fail_persisted_scan(scan_id: int, error: str) -> None:
    session = SessionLocal()
    try:
        fail_scan_session(session, scan_id, error)
    finally:
        session.close()


def _sync_monitor_state():
    update_monitor_state(_system_monitor_enabled, _watch_manager.active_paths())


def _set_scan_state(**updates):
    with _scan_state_lock:
        _scan_state.update(updates)
        _scan_state["updated_at"] = datetime.utcnow().isoformat()


def _scan_snapshot() -> dict:
    with _scan_state_lock:
        return dict(_scan_state)


def _progress_metrics(update: dict) -> dict:
    keys = (
        "scan_mode",
        "elapsed_seconds",
        "files_per_second",
        "bytes_processed",
        "bytes_per_second",
        "mb_per_second",
        "hash_seconds",
        "db_commit_seconds",
        "commit_count",
        "last_commit_seconds",
        "errors",
        "current_file",
        "hash_workers",
    )
    return {key: update.get(key) for key in keys if key in update}


def _empty_progress_metrics() -> dict:
    return {
        "scan_mode": None,
        "elapsed_seconds": 0,
        "files_per_second": 0,
        "bytes_processed": 0,
        "bytes_per_second": 0,
        "mb_per_second": 0,
        "hash_seconds": 0,
        "db_commit_seconds": 0,
        "commit_count": 0,
        "last_commit_seconds": 0,
        "errors": 0,
        "current_file": None,
        "hash_workers": 0,
    }


def _progress_callback(update: dict) -> None:
    stage = update.get("stage", "scan")
    processed = int(update.get("processed") or 0)
    total = int(update.get("total") or 0)
    percent = round((processed / total) * 100, 1) if total else 0
    label = (
        "Capturing hashes"
        if stage == "hash_baseline"
        else ("Building baseline" if stage == "baseline" else "Reconciling changes")
    )
    _set_scan_state(
        active=True,
        stage=stage,
        path=update.get("path"),
        processed=processed,
        total=total,
        percent=percent,
        message=f"{label}: {processed}/{total}",
        **_progress_metrics(update),
    )


def _empty_change_summary(reason: str) -> dict:
    return {
        "new": 0,
        "modified": 0,
        "deleted": 0,
        "renamed": 0,
        "hashed": 0,
        "metadata_skipped": 0,
        "platform_renames": 0,
        "skipped": True,
        "reason": reason,
    }


def _post_baseline_changes(path: str, baseline: dict, progress_callback) -> dict:
    if (baseline or {}).get("scan_mode") == "hash_first":
        return _empty_change_summary(
            "Skipped immediate reconciliation because hash-first baseline just captured current state."
        )
    return compare_and_log(path, progress_callback=progress_callback)


def _system_monitor_progress_callback(
    scan_id: int,
    root_path: str,
    path_index: int,
    total_paths: int,
):
    def callback(update: dict) -> None:
        stage = update.get("stage", "scan")
        processed = int(update.get("processed") or 0)
        total = int(update.get("total") or 0)
        percent = round((processed / total) * 100, 1) if total else 0
        label = (
            "Capturing hashes"
            if stage == "hash_baseline"
            else ("Building baseline" if stage == "baseline" else "Reconciling changes")
        )
        _set_scan_state(
            active=True,
            scan_session_id=scan_id,
            stage=f"system_{stage}",
            path=update.get("path") or root_path,
            processed=processed,
            total=total,
            percent=percent,
            message=(
                f"System monitor scan {path_index}/{total_paths} - "
                f"{label}: {processed}/{total}"
            ),
            **_progress_metrics(update),
        )

    return callback


def _run_system_monitor_directory_scan(paths: List[str]) -> None:
    """Build visible baseline state for System Monitor filesystem paths."""
    total_paths = len(paths)
    if total_paths == 0:
        return

    started_at = datetime.utcnow().isoformat()
    _set_scan_state(
        active=True,
        scan_session_id=None,
        stage="system_queued",
        path=None,
        processed=0,
        total=total_paths,
        percent=0,
        message=f"System monitor directory scan queued for {total_paths} path(s)",
        started_at=started_at,
        completed_at=None,
        result=None,
        error=None,
        **_empty_progress_metrics(),
    )

    completed = []
    errors = []
    last_scan_id = None

    for index, path in enumerate(paths, start=1):
        scan_id = None
        try:
            scan_id = _create_persisted_scan(path, trigger="system_monitor")
            last_scan_id = scan_id
            _mark_persisted_scan_running(scan_id)
            _set_scan_state(
                active=True,
                scan_session_id=scan_id,
                stage="system_starting",
                path=path,
                processed=0,
                total=0,
                percent=0,
                message=f"System monitor scan {index}/{total_paths}: {path}",
                error=None,
            )

            progress = _system_monitor_progress_callback(
                scan_id=scan_id,
                root_path=path,
                path_index=index,
                total_paths=total_paths,
            )
            logger.info(f"System monitor visible baseline scan: {path}")
            baseline = scan_and_baseline(path, progress_callback=progress)
            changes = _post_baseline_changes(path, baseline, progress)
            _complete_persisted_scan(scan_id, baseline, changes)
            completed.append({
                "path": path,
                "scan_session_id": scan_id,
                "baseline": baseline,
                "changes": changes,
            })
            logger.info(
                f"System monitor visible scan complete for {path}: "
                f"{baseline}, changes={changes}"
            )
        except Exception as exc:
            logger.exception(f"System monitor visible scan failed for {path}: {exc}")
            if scan_id is not None:
                _fail_persisted_scan(scan_id, str(exc))
            errors.append({"path": path, "error": str(exc)})

    completed_at = datetime.utcnow().isoformat()
    failed_count = len(errors)
    completed_count = len(completed)
    stage = "error" if failed_count and not completed_count else "complete"
    message = (
        f"System monitor directory scan complete: {completed_count}/{total_paths} path(s)"
        if not failed_count
        else (
            f"System monitor directory scan completed with {failed_count} "
            f"failure(s): {completed_count}/{total_paths} path(s)"
        )
    )
    _set_scan_state(
        active=False,
        scan_session_id=last_scan_id,
        stage=stage,
        path=None,
        processed=completed_count,
        total=total_paths,
        percent=100 if total_paths else 0,
        message=message,
        completed_at=completed_at,
        result={
            "system_monitor": {
                "total_paths": total_paths,
                "completed_paths": completed_count,
                "failed_paths": failed_count,
                "scans": completed,
                "errors": errors,
            }
        },
        error="; ".join(e["error"] for e in errors) if stage == "error" else None,
        **(_progress_metrics(completed[-1]["baseline"]) if completed else _empty_progress_metrics()),
    )


# ─── Startup ────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    # Configure preferred local model at startup.
    try:
        configure_preferred_ollama_model()
    except Exception as exc:
        logger.warning(f"Unable to auto-configure Ollama model: {exc}")

    # Start background analysis thread
    t = threading.Thread(target=run_analysis_loop, args=(5.0,), daemon=True)
    t.start()
    logger.info("Background analysis thread started.")

    # Start notification dispatch thread (Stage C)
    nt = threading.Thread(target=dispatcher.dispatch_loop, args=(10.0,), daemon=True)
    nt.start()
    logger.info("Notification dispatch thread started.")


# ─── Request / Response Models ──────────────────────────────

class ScanRequest(BaseModel):
    path: str
    reanalyze_existing: bool = False
    reanalyze_limit: int = 200


class WatchRequest(BaseModel):
    path: str
    reanalyze_existing: bool = False
    reanalyze_limit: int = 200


class SystemMonitorToggleRequest(BaseModel):
    enabled: bool


class StatsResponse(BaseModel):
    hash_mode: str
    hash_algorithm: str
    security_hash_algorithm: str
    hash_chunk_size: int
    blake3_max_threads: str
    baseline_hash_workers: int
    monitored_files: int
    total_events: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    pending: int
    pending_analysis: int = 0
    recorded_events: int = 0
    analyzed_events: int = 0
    ignored_events: int = 0
    error_events: int = 0
    watcher_active: bool


# ─── Helpers ────────────────────────────────────────────────


def _build_analysis_payload(analysis_json) -> Optional[dict]:
    """Extract the full structured analysis from stored JSON."""
    if not analysis_json or not isinstance(analysis_json, dict):
        return None
    selected = analysis_json
    has_primary_analysis = any(
        bool(analysis_json.get(key))
        for key in (
            'reasoning',
            'threat_type',
            'threat_classification',
            'analysis_source',
            'findings',
            'recommended_actions',
            'mitre_attack',
            'iocs',
        )
    )
    if not has_primary_analysis:
        baseline_triage = analysis_json.get('baseline_triage')
        if isinstance(baseline_triage, dict):
            selected = dict(baseline_triage)
            selected['baseline_context'] = True
            selected.setdefault('event_context', {
                key: analysis_json.get(key)
                for key in ('diff', 'metadata', 'file_category', 'is_baseline', 'reanalyze')
                if key in analysis_json
            })
        else:
            return None
    return {
        "reasoning":             selected.get('reasoning', ''),
        "risk_score":            selected.get('risk_score'),
        "priority":              selected.get('priority', ''),
        "threat_type":           selected.get('threat_type', ''),
        "threat_classification": selected.get('threat_classification', ''),
        "is_malicious":          selected.get('is_malicious', False),
        "mitre_attack":          selected.get('mitre_attack', []),
        "iocs":                  selected.get('iocs', []),
        "confidence":            selected.get('confidence', ''),
        "analysis_source":       selected.get('analysis_source', ''),
        "context_notes":         selected.get('context_notes', []),
        "findings":              selected.get('findings', []),
        "change_summary":        selected.get('change_summary', ''),
        "recommended_actions":   selected.get('recommended_actions', []),
        "baseline_context":      selected.get('baseline_context', False),
        "analysis_deferred":     selected.get('analysis_deferred', False),
    }


# ─── Routes ─────────────────────────────────────────────────

@app.get("/api/stats")
def get_stats():
    session = SessionLocal()
    try:
        file_count = session.query(FileRecord).count()
        total_events = session.query(FileLog).count()

        # Count by priority
        priority_counts = (
            session.query(FileLog.priority, func.count(FileLog.id))
            .group_by(FileLog.priority)
            .all()
        )
        counts = {p: c for p, c in priority_counts}
        status_counts = dict(
            session.query(FileLog.status, func.count(FileLog.id))
            .group_by(FileLog.status)
            .all()
        )

        return {
            "hash_mode": settings.hash_mode,
            "hash_algorithm": settings.hash_algorithm,
            "security_hash_algorithm": settings.security_hash_algorithm,
            "hash_chunk_size": settings.hash_chunk_size,
            "blake3_max_threads": settings.blake3_max_threads,
            "baseline_hash_workers": settings.baseline_hash_workers,
            "monitored_files": file_count,
            "total_events": total_events,
            "critical": counts.get('critical', 0),
            "high": counts.get('high', 0),
            "medium": counts.get('medium', 0),
            "low": counts.get('low', 0),
            "info": counts.get('info', 0),
            "pending": counts.get('pending', 0),
            "pending_analysis": status_counts.get('pending', 0),
            "recorded_events": status_counts.get('recorded', 0),
            "analyzed_events": status_counts.get('analyzed', 0),
            "ignored_events": status_counts.get('ignored', 0),
            "error_events": status_counts.get('error', 0),
            "watcher_active": _watch_manager.is_active(),
        }
    finally:
        session.close()


@app.get("/api/logs")
def get_logs(limit: int = 100, priority: Optional[str] = None):
    session = SessionLocal()
    try:
        query = session.query(FileLog).order_by(FileLog.timestamp.desc())

        if priority and priority != 'all':
            query = query.filter(FileLog.priority == priority)

        logs = query.limit(limit).all()

        result = []
        for log in logs:
            analysis_payload = _build_analysis_payload(log.analysis_json)
            result.append({
                "id": log.id,
                "file_id": log.file_id,
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                "path": log.path,
                "event_type": log.event_type,
                "old_hash": log.old_hash,
                "new_hash": log.new_hash,
                "details": log.details,
                "priority": log.priority,
                "risk_score": (
                    log.risk_score if log.risk_score is not None
                    else (analysis_payload or {}).get('risk_score')
                ),
                "status": log.status,
                "analysis": analysis_payload,
            })
        return result
    finally:
        session.close()


@app.get("/api/files")
def get_files(limit: int = 200):
    session = SessionLocal()
    try:
        files = session.query(FileRecord).order_by(FileRecord.path).limit(limit).all()
        return [{
            "id": f.id,
            "file_id": f.file_id,
            "path": f.path,
            "hash": f.hash,
            "last_seen": f.last_seen.isoformat() if f.last_seen else None,
            "is_baseline": f.is_baseline,
            "size": f.size,
        } for f in files]
    finally:
        session.close()


@app.get("/api/tree")
def get_tree(parent_id: Optional[int] = None, limit: int = 500):
    """Lazy-load one directory-tree level plus files for the selected node."""
    safe_limit = max(1, min(int(limit or 500), 2000))
    session = SessionLocal()
    try:
        if parent_id is None:
            dir_query = session.query(DirectoryNode).filter(DirectoryNode.parent_id.is_(None))
            files = []
            parent = None
        else:
            parent = session.query(DirectoryNode).filter(DirectoryNode.id == parent_id).first()
            if parent is None:
                raise HTTPException(status_code=404, detail="Directory node not found")
            dir_query = session.query(DirectoryNode).filter(DirectoryNode.parent_id == parent_id)
            file_rows = (
                session.query(FileRecord)
                .filter(FileRecord.directory_id == parent_id)
                .order_by(FileRecord.name, FileRecord.path)
                .limit(safe_limit)
                .all()
            )
            files = [{
                "id": f.id,
                "file_id": f.file_id,
                "name": f.name or os.path.basename(f.path),
                "path": f.path,
                "hash": f.hash,
                "size": f.size,
                "mtime": f.mtime,
                "is_baseline": f.is_baseline,
                "last_seen": f.last_seen.isoformat() if f.last_seen else None,
            } for f in file_rows]

        directories = (
            dir_query
            .order_by(DirectoryNode.name, DirectoryNode.full_path)
            .limit(safe_limit)
            .all()
        )

        return {
            "parent": ({
                "id": parent.id,
                "name": parent.name,
                "full_path": parent.full_path,
                "depth": parent.depth,
            } if parent else None),
            "directories": [{
                "id": d.id,
                "parent_id": d.parent_id,
                "name": d.name,
                "full_path": d.full_path,
                "depth": d.depth,
                "last_seen": d.last_seen.isoformat() if d.last_seen else None,
            } for d in directories],
            "files": files,
            "limit": safe_limit,
        }
    finally:
        session.close()


@app.post("/api/scan")
def trigger_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    if not os.path.exists(request.path):
        raise HTTPException(status_code=400, detail="Path does not exist")

    reanalyze_existing = bool(request.reanalyze_existing)
    reanalyze_limit = max(1, min(int(request.reanalyze_limit or 200), 2000))
    scan_session_id = _create_persisted_scan(request.path, trigger="manual_scan")
    _set_scan_state(
        active=True,
        scan_session_id=scan_session_id,
        stage="queued",
        path=request.path,
        processed=0,
        total=0,
        percent=0,
        message="Scan queued",
        started_at=datetime.utcnow().isoformat(),
        completed_at=None,
        result=None,
        error=None,
        **_empty_progress_metrics(),
    )

    def do_scan(path: str, scan_id: int):
        try:
            _mark_persisted_scan_running(scan_id)
            logger.info(f"Starting baseline scan: {path}")
            result = scan_and_baseline(
                path,
                reanalyze_existing=reanalyze_existing,
                reanalyze_limit=reanalyze_limit,
                progress_callback=_progress_callback,
            )
            logger.info(f"Baseline scan complete: {result}")
            # Hash-first baseline already represents current on-disk state.
            changes = _post_baseline_changes(path, result, _progress_callback)
            logger.info(f"Change detection complete: {changes}")
            _complete_persisted_scan(scan_id, result, changes)
            _set_scan_state(
                active=False,
                scan_session_id=scan_id,
                stage="complete",
                message="Scan complete",
                completed_at=datetime.utcnow().isoformat(),
                result={"baseline": result, "changes": changes},
                error=None,
                **_progress_metrics(result),
            )
        except Exception as exc:
            logger.exception(f"Scan failed for {path}: {exc}")
            _fail_persisted_scan(scan_id, str(exc))
            _set_scan_state(
                active=False,
                scan_session_id=scan_id,
                stage="error",
                message="Scan failed",
                completed_at=datetime.utcnow().isoformat(),
                error=str(exc),
            )

    background_tasks.add_task(do_scan, request.path, scan_session_id)
    return {
        "message": f"Scan started for {request.path}",
        "status": "started",
        "scan_session_id": scan_session_id,
    }


@app.get("/api/scan/status")
def scan_status():
    return _scan_snapshot()


@app.get("/api/scans")
def get_scan_sessions(limit: int = 20):
    safe_limit = max(1, min(int(limit or 20), 200))
    session = SessionLocal()
    try:
        scans = (
            session.query(ScanSession)
            .order_by(ScanSession.started_at.desc(), ScanSession.id.desc())
            .limit(safe_limit)
            .all()
        )
        return [serialize_scan_session(scan) for scan in scans]
    finally:
        session.close()


@app.get("/api/scans/latest")
def get_latest_scan_session():
    session = SessionLocal()
    try:
        scan = (
            session.query(ScanSession)
            .order_by(ScanSession.started_at.desc(), ScanSession.id.desc())
            .first()
        )
        return serialize_scan_session(scan)
    finally:
        session.close()


@app.post("/api/initialize-watch")
def initialize_and_watch(request: WatchRequest, background_tasks: BackgroundTasks):
    """
    One-step onboarding:
      1) build baseline hashes + initial AI context
      2) start live watcher for immediate change tracking
    """
    if not os.path.exists(request.path):
        raise HTTPException(status_code=400, detail="Path does not exist")

    reanalyze_existing = bool(request.reanalyze_existing)
    reanalyze_limit = max(1, min(int(request.reanalyze_limit or 200), 2000))
    scan_session_id = _create_persisted_scan(request.path, trigger="initialize_watch")
    _set_scan_state(
        active=True,
        scan_session_id=scan_session_id,
        stage="queued",
        path=request.path,
        processed=0,
        total=0,
        percent=0,
        message="Initialization queued",
        started_at=datetime.utcnow().isoformat(),
        completed_at=None,
        result=None,
        error=None,
    )

    def initialize_context(path: str, scan_id: int):
        try:
            _mark_persisted_scan_running(scan_id)
            logger.info(f"Initializing baseline and context state: {path}")
            result = scan_and_baseline(
                path,
                reanalyze_existing=reanalyze_existing,
                reanalyze_limit=reanalyze_limit,
                progress_callback=_progress_callback,
            )
            logger.info(f"Initial baseline/context complete: {result}")
            changes = _post_baseline_changes(path, result, _progress_callback)
            logger.info(f"Post-baseline reconciliation complete: {changes}")
            _complete_persisted_scan(scan_id, result, changes)
            _set_scan_state(
                active=False,
                scan_session_id=scan_id,
                stage="complete",
                message="Initialization complete",
                completed_at=datetime.utcnow().isoformat(),
                result={"baseline": result, "changes": changes},
                error=None,
                **_progress_metrics(result),
            )
        except Exception as exc:
            logger.exception(f"Initialization failed for {path}: {exc}")
            _fail_persisted_scan(scan_id, str(exc))
            _set_scan_state(
                active=False,
                scan_session_id=scan_id,
                stage="error",
                message="Initialization failed",
                completed_at=datetime.utcnow().isoformat(),
                error=str(exc),
            )

    background_tasks.add_task(initialize_context, request.path, scan_session_id)
    try:
        started = _watch_manager.start(request.path)
    except Exception as exc:
        logger.warning(f"Failed to start watcher on {request.path}: {exc}")
        raise HTTPException(status_code=500, detail=f"Failed to start watcher on {request.path}: {exc}")
    _sync_monitor_state()

    return {
        "message": (f"Initialization started and watcher active on {request.path}"
                    if started else f"Initialization started; watcher already active on {request.path}"),
        "status": "active",
        "watch_started": started,
        "initialization": "running",
        "scan_session_id": scan_session_id,
    }


@app.post("/api/watch/start")
def start_watcher(request: WatchRequest):
    if not os.path.exists(request.path):
        raise HTTPException(status_code=400, detail="Path does not exist")

    try:
        started = _watch_manager.start(request.path)
    except Exception as exc:
        logger.warning(f"Failed to start watcher on {request.path}: {exc}")
        raise HTTPException(status_code=500, detail=f"Failed to start watcher on {request.path}: {exc}")
    _sync_monitor_state()

    if started:
        return {"message": f"Watcher started on {request.path}", "status": "active"}
    return {"message": f"Watcher already active on {request.path}", "status": "active"}


@app.post("/api/watch/stop")
def stop_watcher(path: Optional[str] = None):
    global _system_monitor_enabled, _system_monitored_paths, _system_started_paths
    global _system_registry_paths, _registry_watcher

    abs_path = os.path.abspath(path) if path else None
    stopped = _watch_manager.stop(abs_path)
    registry_stopped = False

    if abs_path and abs_path in _system_monitored_paths:
        _system_monitored_paths = [p for p in _system_monitored_paths if p != abs_path]
    if abs_path and abs_path in _system_started_paths:
        _system_started_paths = [p for p in _system_started_paths if p != abs_path]

    if abs_path is None:
        if _registry_watcher and _registry_watcher.is_running:
            _registry_watcher.stop()
            registry_stopped = True
        _registry_watcher = None

        _system_monitor_enabled = False
        _system_monitored_paths = []
        _system_started_paths = []
        _system_registry_paths = []
    elif not _system_monitored_paths and not _system_registry_paths:
        _system_monitor_enabled = False

    total_stopped = stopped + (1 if registry_stopped else 0)
    _sync_monitor_state()

    if total_stopped > 0:
        if abs_path:
            return {"message": f"Watcher stopped for {abs_path}", "status": "stopped"}
        return {"message": f"Stopped {total_stopped} watcher(s)", "status": "stopped"}

    if abs_path:
        return {"message": f"No active watcher for {abs_path}", "status": "inactive"}
    return {"message": "No active watchers", "status": "inactive"}


@app.get("/api/watch/status")
def watcher_status():
    paths = _watch_manager.active_paths()
    registry_active = bool(_registry_watcher and _registry_watcher.is_running)
    return {
        "active": len(paths) > 0 or registry_active,
        "count": len(paths),
        "path": paths[0] if paths else None,
        "paths": paths,
        "registry_active": registry_active,
    }


@app.get("/api/system-monitor/status")
def system_monitor_status():
    return {
        "enabled": _system_monitor_enabled,
        "paths": list(_system_monitored_paths),
        "count": len(_system_monitored_paths),
        "registry_paths": list(_system_registry_paths),
        "registry_count": len(_system_registry_paths),
        "registry_supported": is_registry_supported(),
    }


@app.post("/api/system-monitor/toggle")
def toggle_system_monitor(request: SystemMonitorToggleRequest, background_tasks: BackgroundTasks):
    global _system_monitor_enabled, _system_monitored_paths, _system_started_paths
    global _system_registry_paths, _registry_watcher

    if request.enabled:
        paths = collect_system_monitor_paths()
        registry_paths = collect_system_registry_paths() if is_registry_supported() else []

        started_paths: List[str] = []
        failed_paths: List[Dict[str, str]] = []
        for path in paths:
            try:
                if _watch_manager.start(path):
                    started_paths.append(path)
            except Exception as exc:
                logger.warning(f"System monitor watcher failed for {path}: {exc}")
                failed_paths.append({"path": path, "error": str(exc)})

        if _registry_watcher and _registry_watcher.is_running:
            _registry_watcher.stop()
            _registry_watcher = None

        active_registry_paths: List[str] = []
        if registry_paths:
            candidate = RegistryWatcher(
                paths=registry_paths,
                on_change=handle_registry_change,
                poll_interval=5.0,
            )
            try:
                if candidate.start():
                    _registry_watcher = candidate
                    active_registry_paths = registry_paths
            except Exception as exc:
                logger.warning(f"Registry watcher failed to start: {exc}")
                failed_paths.append({"path": "registry", "error": str(exc)})

        if not started_paths and not active_registry_paths:
            _system_monitor_enabled = False
            _system_monitored_paths = []
            _system_started_paths = []
            _system_registry_paths = []

            detail = "System monitoring could not start on this host."
            if failed_paths:
                first = failed_paths[0]
                detail = f"{detail} First failure: {first.get('path')}: {first.get('error')}"
            raise HTTPException(status_code=500, detail=detail)

        _system_monitor_enabled = True
        _system_monitored_paths = started_paths
        _system_started_paths = started_paths
        _system_registry_paths = active_registry_paths
        _sync_monitor_state()

        if started_paths:
            _set_scan_state(
                active=True,
                scan_session_id=None,
                stage="system_queued",
                path=None,
                processed=0,
                total=len(started_paths),
                percent=0,
                message=(
                    "System monitor directory scan queued "
                    f"for {len(started_paths)} path(s)"
                ),
                started_at=datetime.utcnow().isoformat(),
                completed_at=None,
                result=None,
                error=None,
                **_empty_progress_metrics(),
            )
            background_tasks.add_task(
                _run_system_monitor_directory_scan,
                list(started_paths),
            )

        return {
            "enabled": True,
            "paths": started_paths,
            "count": len(started_paths),
            "started_paths": started_paths,
            "started_count": len(started_paths),
            "failed_paths": failed_paths,
            "failed_count": len(failed_paths),
            "registry_paths": active_registry_paths,
            "registry_count": len(active_registry_paths),
            "scan_started": bool(started_paths),
            "scan_path_count": len(started_paths),
            "message": (
                f"System monitoring enabled for {len(started_paths)} filesystem watcher(s) "
                f"and {len(active_registry_paths)} registry path(s). "
                f"{len(failed_paths)} path(s) failed to start. "
                f"Directory scan {'queued' if started_paths else 'not started'}."
            ),
        }

    # Disable system monitoring (only stop watchers started by this feature).
    for path in list(_system_started_paths):
        _watch_manager.stop(path)

    if _registry_watcher and _registry_watcher.is_running:
        _registry_watcher.stop()
    _registry_watcher = None

    _system_monitor_enabled = False
    _system_monitored_paths = []
    _system_started_paths = []
    _system_registry_paths = []
    _sync_monitor_state()

    return {
        "enabled": False,
        "paths": [],
        "count": 0,
        "registry_paths": [],
        "registry_count": 0,
        "message": "System monitoring disabled",
    }

@app.get("/api/files/timeline")
def get_file_timeline(path: Optional[str] = None, file_id: Optional[int] = None):
    """Return the full chronological change history for a specific file."""
    if file_id is None and not path:
        raise HTTPException(status_code=400, detail="path or file_id is required")

    session = SessionLocal()
    try:
        record = None
        identity = None
        if file_id is not None:
            record = session.query(FileRecord).filter(FileRecord.file_id == file_id).first()
            identity = session.get(FileIdentity, file_id)
        if record is None and path:
            record = session.query(FileRecord).filter(FileRecord.path == path).first()
            if record and record.file_id is not None:
                file_id = record.file_id
                identity = session.get(FileIdentity, file_id)
        if identity is None and file_id is not None:
            identity = session.get(FileIdentity, file_id)

        baseline = None
        if record:
            baseline = {
                "file_id": record.file_id,
                "path": record.path,
                "hash": record.hash,
                "hash_algorithm": record.hash_algorithm,
                "fast_hash": record.fast_hash,
                "security_hash": record.security_hash,
                "security_hash_algorithm": record.security_hash_algorithm,
                "is_baseline": record.is_baseline,
                "size": record.size,
                "last_seen": record.last_seen.isoformat() if record.last_seen else None,
            }
        elif identity:
            baseline = {
                "file_id": identity.id,
                "path": identity.current_path,
                "hash": identity.current_hash,
                "fast_hash": identity.current_fast_hash,
                "security_hash": identity.current_security_hash,
                "is_baseline": False,
                "size": identity.size,
                "last_seen": identity.updated_at.isoformat() if identity.updated_at else None,
            }

        query = session.query(FileLog)
        if file_id is not None and path:
            query = query.filter(or_(FileLog.file_id == file_id, FileLog.path == path))
        elif file_id is not None:
            query = query.filter(FileLog.file_id == file_id)
        else:
            query = query.filter(FileLog.path == path)
        logs = query.order_by(FileLog.timestamp.asc()).all()

        if not logs and path and file_id is not None:
            logs = (
                session.query(FileLog)
                .filter(FileLog.path == path)
                .order_by(FileLog.timestamp.asc())
                .all()
            )

        events = []
        for log in logs:
            analysis_payload = _build_analysis_payload(log.analysis_json)
            events.append({
                "id": log.id,
                "file_id": log.file_id,
                "path": log.path,
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                "event_type": log.event_type,
                "old_hash": log.old_hash,
                "new_hash": log.new_hash,
                "details": log.details,
                "priority": log.priority,
                "risk_score": (
                    log.risk_score if log.risk_score is not None
                    else (analysis_payload or {}).get('risk_score')
                ),
                "status": log.status,
                "analysis": analysis_payload,
            })

        return {"file_id": file_id, "baseline": baseline, "events": events}
    finally:
        session.close()


@app.get("/api/baseline")
def get_baseline():
    """Return all monitored file records with their AI analysis and change stats."""
    session = SessionLocal()
    try:
        records = (
            session.query(FileRecord)
            .order_by(FileRecord.path)
            .all()
        )

        result = []
        for rec in records:
            log_scope = session.query(FileLog)
            if rec.file_id is not None:
                log_scope = log_scope.filter(
                    or_(FileLog.file_id == rec.file_id, FileLog.path == rec.path)
                )
            else:
                log_scope = log_scope.filter(FileLog.path == rec.path)

            # Get the initial 'new' log entry for this file (baseline scan event)
            initial_log = (
                log_scope
                .filter(FileLog.event_type == 'new')
                .order_by(FileLog.timestamp.asc())
                .first()
            )

            # Count total changes for this file
            change_count = log_scope.count()

            # Get the highest priority event for this file
            highest_priority_log = (
                log_scope
                .order_by(
                    # Order by severity: critical > high > medium > low > info > pending
                    case(
                        (FileLog.priority == 'critical', 0),
                        (FileLog.priority == 'high', 1),
                        (FileLog.priority == 'medium', 2),
                        (FileLog.priority == 'low', 3),
                        (FileLog.priority == 'info', 4),
                        else_=5
                    )
                )
                .first()
            )
            initial_analysis_payload = (
                _build_analysis_payload(initial_log.analysis_json)
                if initial_log else None
            )

            result.append({
                "id": rec.id,
                "file_id": rec.file_id,
                "path": rec.path,
                "hash": rec.hash,
                "hash_algorithm": rec.hash_algorithm,
                "fast_hash": rec.fast_hash,
                "security_hash": rec.security_hash,
                "security_hash_algorithm": rec.security_hash_algorithm,
                "size": rec.size,
                "last_seen": rec.last_seen.isoformat() if rec.last_seen else None,
                "is_baseline": rec.is_baseline,
                "change_count": change_count,
                "highest_priority": highest_priority_log.priority if highest_priority_log else 'info',
                "initial_analysis": (
                    initial_analysis_payload.get('reasoning')
                    if initial_analysis_payload else None
                ),
            })

        return result
    finally:
        session.close()


@app.get("/api/platform")
def get_platform_info():
    """Return detected OS and recommended default monitoring paths."""
    current_os = detect_os()
    return {
        "os": current_os,
        "default_paths": get_paths_summary(target_os=current_os),
        "noisy_dirs": get_noisy_dirs(target_os=current_os),
    }


# ─── Notification Endpoints ─────────────────────────────────

@app.get("/api/notifications/config")
def get_notification_config():
    """Return the current notification configuration."""
    return dispatcher.get_config()


@app.post("/api/notifications/config")
def update_notification_config(config: dict):
    """Update notification configuration (email, batching, escalation)."""
    dispatcher.update_config(config)
    return {"message": "Notification config updated", "config": dispatcher.get_config()}


@app.get("/api/notifications/history")
def get_notification_history(limit: int = 50):
    """Return recent notification dispatch history."""
    return dispatcher.get_history(limit=limit)


# ─── Serve Frontend ────────────────────────────────────────

web_dir = os.path.join(os.path.dirname(__file__), '..', 'web')
if os.path.exists(web_dir):
    app.mount("/", StaticFiles(directory=web_dir, html=True), name="static")
else:
    logger.warning("'web' directory not found. Frontend will not be served.")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)



























