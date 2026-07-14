"""
Background processing for pending FileLog events.

The worker applies registry context, tier-aware prefiltering, content analysis,
MemPalace enrichment, and notification dispatch for queued file changes.
"""
import time
import os
import logging
import difflib
import threading
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import case, or_
from .config import settings
from .database import SessionLocal
from .models import FileLog, FileRecord
from .hasher import calculate_security_file_hash
from .file_content import read_text_snippet
from .analysis_cache import (
    build_analysis_cache_meta,
    get_cached_analysis,
    store_analysis_cache,
)
from .llm_analyzer import analyze_file_change
from .platform_paths import get_tier_for_path
from .notification_dispatcher import NotificationDispatcher
from .services.registry_analyzer import (
    analysis_from_registry_signal,
    apply_registry_floor,
    prepare_registry_analysis,
    run_mempalace_context_analysis,
)

logger = logging.getLogger(__name__)

# Shared by the analysis worker and the notification API.
dispatcher = NotificationDispatcher()

_UNREADABLE_SENTINELS = {'', 'Binary/Unreadable', 'File deleted'}

_SYSTEM_MONITOR_ENABLED = False
_ACTIVE_WATCH_PATHS: set[str] = set()
_BACKLOG_THRESHOLD = settings.analysis_backlog_threshold
_DEFAULT_BATCH_SIZE = settings.analysis_batch_size
_COALESCE_WINDOW_SECONDS = settings.analysis_coalesce_window_seconds
_PENDING_HARD_CAP = settings.analysis_pending_hard_cap
_DEMOTE_BATCH_SIZE = settings.analysis_low_priority_demote_batch
_DEMOTE_RISK_THRESHOLD = settings.analysis_low_priority_demote_risk_threshold


def _ensure_security_hash(session: Session, log: FileLog, event_context: dict) -> None:
    """Populate BLAKE3 security hash for analyzed on-disk files in hybrid mode."""
    if settings.hash_mode != "hybrid" or log.event_type == "deleted":
        return
    if not log.path or not os.path.exists(log.path):
        return

    record = None
    if log.file_id is not None:
        record = session.query(FileRecord).filter(FileRecord.file_id == log.file_id).first()
    if record is None:
        record = session.query(FileRecord).filter(FileRecord.path == log.path).first()

    hashes = event_context.setdefault("hashes", {})
    hashes.setdefault("mode", settings.hash_mode)
    hashes.setdefault("comparison_algorithm", settings.hash_algorithm)
    hashes.setdefault("comparison_hash", log.new_hash or log.old_hash)
    hashes.setdefault("security_algorithm", settings.security_hash_algorithm)

    if record is not None and record.security_hash:
        hashes["security_hash"] = record.security_hash
        hashes["security_hash_pending"] = False
        return

    try:
        security_hash = calculate_security_file_hash(log.path)
    except (PermissionError, OSError) as exc:
        hashes["security_hash_error"] = str(exc)
        hashes["security_hash_pending"] = True
        return

    hashes["security_hash"] = security_hash
    hashes["security_hash_pending"] = False
    if record is not None:
        record.security_hash = security_hash
        record.security_hash_algorithm = settings.security_hash_algorithm
_last_backlog_notice = 0.0


def update_monitor_state(system_enabled: bool, active_paths: list[str] | None):
    """Update live monitor state so background analysis can suppress stale system events."""
    global _SYSTEM_MONITOR_ENABLED, _ACTIVE_WATCH_PATHS
    _SYSTEM_MONITOR_ENABLED = bool(system_enabled)
    _ACTIVE_WATCH_PATHS = {
        os.path.abspath(p) for p in (active_paths or []) if p
    }


def _is_under_active_watch(path: str) -> bool:
    """True if the path is within an actively watched root."""
    try:
        norm = os.path.normcase(os.path.abspath(os.path.normpath(path)))
    except Exception:
        return False
    for root in _ACTIVE_WATCH_PATHS:
        try:
            normalized_root = os.path.normcase(os.path.abspath(os.path.normpath(root)))
            if os.path.commonpath([norm, normalized_root]) == normalized_root:
                return True
        except (OSError, ValueError):
            continue
    return False


def _is_readable_snippet(snippet: str | None) -> bool:
    """True when snippet has readable content suitable for context analysis."""
    return bool(snippet and snippet not in _UNREADABLE_SENTINELS)


def _is_baseline_log(log: FileLog) -> bool:
    """Detect baseline initialization logs."""
    data = log.analysis_json if isinstance(log.analysis_json, dict) else {}
    event_context = data.get('event_context') if isinstance(data.get('event_context'), dict) else {}
    if event_context.get('is_baseline'):
        return True
    if data.get('is_baseline'):
        return True
    details = log.details or ''
    return 'Baseline scan' in details


def _extract_event_context(analysis_json) -> dict:
    """
    Return the raw event context stored with a FileLog.

    Older rows stored the file snippet directly at analysis_json["diff"].
    New analyzed rows keep the raw event under analysis_json["event_context"]
    so future modified events can build an actual previous/current diff.
    """
    if not isinstance(analysis_json, dict):
        return {}

    existing = analysis_json.get('event_context')
    if isinstance(existing, dict):
        return dict(existing)

    context = {}
    for key in (
        'diff', 'metadata', 'file_category', 'is_baseline', 'reanalyze',
        'analysis_deferred', 'registry', 'registry_signal',
    ):
        if key in analysis_json:
            context[key] = analysis_json[key]
    return context


def _read_deferred_snippet(file_path: str, max_chars: int = 5000) -> str:
    """Read a bounded text snippet for hash-first deferred analysis."""
    return read_text_snippet(file_path, max_chars)


def _latest_previous_snippet(
    session: Session,
    path: str,
    before_id: int | None,
    file_id: int | None = None,
) -> str | None:
    """Fetch the latest readable snippet for a file before the current log row."""
    q = session.query(FileLog)
    if file_id is not None:
        q = q.filter(or_(FileLog.file_id == file_id, FileLog.path == path))
    else:
        q = q.filter(FileLog.path == path)
    if before_id is not None:
        q = q.filter(FileLog.id < before_id)
    previous_logs = q.order_by(FileLog.id.desc()).limit(20).all()

    for prev in previous_logs:
        if isinstance(prev.analysis_json, dict) and prev.analysis_json.get('coalesced'):
            continue
        event_context = _extract_event_context(prev.analysis_json)
        prev_snippet = event_context.get('diff')
        if isinstance(prev_snippet, str) and _is_readable_snippet(prev_snippet):
            return prev_snippet
    return None


def _event_identity_key(log: FileLog) -> str:
    """Stable grouping key for duplicate pending events."""
    if log.file_id is not None:
        return f"file:{log.file_id}"
    try:
        normalized = os.path.normcase(os.path.abspath(os.path.normpath(log.path)))
    except Exception:
        normalized = log.path or ""
    return f"path:{normalized}"


def coalesce_pending_events(
    session: Session,
    window_seconds: int | None = None,
    scan_limit: int = 5000,
) -> int:
    """
    Collapse duplicate rapid pending modifications for the same logical file.

    Older rows are retained for audit history, but marked ignored so the
    expensive analyzer only reviews the latest pending content.
    """
    window = _COALESCE_WINDOW_SECONDS if window_seconds is None else int(window_seconds)
    if window <= 0:
        return 0

    rows = (
        session.query(FileLog)
        .filter(FileLog.status == 'pending', FileLog.event_type == 'modified')
        .order_by(FileLog.id.asc())
        .limit(max(1, int(scan_limit or 5000)))
        .all()
    )
    if len(rows) < 2:
        return 0

    groups: dict[str, list[FileLog]] = {}
    for row in rows:
        groups.setdefault(_event_identity_key(row), []).append(row)

    coalesced = 0
    now = datetime.utcnow()
    for group_rows in groups.values():
        if len(group_rows) < 2:
            continue

        ordered = sorted(group_rows, key=lambda item: (item.timestamp or now, item.id))
        window_group: list[FileLog] = []

        for row in ordered:
            if not window_group:
                window_group = [row]
                continue

            start_ts = window_group[0].timestamp or row.timestamp or now
            row_ts = row.timestamp or now
            if abs((row_ts - start_ts).total_seconds()) <= window:
                window_group.append(row)
            else:
                coalesced += _coalesce_window(window_group, now)
                window_group = [row]

        coalesced += _coalesce_window(window_group, now)

    if coalesced:
        session.commit()
        logger.info(f"Coalesced {coalesced} duplicate pending file event(s).")
    return coalesced


def _coalesce_window(rows: list[FileLog], now: datetime) -> int:
    if len(rows) < 2:
        return 0

    keep = max(rows, key=lambda item: (item.timestamp or now, item.id))
    coalesced = 0
    for row in rows:
        if row.id == keep.id:
            continue

        payload = dict(row.analysis_json or {}) if isinstance(row.analysis_json, dict) else {}
        payload['coalesced'] = True
        payload['coalesced_into'] = keep.id
        payload['coalesce_reason'] = 'Superseded by a newer pending modified event for the same file.'

        row.status = 'ignored'
        row.priority = 'info'
        row.risk_score = 1
        row.analyzed_at = now
        row.analysis_json = payload
        row.details = f"{row.details or 'Modified file event'} [Coalesced into event #{keep.id}]"
        coalesced += 1
    return coalesced


def enforce_pending_hard_cap(
    session: Session,
    pending_total: int | None = None,
    hard_cap: int | None = None,
    demote_limit: int | None = None,
) -> int:
    """
    Record low-priority pending events when the queue exceeds the hard cap.

    This preserves audit rows and event context, but avoids spending model
    capacity on obvious low-risk backlog such as Tier 4 cache/log/temp churn.
    """
    cap = _PENDING_HARD_CAP if hard_cap is None else int(hard_cap)
    if cap <= 0:
        return 0

    total = (
        session.query(FileLog).filter(FileLog.status == 'pending').count()
        if pending_total is None else int(pending_total)
    )
    excess = total - cap
    if excess <= 0:
        return 0

    limit = min(
        max(1, excess),
        max(1, _DEMOTE_BATCH_SIZE if demote_limit is None else int(demote_limit)),
    )
    scan_limit = min(max(limit * 4, limit), max(total, limit))
    rows = (
        session.query(FileLog)
        .filter(FileLog.status == 'pending')
        .order_by(FileLog.timestamp.asc(), FileLog.id.asc())
        .limit(scan_limit)
        .all()
    )

    demoted = 0
    now = datetime.utcnow()
    for log in rows:
        if demoted >= limit:
            break

        analysis = _low_priority_demote_analysis(log)
        if analysis is None:
            continue

        event_context = _extract_event_context(log.analysis_json)
        snippet = event_context.get('diff', '')
        if not isinstance(snippet, str):
            snippet = ''
        change_summary = _build_change_summary(log.event_type, snippet, None)
        log.analysis_json = _attach_event_context(
            analysis,
            event_context,
            snippet,
            None,
            change_summary,
        )
        log.risk_score = analysis.get('risk_score', 1)
        log.priority = analysis.get('priority', 'info')
        log.status = 'recorded'
        log.analyzed_at = now
        log.details = f"{log.details or 'Low-priority event'} [Recorded by backlog cap]"
        demoted += 1

    if demoted:
        session.commit()
        logger.info(
            f"Recorded {demoted} low-priority pending event(s) to keep "
            f"analysis backlog under cap {cap}."
        )
    return demoted


def _low_priority_demote_analysis(log: FileLog) -> dict | None:
    """Return an analysis payload when a pending row is safe to record."""
    if log.event_type not in ('new', 'modified'):
        return None

    tier = get_tier_for_path(log.path)
    if tier in (1, 2):
        return None

    event_context = _extract_event_context(log.analysis_json)
    metadata = event_context.get('metadata') or {}
    if not isinstance(metadata, dict):
        metadata = {"_raw_metadata": metadata}
    metadata.setdefault('is_baseline', _is_baseline_log(log))
    event_context['metadata'] = metadata

    is_baseline = bool(metadata.get('is_baseline') or _is_baseline_log(log))
    snippet = event_context.get('diff', '')
    readable = _is_readable_snippet(snippet if isinstance(snippet, str) else '')

    # Only auto-record low-value domains. Unknown readable content still gets
    # analyzed because its path alone is not enough to classify risk.
    if tier != 4 and not is_baseline:
        return None

    if not readable:
        return _backlog_recorded_analysis(
            log,
            reason=(
                "No readable content was available and the event belongs to "
                "a low-priority baseline or Tier 4 path."
            ),
            tier=tier,
        )

    from .llm_analyzer import _fallback_analysis

    heuristic = _fallback_analysis(
        log.path,
        log.event_type,
        snippet,
        metadata=metadata,
    )
    score = int(heuristic.get('risk_score') or 0)
    if score > _DEMOTE_RISK_THRESHOLD:
        return None

    analysis = dict(heuristic)
    analysis['backlog_demoted'] = True
    analysis['backlog_cap_reason'] = (
        'Low-risk heuristic result recorded without full model analysis '
        'because the pending queue exceeded the configured hard cap.'
    )
    analysis['reasoning'] = (
        f"{analysis['backlog_cap_reason']} {analysis.get('reasoning', '')}"
    ).strip()
    analysis.setdefault('priority', 'info')
    analysis.setdefault('risk_score', score)
    return analysis


def _backlog_recorded_analysis(log: FileLog, reason: str, tier: int | None) -> dict:
    return {
        'risk_score': 1,
        'priority': 'info',
        'is_malicious': False,
        'threat_type': 'benign',
        'threat_classification': 'Backlog Recorded',
        'confidence': 'low',
        'reasoning': (
            f"Low-priority event recorded without full model analysis because "
            f"the pending queue exceeded the configured hard cap. {reason}"
        ),
        'analysis_source': 'backlog_cap',
        'tier': tier,
        'backlog_demoted': True,
        'backlog_cap_reason': reason,
        'context_notes': [
            'Recorded to prevent low-priority backlog from starving higher-value analysis.'
        ],
        'findings': [],
        'recommended_actions': [
            'Review only if this low-priority path was unexpected.'
        ],
    }


def _build_change_summary(
    event_type: str,
    current_snippet: str,
    previous_snippet: str | None,
) -> dict:
    """Build structured before/after counts for audit and notifications."""
    if event_type != 'modified' or not previous_snippet or not _is_readable_snippet(current_snippet):
        return {
            'previous_snippet_available': False,
            'added_lines': 0,
            'removed_lines': 0,
        }

    unified = list(difflib.unified_diff(
        previous_snippet.splitlines(),
        current_snippet.splitlines(),
        fromfile='before',
        tofile='after',
        n=3,
        lineterm='',
    ))
    added = [ln[1:] for ln in unified if ln.startswith('+') and not ln.startswith('+++')]
    removed = [ln[1:] for ln in unified if ln.startswith('-') and not ln.startswith('---')]
    return {
        'previous_snippet_available': True,
        'added_lines': len(added),
        'removed_lines': len(removed),
        'added_preview': added[:10],
        'removed_preview': removed[:10],
    }


def _build_contextual_payload(
    path: str,
    event_type: str,
    current_snippet: str,
    previous_snippet: str | None,
) -> str:
    """
    Build a context-rich payload for modified files so the model sees
    previous state, current state, and the actual diff.
    """
    if not _is_readable_snippet(current_snippet):
        return current_snippet
    if event_type != 'modified' or not previous_snippet:
        return current_snippet

    before_lines = previous_snippet.splitlines()
    after_lines = current_snippet.splitlines()
    unified = list(difflib.unified_diff(
        before_lines, after_lines,
        fromfile='before', tofile='after', n=3, lineterm=''
    ))
    if not unified:
        return current_snippet

    added = sum(1 for ln in unified if ln.startswith('+') and not ln.startswith('+++'))
    removed = sum(1 for ln in unified if ln.startswith('-') and not ln.startswith('---'))
    diff_preview = '\n'.join(unified[:120])

    return (
        f"[Context-Aware Change Analysis]\n"
        f"File: {path}\n"
        f"Event: {event_type}\n"
        f"Added lines: {added}\n"
        f"Removed lines: {removed}\n\n"
        f"=== PREVIOUS CONTENT (snippet) ===\n"
        f"{previous_snippet[:1200]}\n\n"
        f"=== CURRENT CONTENT (snippet) ===\n"
        f"{current_snippet[:1200]}\n\n"
        f"=== UNIFIED DIFF (before -> after) ===\n"
        f"{diff_preview}\n"
    )


def _attach_event_context(
    analysis: dict,
    event_context: dict,
    contextual_payload: str,
    previous_snippet: str | None,
    change_summary: dict,
) -> dict:
    """Preserve raw file-change context alongside the final verdict."""
    merged = dict(analysis or {})
    context = dict(event_context or {})

    if contextual_payload and contextual_payload != context.get('diff'):
        context['contextual_payload'] = contextual_payload[:8000]
    context['previous_snippet_available'] = bool(previous_snippet)
    context['change_summary'] = change_summary

    merged['event_context'] = context
    merged.setdefault('change_summary', change_summary)
    return merged


def _apply_tier_prefilter(log: FileLog, registry_signal: dict | None = None) -> dict | None:
    """
    Apply static prefiltering using file-criticality tiers.

    Returns a pre-built analysis dict for Tier 1 and Tier 4 files,
    bypassing provider calls. Returns None for Tier 2/3 events.
    """
    if registry_signal and registry_signal.get("tier") == 1:
        analysis = analysis_from_registry_signal(registry_signal)
        if analysis:
            analysis['prefiltered'] = True
            return analysis

    tier = (
        registry_signal.get("tier")
        if registry_signal and registry_signal.get("tier") is not None
        else get_tier_for_path(log.path)
    )

    if tier == 4:
        # Low-tier files are usually temp files, caches, or log appends.
        return {
            'risk_score': 1,
            'priority': 'info',
            'is_malicious': False,
            'reasoning': (
                f'Tier 4 file (temp/cache/log); silently logged. '
                f'Path: {log.path}'
            ),
            'tier': 4,
            'prefiltered': True,
        }

    if tier == 1:
        if _is_baseline_log(log):
            # Baseline initialization should be content-driven to avoid noisy alerts
            return None
        # Critical files include system binaries, auth files, and startup points.
        return {
            'risk_score': 9,
            'priority': 'critical',
            'is_malicious': False,       # not necessarily malicious, but critical
            'reasoning': (
                f'Tier 1 critical file changed outside tracked update; '
                f'immediate alert required. Path: {log.path}'
            ),
            'tier': 1,
            'prefiltered': True,
        }

    # Tier 2, Tier 3, and unclassified paths need content analysis.
    return None


def process_pending_analysis(batch_size: int | None = None):
    """
    Fetch pending FileLogs and run the prioritisation pipeline on them.
    Priority order: new > modified > deleted > other.
    """
    session: Session = SessionLocal()
    try:
        effective_batch = batch_size or _DEFAULT_BATCH_SIZE
        coalesce_pending_events(session)
        pending_total = session.query(FileLog).filter_by(status='pending').count()
        if enforce_pending_hard_cap(session, pending_total=pending_total):
            pending_total = session.query(FileLog).filter_by(status='pending').count()
        force_heuristic = False
        if _BACKLOG_THRESHOLD > 0:
            force_heuristic = pending_total >= _BACKLOG_THRESHOLD
            global _last_backlog_notice
            now = time.time()
            if force_heuristic and (now - _last_backlog_notice) > 60:
                logger.info(
                    f"Backlog detected ({pending_total} pending). "
                    f"Using heuristic-only for baseline events to drain queue."
                )
                _last_backlog_notice = now

        # Priority ordering for processing
        priority_order = case(
            (FileLog.event_type == 'new', 1),
            (FileLog.event_type == 'modified', 2),
            (FileLog.event_type == 'deleted', 3),
            else_=4,
        )

        pending = (
            session.query(FileLog)
            .filter_by(status='pending')
            .order_by(priority_order)
            .limit(effective_batch * 6)
            .all()
        )

        if not pending:
            return 0

        def _event_priority(log: FileLog):
            event_pri = {'new': 1, 'modified': 2, 'deleted': 3}.get(log.event_type, 4)
            watch_pri = 0 if _is_under_active_watch(log.path) else 1
            return (watch_pri, event_pri, log.id)

        pending = sorted(pending, key=_event_priority)[:effective_batch]

        processed = 0
        investigations_used = 0
        for log in pending:
            try:
                stored = log.analysis_json if isinstance(log.analysis_json, dict) else {}
                event_context = _extract_event_context(stored)
                snippet = event_context.get('diff', '')
                if event_context.get('analysis_deferred') and not _is_readable_snippet(snippet):
                    snippet = _read_deferred_snippet(log.path)
                    event_context['diff'] = snippet
                metadata = event_context.get('metadata') or {}
                if not isinstance(metadata, dict):
                    metadata = {"_raw_metadata": metadata}
                metadata.setdefault('is_baseline', _is_baseline_log(log))
                event_context['metadata'] = metadata
                event_context.setdefault('is_baseline', bool(metadata.get('is_baseline')))
                _ensure_security_hash(session, log, event_context)
                registry_payload, registry_signal = prepare_registry_analysis(
                    session, log, event_context
                )
                if registry_payload:
                    metadata["registry"] = registry_payload

                previous_snippet = None
                contextual_diff = snippet
                if _is_readable_snippet(snippet):
                    previous_snippet = _latest_previous_snippet(
                        session, log.path, log.id, log.file_id
                    )
                    contextual_diff = _build_contextual_payload(
                        log.path,
                        log.event_type,
                        snippet,
                        previous_snippet,
                    )
                change_summary = _build_change_summary(log.event_type, snippet, previous_snippet)
                cache_meta = build_analysis_cache_meta(
                    path=log.path,
                    event_type=log.event_type,
                    new_hash=log.new_hash,
                    old_hash=log.old_hash,
                    contextual_payload=contextual_diff,
                    metadata=metadata,
                )

                tier = (
                    (registry_payload or {}).get("tier")
                    or get_tier_for_path(log.path)
                )
                if tier in (1, 2) and not _SYSTEM_MONITOR_ENABLED and not _is_under_active_watch(log.path):
                    analysis = {
                        'risk_score': 1,
                        'priority': 'info',
                        'is_malicious': False,
                        'reasoning': (
                            'System monitoring is disabled; '
                            'system-tier event suppressed until explicitly monitored.'
                        ),
                        'tier': tier,
                        'suppressed': True,
                    }
                    log.risk_score = 1
                    log.priority = 'info'
                    log.analysis_json = _attach_event_context(
                        analysis, event_context, contextual_diff, previous_snippet, change_summary
                    )
                    log.status = 'ignored'
                    log.analyzed_at = datetime.utcnow()
                    session.commit()
                    processed += 1
                    continue

                # Tier prefilter
                prefilter_result = _apply_tier_prefilter(log, registry_signal)

                if prefilter_result is not None:
                    # Tier 1 and Tier 4 still get a content check when readable.
                    # The tier pre-filter is path-based only. If the file
                    # content contains threats, override with full analysis.
                    if _is_readable_snippet(snippet):
                        from .llm_analyzer import _fallback_analysis, _summarize_content

                        # The heuristic is cheap enough to decide whether provider review is useful.
                        heuristic_result = _fallback_analysis(
                            log.path, log.event_type, contextual_diff, metadata=metadata
                        )
                        heuristic_score = int(heuristic_result.get('risk_score') or 0)
                        prefilter_score = int(prefilter_result.get('risk_score') or 0)

                        if heuristic_score >= 7:
                            if force_heuristic and not _is_under_active_watch(log.path):
                                # Backlog mode avoids remote/slow calls, but a high
                                # content score must still override a low-risk path tier.
                                analysis = heuristic_result
                                analysis['tier_override'] = True
                                analysis['original_tier'] = prefilter_result.get('tier')
                                analysis['reasoning'] = (
                                    f"Readable file content overrode Tier {prefilter_result.get('tier')} "
                                    f"path-only prefilter during backlog heuristic mode. "
                                    f"{analysis.get('reasoning', '')}"
                                )
                            else:
                                logger.info(
                                    "Tier %s prefilter overridden by heuristic score %s; "
                                    "requesting provider review for %s",
                                    prefilter_result.get('tier'),
                                    heuristic_score,
                                    log.path,
                                )

                                analysis = analyze_file_change(
                                    file_path=log.path,
                                    change_type=log.event_type,
                                    diff=contextual_diff,
                                    metadata=metadata,
                                )

                                # The provider sees the contextual diff and may confirm or downgrade
                                # a pattern-only heuristic result.
                                analysis['tier_override'] = True
                                analysis['original_tier'] = prefilter_result.get('tier')

                                logger.info(
                                    "Provider review completed for %s: risk=%s, priority=%s",
                                    log.path,
                                    analysis.get('risk_score', 'N/A'),
                                    analysis.get('priority', 'N/A'),
                                )
                        elif heuristic_score > prefilter_score:
                            # A watched low-tier path can still contain risky content.
                            # Keep the content verdict instead of flattening it to a
                            # silent Tier 4 log.
                            analysis = heuristic_result
                            analysis['tier_override'] = True
                            analysis['original_tier'] = prefilter_result.get('tier')
                            analysis['reasoning'] = (
                                f"Readable file content overrode Tier {prefilter_result.get('tier')} "
                                f"path-only prefilter. {analysis.get('reasoning', '')}"
                            )
                        else:
                            # Content is safe; use the tier pre-filter result.
                            analysis = prefilter_result
                            content_desc = _summarize_content(snippet, log.path)
                            if content_desc:
                                analysis['reasoning'] += f' {content_desc}'
                    else:
                        # No readable content; use tier result as-is.
                        analysis = prefilter_result

                    if not analysis.get('tier_override'):
                        logger.info(
                            f"Pre-filtered (Tier {analysis.get('tier', prefilter_result.get('tier'))}): "
                            f"{log.path} -> {analysis['priority']}"
                        )
                else:
                    # Provider or heuristic analysis
                    cached_analysis = get_cached_analysis(session, cache_meta)
                    if cached_analysis is not None:
                        analysis = cached_analysis
                        logger.info(f"Analysis cache hit: {log.path} ({log.event_type})")
                    else:
                        logger.info(f"Analyzing (LLM/heuristic): {log.path} ({log.event_type})")
                        if force_heuristic and (metadata.get('is_baseline') or not _is_under_active_watch(log.path)):
                            from .llm_analyzer import _fallback_analysis
                            analysis = _fallback_analysis(
                                log.path, log.event_type, contextual_diff, metadata=metadata
                            )
                        else:
                            analysis = analyze_file_change(
                                file_path=log.path,
                                change_type=log.event_type,
                                diff=contextual_diff,
                                metadata=metadata,
                            )
                        store_analysis_cache(session, cache_meta, analysis)

                analysis = apply_registry_floor(analysis, registry_signal)
                analysis = run_mempalace_context_analysis(
                    log=log,
                    event_context=event_context,
                    content_payload=contextual_diff,
                    content_analysis=analysis,
                    registry_signal=registry_signal,
                    previous_snippet_available=bool(previous_snippet),
                    change_summary=change_summary,
                    performance_context={
                        "pending_depth": pending_total,
                        "investigations_used": investigations_used,
                        "max_per_batch": getattr(settings, "agent_investigation_max_per_batch", 8),
                        "backlog_threshold": getattr(settings, "agent_investigation_backlog_threshold", 500),
                        "backlog_critical_only": getattr(settings, "agent_investigation_backlog_critical_only", True),
                    },
                )
                analysis["baseline_context"] = bool(
                    metadata.get("is_baseline") or _is_baseline_log(log)
                )
                if (analysis.get("agent_investigation") or {}).get("ran"):
                    investigations_used += 1
                analysis = _attach_event_context(
                    analysis, event_context, contextual_diff, previous_snippet, change_summary
                )

                # Update log with results
                log.risk_score = analysis.get('risk_score')
                log.priority = analysis.get('priority', 'info')
                log.analysis_json = analysis
                log.status = 'analyzed'
                log.analyzed_at = datetime.utcnow()

                session.commit()
                processed += 1
                logger.info(f"Analyzed {log.path} -> priority={log.priority}, risk={log.risk_score}")

                # Notification dispatch
                registry_for_notification = (
                    analysis.get('registry')
                    or analysis.get('event_context', {}).get('registry')
                    or {}
                )
                dispatcher.enqueue({
                    'event_id': log.id,
                    'timestamp': log.timestamp.isoformat() if log.timestamp else None,
                    'path': log.path,
                    'event_type': log.event_type,
                    'priority': log.priority,
                    'risk_score': log.risk_score,
                    'reasoning': analysis.get('reasoning', ''),
                    'threat_type': analysis.get('threat_type', ''),
                    'threat_classification': analysis.get('threat_classification', ''),
                    'confidence': analysis.get('confidence', ''),
                    'analysis_source': analysis.get('analysis_source', ''),
                    'mitre_attack': analysis.get('mitre_attack', []),
                    'iocs': analysis.get('iocs', []),
                    'change_summary': analysis.get('change_summary', {}),
                    'recommended_actions': analysis.get('recommended_actions', []),
                    'registry': registry_for_notification,
                    'mem_palace': analysis.get('mem_palace'),
                    'agent_notification': analysis.get('agent_notification'),
                    'agent_investigation': analysis.get('agent_investigation'),
                    'semantic_role': analysis.get('semantic_role') or registry_for_notification.get('semantic_role'),
                    'asset_tier': analysis.get('tier') or registry_for_notification.get('tier'),
                })

            except Exception as e:
                logger.error(f"Error analyzing {log.path}: {e}")
                log.status = 'error'
                log.details = (log.details or "") + f" [Analysis error: {str(e)}]"
                session.commit()

        return processed

    except Exception as e:
        logger.error(f"Background analysis error: {e}")
        session.rollback()
        return 0
    finally:
        session.close()


def run_analysis_loop(
    interval: float = 5.0,
    stop_event: threading.Event | None = None,
) -> None:
    """Process pending analyses until the application asks the worker to stop."""
    logger.info("Background analysis loop started.")
    while stop_event is None or not stop_event.is_set():
        try:
            processed = process_pending_analysis()
            if processed:
                logger.info(f"Processed {processed} pending events.")
        except Exception:
            logger.exception("Analysis worker failed while processing the queue.")
        if stop_event is None:
            time.sleep(interval)
        else:
            stop_event.wait(interval)
