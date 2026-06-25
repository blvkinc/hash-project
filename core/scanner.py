"""Directory scanning and baseline hashing."""
import os
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime
from typing import Callable
from sqlalchemy.orm import Session
from .config import settings
from .database import SessionLocal
from .models import FileIdentity, FileRecord, FileLog
from .hasher import calculate_file_hash, get_file_metadata
from .file_identity import (
    attach_identity_to_record,
    find_identity_by_platform_id,
    mark_identity_inactive,
)
from .path_tree import assign_file_location
from .platform_paths import get_noisy_dirs, get_file_category
from .services.file_registry import (
    mark_registry_inactive,
    registry_context as build_registry_context,
    upsert_registry_entry,
)

EXCLUDED_DIRS = {
    '.git', '__pycache__', 'node_modules', '.venv', 'env', 'venv',
    '$RECYCLE.BIN', 'System Volume Information', '.idea', '.vscode',
}

for _noisy in get_noisy_dirs():
    EXCLUDED_DIRS.add(os.path.basename(_noisy))

EXCLUDED_FILES = {
    'file_monitor.db', 'file_monitor.db-journal', 'file_monitor.db-wal',
}

BASELINE_TRIAGE_EXTENSIONS = {
    '', '.bat', '.bash', '.c', '.cmd', '.conf', '.config', '.cpp', '.cs',
    '.env', '.go', '.h', '.ini', '.java', '.js', '.json', '.jsx', '.key',
    '.lua', '.md', '.pem', '.php', '.pl', '.ps1', '.py', '.rb', '.rs',
    '.sh', '.sql', '.ts', '.tsx', '.txt', '.xml', '.yaml', '.yml',
}

DEFERRED_BASELINE_ANALYSIS_EXTENSIONS = {
    '.bat', '.bash', '.cmd', '.conf', '.config', '.crt', '.env', '.ini',
    '.js', '.json', '.key', '.pem', '.php', '.pl', '.ps1', '.py', '.rb',
    '.sh', '.sql', '.ts', '.xml', '.yaml', '.yml',
}


def _walk_directory(root_path: str) -> list[str]:
    """Walk directory tree and return list of absolute file paths."""
    abs_root = os.path.abspath(root_path)
    file_list = []

    for dirpath, dirnames, filenames in os.walk(abs_root):
        # Skip excluded directories (in-place modification)
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]

        for filename in filenames:
            if filename in EXCLUDED_FILES:
                continue
            file_list.append(os.path.abspath(os.path.join(dirpath, filename)))

    return file_list


def _emit_progress(
    callback: Callable[[dict], None] | None,
    stage: str,
    processed: int,
    total: int,
    path: str,
    extra: dict | None = None,
) -> None:
    """Report scan progress without coupling scanner to the API."""
    if callback is None:
        return
    if processed not in (0, total) and processed % 100 != 0:
        return
    payload = {
        "stage": stage,
        "processed": processed,
        "total": total,
        "path": path,
    }
    if extra:
        payload.update(extra)
    callback(payload)


def _hash_baseline_metrics(
    *,
    started_at: float,
    processed: int,
    hashed_bytes: int,
    hash_seconds: float,
    db_seconds: float,
    commit_count: int,
    last_commit_seconds: float,
    errors: int,
    current_file: str | None = None,
    hash_workers: int = 1,
) -> dict:
    """Build live throughput metrics for the hash-first baseline pass."""
    elapsed = max(time.perf_counter() - started_at, 0.000001)
    return {
        "scan_mode": "hash_first",
        "elapsed_seconds": round(elapsed, 3),
        "files_per_second": round(processed / elapsed, 2) if processed else 0,
        "bytes_processed": int(hashed_bytes),
        "bytes_per_second": round(hashed_bytes / elapsed, 2) if hashed_bytes else 0,
        "mb_per_second": round((hashed_bytes / (1024 * 1024)) / elapsed, 2) if hashed_bytes else 0,
        "hash_seconds": round(hash_seconds, 3),
        "db_commit_seconds": round(db_seconds, 3),
        "commit_count": int(commit_count),
        "last_commit_seconds": round(last_commit_seconds, 3),
        "errors": int(errors),
        "current_file": current_file,
        "hash_workers": int(hash_workers),
    }


def _hash_file_for_baseline(file_path: str) -> dict:
    """Read metadata and calculate a content hash outside the DB session."""
    started = time.perf_counter()
    try:
        metadata = get_file_metadata(file_path)
        if not metadata:
            return {
                "path": file_path,
                "metadata": None,
                "hash": None,
                "hash_algorithm": settings.hash_algorithm,
                "fast_hash": None,
                "security_hash": None,
                "bytes": 0,
                "hash_seconds": time.perf_counter() - started,
                "error": "metadata_unavailable",
            }
        file_hash = calculate_file_hash(file_path)
        return {
            "path": file_path,
            "metadata": metadata,
            "hash": file_hash,
            "hash_algorithm": settings.hash_algorithm,
            "fast_hash": file_hash,
            "security_hash": None,
            "bytes": int(metadata.get('size') or 0),
            "hash_seconds": time.perf_counter() - started,
            "error": None,
        }
    except (PermissionError, OSError) as exc:
        return {
            "path": file_path,
            "metadata": None,
            "hash": None,
            "hash_algorithm": settings.hash_algorithm,
            "fast_hash": None,
            "security_hash": None,
            "bytes": 0,
            "hash_seconds": time.perf_counter() - started,
            "error": str(exc),
        }


def _iter_baseline_hash_results(file_list: list[str], worker_count: int):
    """Yield hash results from a bounded parallel worker pool."""
    worker_count = max(1, int(worker_count or 1))
    if worker_count == 1:
        for file_path in file_list:
            yield _hash_file_for_baseline(file_path)
        return

    max_pending = max(worker_count * 2, worker_count)
    file_iter = iter(file_list)
    pending = {}

    with ThreadPoolExecutor(
        max_workers=worker_count,
        thread_name_prefix="baseline-hash",
    ) as executor:
        def fill_pending() -> None:
            while len(pending) < max_pending:
                try:
                    file_path = next(file_iter)
                except StopIteration:
                    return
                pending[executor.submit(_hash_file_for_baseline, file_path)] = file_path

        fill_pending()
        while pending:
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                pending.pop(future, None)
                yield future.result()
            fill_pending()


def _scan_registry_context(
    session: Session,
    path: str,
    metadata: dict | None,
    file_hash: str | None,
    file_id: int | None = None,
    fast_hash: str | None = None,
    security_hash: str | None = None,
    hash_algorithm: str | None = None,
    is_baseline: bool = False,
    active: bool = True,
) -> dict | None:
    """Upsert registry state and return JSON-safe context for event payloads."""
    entry = upsert_registry_entry(
        session=session,
        path=path,
        metadata=metadata,
        file_hash=file_hash,
        fast_hash=fast_hash or file_hash,
        security_hash=security_hash,
        file_id=file_id,
        hash_algorithm=hash_algorithm,
        security_hash_algorithm=settings.security_hash_algorithm,
        is_baseline=is_baseline,
        active=active,
    )
    return build_registry_context(entry)


def scan_and_baseline(
    root_path: str,
    reanalyze_existing: bool = False,
    reanalyze_limit: int = 200,
    progress_callback: Callable[[dict], None] | None = None,
) -> dict:
    """
    Initial scan: hash every file and store as baseline in DB.
    Also creates FileLog events so content is analysed for threats.
    Returns summary dict with counts.
    """
    capture_mode = (settings.baseline_capture_mode or "hash_first").lower()
    if capture_mode in ("hash_first", "hash-first", "fast", "snapshot"):
        return _scan_hash_first_baseline(
            root_path=root_path,
            reanalyze_existing=reanalyze_existing,
            reanalyze_limit=reanalyze_limit,
            progress_callback=progress_callback,
        )

    session: Session = SessionLocal()
    file_list = _walk_directory(root_path)
    new_count = 0
    existing_count = 0
    reanalyzed_count = 0
    reanalyze_skipped = 0
    baseline_analysis_checked = 0
    baseline_analysis_queued = 0
    baseline_analysis_skipped = 0

    try:
        _emit_progress(progress_callback, "baseline", 0, len(file_list), root_path)
        # Build a lookup of existing records
        existing = {r.path: r for r in session.query(FileRecord).all()}
        directory_cache = {}

        for idx, file_path in enumerate(file_list, start=1):
            try:
                file_hash = calculate_file_hash(file_path)
                metadata = get_file_metadata(file_path)
            except (PermissionError, OSError):
                _emit_progress(progress_callback, "baseline", idx, len(file_list), root_path)
                continue

            if file_path in existing:
                # Update existing record
                record = existing[file_path]
                record.hash = file_hash
                record.last_seen = datetime.utcnow()
                record.mtime = metadata['mtime'] if metadata else None
                record.size = metadata['size'] if metadata else None
                attach_identity_to_record(
                    session, record, file_path, metadata, file_hash,
                    fast_hash=file_hash,
                    directory_cache=directory_cache,
                )
                registry = _scan_registry_context(
                    session=session,
                    path=file_path,
                    metadata=metadata,
                    file_hash=file_hash,
                    file_id=record.file_id,
                    fast_hash=file_hash,
                    is_baseline=True,
                )
                existing_count += 1
                if reanalyze_existing:
                    if reanalyzed_count < reanalyze_limit:
                        snippet = _read_snippet(file_path)
                        file_cat = get_file_category(file_path)
                        context = _baseline_event_context(
                            snippet=snippet,
                            metadata=metadata,
                            file_category=file_cat,
                            registry_context=registry,
                            reanalyze=True,
                        )
                        session.add(FileLog(
                            file_id=record.file_id,
                            path=file_path,
                            event_type='new',
                            old_hash=None,
                            new_hash=file_hash,
                            details="Baseline reanalysis - context refresh",
                            status='pending',
                            analysis_json={"event_context": context},
                        ))
                        reanalyzed_count += 1
                    else:
                        reanalyze_skipped += 1
            else:
                # New file  -  add baseline record
                record = FileRecord(
                    path=file_path,
                    hash=file_hash,
                    is_baseline=True,
                    mtime=metadata['mtime'] if metadata else None,
                    size=metadata['size'] if metadata else None,
                )
                attach_identity_to_record(
                    session, record, file_path, metadata, file_hash,
                    fast_hash=file_hash,
                    directory_cache=directory_cache,
                )
                registry = _scan_registry_context(
                    session=session,
                    path=file_path,
                    metadata=metadata,
                    file_hash=file_hash,
                    file_id=record.file_id,
                    fast_hash=file_hash,
                    is_baseline=True,
                )
                session.add(record)

                file_cat = get_file_category(file_path)
                baseline_triage = None
                should_queue_baseline = False
                snippet = ""
                skipped_reason = None
                if _should_triage_baseline_file(file_path, metadata):
                    snippet = _read_snippet(file_path)
                    baseline_triage = _baseline_triage_analysis(file_path, snippet, metadata, file_cat)
                    should_queue_baseline = _should_queue_baseline_analysis(file_path, metadata, baseline_triage)
                    baseline_analysis_checked += 1
                    if should_queue_baseline:
                        baseline_analysis_queued += 1
                    else:
                        baseline_analysis_skipped += 1
                else:
                    skipped_reason = _baseline_triage_skip_reason(file_path, metadata)
                    baseline_analysis_skipped += 1
                analysis_payload = _baseline_analysis_payload(
                    file_path=file_path,
                    snippet=snippet,
                    metadata=metadata,
                    file_category=file_cat,
                    baseline_triage=baseline_triage,
                    skipped_reason=skipped_reason,
                    registry_context=registry,
                )
                session.add(FileLog(
                    file_id=record.file_id,
                    path=file_path,
                    event_type='new',
                    old_hash=None,
                    new_hash=file_hash,
                    details="Baseline scan - initial content analysis",
                    status='pending' if should_queue_baseline else 'recorded',
                    priority='pending' if should_queue_baseline else 'info',
                    risk_score=analysis_payload.get("risk_score"),
                    analysis_json=analysis_payload,
                ))
                new_count += 1
            _emit_progress(progress_callback, "baseline", idx, len(file_list), root_path)

        session.commit()
        return {
            "total_files": len(file_list),
            "new_baselined": new_count,
            "updated": existing_count,
            "reanalyzed": reanalyzed_count,
            "reanalyze_skipped": reanalyze_skipped,
            "baseline_analysis_checked": baseline_analysis_checked,
            "baseline_analysis_queued": baseline_analysis_queued,
            "baseline_analysis_skipped": baseline_analysis_skipped,
        }

    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def _scan_hash_first_baseline(
    root_path: str,
    reanalyze_existing: bool = False,
    reanalyze_limit: int = 200,
    progress_callback: Callable[[dict], None] | None = None,
) -> dict:
    """
    Fast baseline mode: capture the integrity ledger first.

    This pass hashes files and stores path/hash/mtime/size with a minimal audit
    event. Content snippets and heuristic/LLM analysis are deferred to the
    background queue for selected high-value text/config/script files.
    """
    session: Session = SessionLocal()
    file_list = _walk_directory(root_path)
    new_count = 0
    existing_count = 0
    reanalyzed_count = 0
    reanalyze_skipped = 0
    baseline_analysis_checked = 0
    baseline_analysis_queued = 0
    baseline_analysis_skipped = 0
    errors = 0
    batch_size = max(1, int(settings.baseline_commit_batch_size or 1000))
    hash_workers = max(1, int(settings.baseline_hash_workers or 1))
    deferred_limit = max(0, int(settings.baseline_deferred_analysis_limit or 0))
    started_at = time.perf_counter()
    hashed_bytes = 0
    hash_seconds = 0.0
    db_seconds = 0.0
    commit_count = 0
    last_commit_seconds = 0.0

    try:
        _emit_progress(
            progress_callback,
            "hash_baseline",
            0,
            len(file_list),
            root_path,
            _hash_baseline_metrics(
                started_at=started_at,
                processed=0,
                hashed_bytes=hashed_bytes,
                hash_seconds=hash_seconds,
                db_seconds=db_seconds,
                commit_count=commit_count,
                last_commit_seconds=last_commit_seconds,
                errors=errors,
                hash_workers=hash_workers,
            ),
        )
        existing = {r.path: r for r in session.query(FileRecord).all()}
        directory_cache = {}

        for idx, hash_result in enumerate(
            _iter_baseline_hash_results(file_list, hash_workers),
            start=1,
        ):
            file_path = hash_result["path"]
            metadata = hash_result.get("metadata")
            file_hash = hash_result.get("hash")
            hash_algorithm = hash_result.get("hash_algorithm") or settings.hash_algorithm
            fast_hash = hash_result.get("fast_hash") or file_hash
            security_hash = hash_result.get("security_hash")
            hash_seconds = max(time.perf_counter() - started_at - db_seconds, 0.0)

            if hash_result.get("error") or not metadata or not file_hash:
                errors += 1
                _emit_progress(
                    progress_callback,
                    "hash_baseline",
                    idx,
                    len(file_list),
                    root_path,
                    _hash_baseline_metrics(
                        started_at=started_at,
                        processed=idx,
                        hashed_bytes=hashed_bytes,
                        hash_seconds=hash_seconds,
                        db_seconds=db_seconds,
                        commit_count=commit_count,
                        last_commit_seconds=last_commit_seconds,
                        errors=errors,
                        current_file=file_path,
                        hash_workers=hash_workers,
                    ),
                )
                continue
            hashed_bytes += int(hash_result.get("bytes") or 0)

            record = existing.get(file_path)
            if record is not None:
                record.hash = file_hash
                record.last_seen = datetime.utcnow()
                record.mtime = metadata.get('mtime')
                record.size = metadata.get('size')
                record.name = os.path.basename(file_path)
                record.is_baseline = True
                record.hash_algorithm = hash_algorithm
                record.fast_hash = fast_hash
                record.security_hash = security_hash
                record.security_hash_algorithm = settings.security_hash_algorithm
                attach_identity_to_record(
                    session=session,
                    record=record,
                    path=file_path,
                    metadata=metadata,
                    file_hash=file_hash,
                    fast_hash=fast_hash,
                    security_hash=security_hash,
                    directory_cache=directory_cache,
                )
                registry = _scan_registry_context(
                    session=session,
                    path=file_path,
                    metadata=metadata,
                    file_hash=file_hash,
                    file_id=record.file_id,
                    fast_hash=fast_hash,
                    security_hash=security_hash,
                    hash_algorithm=hash_algorithm,
                    is_baseline=True,
                )
                existing_count += 1
                if reanalyze_existing:
                    if reanalyzed_count < reanalyze_limit:
                        context = _deferred_baseline_event_context(
                            metadata=metadata,
                            file_category=get_file_category(file_path),
                            hash_algorithm=hash_algorithm,
                            fast_hash=fast_hash,
                            security_hash=security_hash,
                            registry_context=registry,
                            reanalyze=True,
                        )
                        session.add(FileLog(
                            file_id=record.file_id,
                            path=file_path,
                            event_type='new',
                            old_hash=None,
                            new_hash=file_hash,
                            details="Hash-first baseline reanalysis queued",
                            status='pending',
                            priority='pending',
                            analysis_json=_hash_first_baseline_payload(
                                file_path=file_path,
                                metadata=metadata,
                                file_category=context.get("file_category"),
                                queued_for_analysis=True,
                                hash_algorithm=hash_algorithm,
                                fast_hash=fast_hash,
                                security_hash=security_hash,
                                registry_context=registry,
                                reanalyze=True,
                            ),
                        ))
                        reanalyzed_count += 1
                    else:
                        reanalyze_skipped += 1
            else:
                record = FileRecord(
                    path=file_path,
                    hash=file_hash,
                    is_baseline=True,
                    mtime=metadata.get('mtime'),
                    size=metadata.get('size'),
                    name=os.path.basename(file_path),
                    hash_algorithm=hash_algorithm,
                    fast_hash=fast_hash,
                    security_hash=security_hash,
                    security_hash_algorithm=settings.security_hash_algorithm,
                )
                attach_identity_to_record(
                    session=session,
                    record=record,
                    path=file_path,
                    metadata=metadata,
                    file_hash=file_hash,
                    fast_hash=fast_hash,
                    security_hash=security_hash,
                    directory_cache=directory_cache,
                )
                registry = _scan_registry_context(
                    session=session,
                    path=file_path,
                    metadata=metadata,
                    file_hash=file_hash,
                    file_id=record.file_id,
                    fast_hash=fast_hash,
                    security_hash=security_hash,
                    hash_algorithm=hash_algorithm,
                    is_baseline=True,
                )
                session.add(record)

                file_category = get_file_category(file_path)
                baseline_analysis_checked += 1
                queue_analysis = _should_queue_deferred_baseline_analysis(
                    file_path=file_path,
                    metadata=metadata,
                    queued_so_far=baseline_analysis_queued,
                    deferred_limit=deferred_limit,
                )
                if queue_analysis:
                    baseline_analysis_queued += 1
                else:
                    baseline_analysis_skipped += 1

                analysis_payload = _hash_first_baseline_payload(
                    file_path=file_path,
                    metadata=metadata,
                    file_category=file_category,
                    queued_for_analysis=queue_analysis,
                    hash_algorithm=hash_algorithm,
                    fast_hash=fast_hash,
                    security_hash=security_hash,
                    registry_context=registry,
                )
                session.add(FileLog(
                    file_id=record.file_id,
                    path=file_path,
                    event_type='new',
                    old_hash=None,
                    new_hash=file_hash,
                    details=(
                        "Hash-first baseline captured - analysis queued"
                        if queue_analysis
                        else "Hash-first baseline captured"
                    ),
                    status='pending' if queue_analysis else 'recorded',
                    priority='pending' if queue_analysis else 'info',
                    risk_score=1,
                    analysis_json=analysis_payload,
                ))
                new_count += 1

            if idx % batch_size == 0:
                commit_started = time.perf_counter()
                session.commit()
                last_commit_seconds = time.perf_counter() - commit_started
                db_seconds += last_commit_seconds
                commit_count += 1
                hash_seconds = max(time.perf_counter() - started_at - db_seconds, 0.0)
            _emit_progress(
                progress_callback,
                "hash_baseline",
                idx,
                len(file_list),
                root_path,
                _hash_baseline_metrics(
                    started_at=started_at,
                    processed=idx,
                    hashed_bytes=hashed_bytes,
                    hash_seconds=hash_seconds,
                    db_seconds=db_seconds,
                    commit_count=commit_count,
                    last_commit_seconds=last_commit_seconds,
                    errors=errors,
                    current_file=file_path,
                    hash_workers=hash_workers,
                ),
            )

        commit_started = time.perf_counter()
        session.commit()
        last_commit_seconds = time.perf_counter() - commit_started
        db_seconds += last_commit_seconds
        commit_count += 1
        hash_seconds = max(time.perf_counter() - started_at - db_seconds, 0.0)
        return {
            "scan_mode": "hash_first",
            "total_files": len(file_list),
            "new_baselined": new_count,
            "updated": existing_count,
            "reanalyzed": reanalyzed_count,
            "reanalyze_skipped": reanalyze_skipped,
            "baseline_analysis_checked": baseline_analysis_checked,
            "baseline_analysis_queued": baseline_analysis_queued,
            "baseline_analysis_skipped": baseline_analysis_skipped,
            "baseline_analysis_deferred": baseline_analysis_queued,
            "errors": errors,
            "elapsed_seconds": round(time.perf_counter() - started_at, 3),
            "bytes_processed": int(hashed_bytes),
            "mb_per_second": round(
                (hashed_bytes / (1024 * 1024)) / max(time.perf_counter() - started_at, 0.000001),
                2,
            ) if hashed_bytes else 0,
            "files_per_second": round(
                len(file_list) / max(time.perf_counter() - started_at, 0.000001),
                2,
            ) if file_list else 0,
            "hash_seconds": round(hash_seconds, 3),
            "db_commit_seconds": round(db_seconds, 3),
            "commit_count": commit_count,
            "hash_workers": hash_workers,
        }

    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def _baseline_triage_analysis(
    file_path: str,
    snippet: str,
    metadata: dict | None,
    file_category: str | None,
) -> dict | None:
    """Run fast local triage for baseline files without calling an LLM."""
    mode = (settings.baseline_analysis_mode or "suspicious").lower()
    if mode in ("off", "false", "0", "none"):
        return None

    enriched_metadata = dict(metadata or {})
    enriched_metadata["is_baseline"] = True
    if file_category:
        enriched_metadata["file_category"] = file_category

    from .llm_analyzer import _fallback_analysis
    return _fallback_analysis(
        file_path=file_path,
        change_type="new",
        content=snippet,
        metadata=enriched_metadata,
    )


def _baseline_triage_skip_reason(file_path: str, metadata: dict | None) -> str | None:
    """Explain why a baseline file did not receive content triage."""
    mode = (settings.baseline_analysis_mode or "suspicious").lower()
    if mode in ("off", "false", "0", "none"):
        return "baseline content analysis is disabled"
    if mode == "all":
        return None

    size = int((metadata or {}).get("size") or 0)
    max_bytes = max(0, int(settings.baseline_analysis_max_bytes or 0))
    if max_bytes and size > max_bytes:
        return f"file size {size} bytes exceeds the {max_bytes} byte baseline analysis limit"

    ext = os.path.splitext(file_path.lower())[1]
    if ext not in BASELINE_TRIAGE_EXTENSIONS:
        return f"extension '{ext or 'none'}' is not in the baseline text-analysis allowlist"
    return None


def _baseline_event_context(
    snippet: str,
    metadata: dict | None,
    file_category: str | None,
    baseline_triage: dict | None = None,
    registry_context: dict | None = None,
    reanalyze: bool = False,
) -> dict:
    """Raw context preserved so later modifications can build before/after diffs."""
    context = {
        "diff": snippet,
        "metadata": metadata,
        "file_category": file_category,
        "is_baseline": True,
    }
    if baseline_triage:
        context["baseline_triage"] = baseline_triage
    if registry_context:
        context["registry"] = registry_context
    if reanalyze:
        context["reanalyze"] = True
    return context


def _baseline_analysis_payload(
    file_path: str,
    snippet: str,
    metadata: dict | None,
    file_category: str | None,
    baseline_triage: dict | None,
    skipped_reason: str | None = None,
    registry_context: dict | None = None,
) -> dict:
    """
    Store baseline context analysis as the primary payload.

    The background analyzer still receives raw event context, but the API/UI can
    immediately render the baseline verdict instead of an empty analysis card.
    """
    event_context = _baseline_event_context(
        snippet=snippet,
        metadata=metadata,
        file_category=file_category,
        baseline_triage=baseline_triage,
        registry_context=registry_context,
    )

    if baseline_triage:
        payload = dict(baseline_triage)
        payload.setdefault("analysis_source", "heuristic")
        payload["baseline_context"] = True
        payload["event_context"] = event_context
        return payload

    reasoning = "Baseline recorded."
    if skipped_reason:
        reasoning += f" Content analysis skipped because {skipped_reason}."
    else:
        reasoning += " No readable content was available for baseline context analysis."

    return {
        "risk_score": 1,
        "priority": "info",
        "is_malicious": False,
        "threat_type": "benign",
        "threat_classification": "Baseline Recorded",
        "mitre_attack": [],
        "iocs": [],
        "confidence": "low",
        "reasoning": reasoning,
        "analysis_source": "baseline",
        "context_notes": ["Baseline event recorded without full content triage."],
        "findings": [],
        "change_summary": "",
        "recommended_actions": [
            "Record the event for audit history.",
            "No immediate response is required unless this baseline was unexpected.",
        ],
        "baseline_context": True,
        "event_context": event_context,
    }


def _deferred_baseline_event_context(
    metadata: dict | None,
    file_category: str | None,
    hash_algorithm: str | None = None,
    fast_hash: str | None = None,
    security_hash: str | None = None,
    registry_context: dict | None = None,
    reanalyze: bool = False,
) -> dict:
    """Event context for hash-first rows; content is read later by analysis."""
    context = {
        "diff": "",
        "metadata": metadata,
        "file_category": file_category,
        "is_baseline": True,
        "analysis_deferred": True,
        "hashes": {
            "mode": settings.hash_mode,
            "comparison_algorithm": hash_algorithm or settings.hash_algorithm,
            "comparison_hash": fast_hash,
            "security_algorithm": settings.security_hash_algorithm,
            "security_hash": security_hash,
            "security_hash_pending": security_hash is None,
        },
    }
    if registry_context:
        context["registry"] = registry_context
    if reanalyze:
        context["reanalyze"] = True
    return context


def _hash_first_baseline_payload(
    file_path: str,
    metadata: dict | None,
    file_category: str | None,
    queued_for_analysis: bool,
    hash_algorithm: str | None = None,
    fast_hash: str | None = None,
    security_hash: str | None = None,
    registry_context: dict | None = None,
    reanalyze: bool = False,
) -> dict:
    """Minimal baseline payload stored during the fast hash capture phase."""
    context = _deferred_baseline_event_context(
        metadata=metadata,
        file_category=file_category,
        hash_algorithm=hash_algorithm,
        fast_hash=fast_hash,
        security_hash=security_hash,
        registry_context=registry_context,
        reanalyze=reanalyze,
    )
    if queued_for_analysis:
        reasoning = (
            "Hash-first baseline captured. Content analysis is queued and will "
            "run after the integrity snapshot is complete."
        )
    else:
        reasoning = (
            "Hash-first baseline captured. Content analysis was deferred to keep "
            "initial hash capture fast."
        )
    return {
        "risk_score": 1,
        "priority": "info",
        "is_malicious": False,
        "threat_type": "benign",
        "threat_classification": "Hash Baseline",
        "mitre_attack": [],
        "iocs": [],
        "confidence": "low",
        "reasoning": reasoning,
        "analysis_source": "hash_first",
        "context_notes": [
            "Initial scan prioritized fast comparison hash capture before content analysis."
        ],
        "findings": [],
        "change_summary": "",
        "recommended_actions": [
            "Use the fast comparison hash for rapid drift detection.",
            "Review security hash coverage as background analysis completes.",
        ],
        "baseline_context": True,
        "analysis_deferred": queued_for_analysis,
        "hash_mode": settings.hash_mode,
        "hash_algorithm": hash_algorithm or settings.hash_algorithm,
        "fast_hash": fast_hash,
        "security_hash_algorithm": settings.security_hash_algorithm,
        "security_hash": security_hash,
        "security_hash_pending": security_hash is None,
        "event_context": context,
    }


def _should_queue_deferred_baseline_analysis(
    file_path: str,
    metadata: dict | None,
    queued_so_far: int,
    deferred_limit: int,
) -> bool:
    """Queue only higher-value baseline files for post-snapshot content analysis."""
    mode = (settings.baseline_analysis_mode or "suspicious").lower()
    if mode in ("off", "false", "0", "none"):
        return False
    if deferred_limit and queued_so_far >= deferred_limit:
        return False

    if not _should_triage_baseline_file(file_path, metadata):
        return False
    if mode == "all":
        return True

    ext = os.path.splitext(file_path.lower())[1]
    return ext in DEFERRED_BASELINE_ANALYSIS_EXTENSIONS


def _should_triage_baseline_file(file_path: str, metadata: dict | None) -> bool:
    """Avoid reading/scanning files that cannot reasonably affect alerting."""
    mode = (settings.baseline_analysis_mode or "suspicious").lower()
    if mode in ("off", "false", "0", "none"):
        return False
    if mode == "all":
        return True

    size = int((metadata or {}).get("size") or 0)
    max_bytes = max(0, int(settings.baseline_analysis_max_bytes or 0))
    if max_bytes and size > max_bytes:
        return False

    ext = os.path.splitext(file_path.lower())[1]
    return ext in BASELINE_TRIAGE_EXTENSIONS


def _should_queue_baseline_analysis(
    file_path: str,
    metadata: dict | None,
    triage_result: dict | None,
) -> bool:
    """Return True when a baseline file deserves full analysis."""
    mode = (settings.baseline_analysis_mode or "suspicious").lower()
    if mode in ("off", "false", "0", "none"):
        return False
    if mode == "all":
        return True

    if not _should_triage_baseline_file(file_path, metadata):
        return False

    score = int((triage_result or {}).get("risk_score") or 0)
    threshold = int(settings.baseline_analysis_risk_threshold or 7)
    return score >= threshold


def _compare_and_log_legacy(
    root_path: str,
    progress_callback: Callable[[dict], None] | None = None,
) -> dict:
    """
    Re-scan directory. Compare hashes against DB.
    Log new, modified, and deleted files as FileLog events.
    Returns summary dict.
    """
    session: Session = SessionLocal()
    file_list = _walk_directory(root_path)

    new_files = []
    modified_files = []
    deleted_files = []
    renamed_files = []
    new_candidates = []

    try:
        _emit_progress(progress_callback, "compare", 0, len(file_list), root_path)
        existing = {r.path: r for r in session.query(FileRecord).all()}
        directory_cache = {}
        scanned_paths = set()

        for idx, file_path in enumerate(file_list, start=1):
            if file_path in scanned_paths:
                _emit_progress(progress_callback, "compare", idx, len(file_list), root_path)
                continue
            scanned_paths.add(file_path)

            try:
                file_hash = calculate_file_hash(file_path)
                metadata = get_file_metadata(file_path)
            except (PermissionError, OSError):
                _emit_progress(progress_callback, "compare", idx, len(file_list), root_path)
                continue

            if file_path not in existing:
                new_candidates.append({
                    "path": file_path,
                    "hash": file_hash,
                    "metadata": metadata,
                })
                _emit_progress(progress_callback, "compare", idx, len(file_list), root_path)
                continue

            else:
                record = existing[file_path]
                assign_file_location(session, record, file_path, directory_cache)

                # Quick check: if mtime+size unchanged, skip hashing
                if (metadata and record.mtime == metadata['mtime']
                        and record.size == metadata['size']):
                    _emit_progress(progress_callback, "compare", idx, len(file_list), root_path)
                    continue

                if record.hash != file_hash:
                    # MODIFIED file
                    modified_files.append(file_path)
                    old_hash = record.hash

                    snippet = _read_snippet(file_path)
                    session.add(FileLog(
                        path=file_path,
                        event_type='modified',
                        old_hash=old_hash,
                        new_hash=file_hash,
                        details=f"Hash changed: {old_hash[:12]}... -> {file_hash[:12]}...",
                        status='pending',
                    analysis_json={"diff": snippet, "metadata": metadata, "is_baseline": False},
                    ))

                    # Update record  -  baseline no longer matches on-disk content.
                    record.hash = file_hash
                    record.last_seen = datetime.utcnow()
                    record.mtime = metadata['mtime'] if metadata else None
                    record.size = metadata['size'] if metadata else None
                    record.is_baseline = False
            _emit_progress(progress_callback, "compare", idx, len(file_list), root_path)

        # Detect DELETED files (in DB but not on disk)
        deleted_candidates = [
            (path, record) for path, record in existing.items()
            if path not in scanned_paths
        ]
        deleted_by_hash = {}
        for path, record in deleted_candidates:
            deleted_by_hash.setdefault(record.hash, []).append((path, record))

        consumed_deleted_paths = set()

        for candidate in new_candidates:
            matched_deleted = deleted_by_hash.get(candidate["hash"]) or []
            if matched_deleted:
                old_path, record = matched_deleted.pop(0)
                new_path = candidate["path"]
                metadata = candidate["metadata"]
                consumed_deleted_paths.add(old_path)
                renamed_files.append((old_path, new_path))

                # Keep the timeline continuous under the current path.
                session.query(FileLog).filter(FileLog.path == old_path).update(
                    {FileLog.path: new_path},
                    synchronize_session=False,
                )

                record.path = new_path
                record.hash = candidate["hash"]
                record.last_seen = datetime.utcnow()
                record.mtime = metadata['mtime'] if metadata else None
                record.size = metadata['size'] if metadata else None
                record.is_baseline = False
                assign_file_location(session, record, new_path, directory_cache)

                session.add(FileLog(
                    path=new_path,
                    event_type='renamed',
                    old_hash=candidate["hash"],
                    new_hash=candidate["hash"],
                    details=f"File renamed: {old_path} -> {new_path}",
                    status='pending',
                    analysis_json={
                        "diff": f"File renamed from {old_path} to {new_path}",
                        "metadata": metadata,
                        "is_baseline": False,
                        "previous_path": old_path,
                        "new_path": new_path,
                    },
                ))
                continue

            # NEW file
            file_path = candidate["path"]
            file_hash = candidate["hash"]
            metadata = candidate["metadata"]
            new_files.append(file_path)
            record = FileRecord(
                path=file_path,
                hash=file_hash,
                is_baseline=False,
                mtime=metadata['mtime'] if metadata else None,
                size=metadata['size'] if metadata else None,
            )
            assign_file_location(session, record, file_path, directory_cache)
            session.add(record)

            # Read snippet for analysis
            snippet = _read_snippet(file_path)
            session.add(FileLog(
                path=file_path,
                event_type='new',
                old_hash=None,
                new_hash=file_hash,
                details="New file detected",
                status='pending',
                analysis_json={"diff": snippet, "metadata": metadata, "is_baseline": False},
            ))

        for path, record in deleted_candidates:
            if path not in consumed_deleted_paths:
                deleted_files.append(path)
                session.add(FileLog(
                    path=path,
                    event_type='deleted',
                    old_hash=record.hash,
                    new_hash=None,
                    details="File removed from disk",
                    status='pending',
                    analysis_json={"diff": "File deleted", "metadata": None, "is_baseline": False},
                ))
                session.delete(record)

        session.commit()
        return {
            "new": len(new_files),
            "modified": len(modified_files),
            "deleted": len(deleted_files),
            "renamed": len(renamed_files),
        }

    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def compare_and_log(
    root_path: str,
    progress_callback: Callable[[dict], None] | None = None,
) -> dict:
    """
    Re-scan a directory with metadata-first reconciliation.

    Unchanged files are not opened for hashing. Renames are matched by the
    platform file ID when the OS exposes one, then by same-hash fallback.
    """
    session: Session = SessionLocal()
    file_list = _walk_directory(root_path)

    new_files = []
    modified_files = []
    deleted_files = []
    renamed_files = []
    new_candidates = []
    hashed_files = 0
    metadata_skipped = 0
    platform_renames = 0
    consumed_deleted_paths = set()

    try:
        _emit_progress(progress_callback, "compare", 0, len(file_list), root_path)
        existing = {r.path: r for r in session.query(FileRecord).all()}
        existing_by_file_id = {
            r.file_id: r for r in existing.values() if r.file_id is not None
        }
        directory_cache = {}
        scanned_paths = set()

        def record_rename(
            record: FileRecord,
            old_path: str,
            new_path: str,
            file_hash: str,
            metadata: dict | None,
            platform_match: bool = False,
        ) -> None:
            nonlocal platform_renames
            consumed_deleted_paths.add(old_path)
            renamed_files.append((old_path, new_path))
            if platform_match:
                platform_renames += 1

            attach_identity_to_record(
                session=session,
                record=record,
                path=new_path,
                metadata=metadata,
                file_hash=file_hash,
                fast_hash=file_hash,
                directory_cache=directory_cache,
            )

            # Keep legacy path-based UI queries continuous while file_id rollout
            # makes the timeline independent from path changes.
            session.query(FileLog).filter(FileLog.path == old_path).update(
                {FileLog.path: new_path, FileLog.file_id: record.file_id},
                synchronize_session=False,
            )

            record.path = new_path
            record.hash = file_hash
            record.last_seen = datetime.utcnow()
            record.mtime = metadata.get('mtime') if metadata else None
            record.size = metadata.get('size') if metadata else None
            record.is_baseline = False
            record.fast_hash = file_hash

            registry = _scan_registry_context(
                session=session,
                path=new_path,
                metadata=metadata,
                file_hash=file_hash,
                file_id=record.file_id,
                fast_hash=file_hash,
                is_baseline=False,
            )

            session.add(FileLog(
                file_id=record.file_id,
                path=new_path,
                event_type='renamed',
                old_hash=file_hash,
                new_hash=file_hash,
                details=f"File renamed: {old_path} -> {new_path}",
                status='pending',
                analysis_json={
                    "diff": f"File renamed from {old_path} to {new_path}",
                    "metadata": metadata,
                    "is_baseline": False,
                    "previous_path": old_path,
                    "new_path": new_path,
                    "identity_match": "platform_file_id" if platform_match else "content_hash",
                    "registry": registry,
                },
            ))

        for idx, file_path in enumerate(file_list, start=1):
            if file_path in scanned_paths:
                _emit_progress(progress_callback, "compare", idx, len(file_list), root_path)
                continue
            scanned_paths.add(file_path)

            try:
                metadata = get_file_metadata(file_path)
            except (PermissionError, OSError):
                _emit_progress(progress_callback, "compare", idx, len(file_list), root_path)
                continue
            if not metadata:
                _emit_progress(progress_callback, "compare", idx, len(file_list), root_path)
                continue

            record = existing.get(file_path)
            if record is None:
                identity = find_identity_by_platform_id(
                    session, metadata.get('platform_file_id')
                )
                identity_record = (
                    existing_by_file_id.get(identity.id)
                    if identity is not None else None
                )
                if identity_record is None and identity is not None:
                    identity_record = existing.get(identity.current_path)
                if (
                    identity_record is not None
                    and identity_record.path not in scanned_paths
                    and not os.path.exists(identity_record.path)
                ):
                    file_hash = identity_record.hash
                    if (
                        identity_record.mtime != metadata.get('mtime')
                        or identity_record.size != metadata.get('size')
                    ):
                        try:
                            file_hash = calculate_file_hash(file_path)
                            hashed_files += 1
                        except (PermissionError, OSError):
                            _emit_progress(progress_callback, "compare", idx, len(file_list), root_path)
                            continue
                    record_rename(
                        identity_record,
                        identity_record.path,
                        file_path,
                        file_hash,
                        metadata,
                        platform_match=True,
                    )
                    _emit_progress(progress_callback, "compare", idx, len(file_list), root_path)
                    continue

                new_candidates.append({
                    "path": file_path,
                    "metadata": metadata,
                })
                _emit_progress(progress_callback, "compare", idx, len(file_list), root_path)
                continue

            attach_identity_to_record(
                session=session,
                record=record,
                path=file_path,
                metadata=metadata,
                file_hash=record.hash,
                fast_hash=record.fast_hash or record.hash,
                security_hash=record.security_hash,
                directory_cache=directory_cache,
            )

            if record.mtime == metadata.get('mtime') and record.size == metadata.get('size'):
                record.last_seen = datetime.utcnow()
                metadata_skipped += 1
                _emit_progress(progress_callback, "compare", idx, len(file_list), root_path)
                continue

            try:
                file_hash = calculate_file_hash(file_path)
                hashed_files += 1
            except (PermissionError, OSError):
                _emit_progress(progress_callback, "compare", idx, len(file_list), root_path)
                continue

            if record.hash != file_hash:
                modified_files.append(file_path)
                old_hash = record.hash
                snippet = _read_snippet(file_path)
                registry = _scan_registry_context(
                    session=session,
                    path=file_path,
                    metadata=metadata,
                    file_hash=file_hash,
                    file_id=record.file_id,
                    fast_hash=file_hash,
                    is_baseline=False,
                )
                session.add(FileLog(
                    file_id=record.file_id,
                    path=file_path,
                    event_type='modified',
                    old_hash=old_hash,
                    new_hash=file_hash,
                    details=f"Hash changed: {old_hash[:12]}... -> {file_hash[:12]}...",
                    status='pending',
                    analysis_json={
                        "diff": snippet,
                        "metadata": metadata,
                        "is_baseline": False,
                        "registry": registry,
                    },
                ))
                record.hash = file_hash
                record.fast_hash = file_hash
                record.is_baseline = False
            else:
                metadata_skipped += 1

            record.last_seen = datetime.utcnow()
            record.mtime = metadata.get('mtime')
            record.size = metadata.get('size')
            attach_identity_to_record(
                session=session,
                record=record,
                path=file_path,
                metadata=metadata,
                file_hash=record.hash,
                fast_hash=record.fast_hash or record.hash,
                security_hash=record.security_hash,
                directory_cache=directory_cache,
            )
            _emit_progress(progress_callback, "compare", idx, len(file_list), root_path)

        deleted_candidates = [
            (path, record) for path, record in existing.items()
            if path not in scanned_paths and path not in consumed_deleted_paths
        ]
        deleted_by_hash = {}
        for path, record in deleted_candidates:
            deleted_by_hash.setdefault(record.hash, []).append((path, record))

        for candidate in new_candidates:
            file_path = candidate["path"]
            metadata = candidate["metadata"]
            try:
                file_hash = calculate_file_hash(file_path)
                hashed_files += 1
            except (PermissionError, OSError):
                continue

            matched_deleted = deleted_by_hash.get(file_hash) or []
            while matched_deleted and matched_deleted[0][0] in consumed_deleted_paths:
                matched_deleted.pop(0)

            if matched_deleted:
                old_path, record = matched_deleted.pop(0)
                record_rename(
                    record,
                    old_path,
                    file_path,
                    file_hash,
                    metadata,
                    platform_match=False,
                )
                continue

            new_files.append(file_path)
            record = FileRecord(
                path=file_path,
                hash=file_hash,
                is_baseline=False,
                mtime=metadata.get('mtime'),
                size=metadata.get('size'),
                hash_algorithm=settings.hash_algorithm,
                fast_hash=file_hash,
                security_hash_algorithm=settings.security_hash_algorithm,
            )
            attach_identity_to_record(
                session=session,
                record=record,
                path=file_path,
                metadata=metadata,
                file_hash=file_hash,
                fast_hash=file_hash,
                directory_cache=directory_cache,
            )
            session.add(record)
            registry = _scan_registry_context(
                session=session,
                path=file_path,
                metadata=metadata,
                file_hash=file_hash,
                file_id=record.file_id,
                fast_hash=file_hash,
                is_baseline=False,
            )

            snippet = _read_snippet(file_path)
            session.add(FileLog(
                file_id=record.file_id,
                path=file_path,
                event_type='new',
                old_hash=None,
                new_hash=file_hash,
                details="New file detected",
                status='pending',
                analysis_json={
                    "diff": snippet,
                    "metadata": metadata,
                    "is_baseline": False,
                    "registry": registry,
                },
            ))

        for path, record in deleted_candidates:
            if path not in consumed_deleted_paths:
                deleted_files.append(path)
                registry_entry = mark_registry_inactive(
                    session,
                    file_id=record.file_id,
                    path=path,
                )
                registry = build_registry_context(registry_entry)
                session.add(FileLog(
                    file_id=record.file_id,
                    path=path,
                    event_type='deleted',
                    old_hash=record.hash,
                    new_hash=None,
                    details="File removed from disk",
                    status='pending',
                    analysis_json={
                        "diff": "File deleted",
                        "metadata": None,
                        "is_baseline": False,
                        "registry": registry,
                    },
                ))
                if record.file_id is not None:
                    mark_identity_inactive(session.get(FileIdentity, record.file_id))
                session.delete(record)

        session.commit()
        return {
            "new": len(new_files),
            "modified": len(modified_files),
            "deleted": len(deleted_files),
            "renamed": len(renamed_files),
            "hashed": hashed_files,
            "metadata_skipped": metadata_skipped,
            "platform_renames": platform_renames,
        }

    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def _read_snippet(file_path: str, max_chars: int = 5000) -> str:
    """Read first N chars of a file for analysis context."""
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(min(1024, max_chars))
            if b'\x00' in chunk:
                return "Binary/Unreadable"

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read(max_chars)
    except Exception:
        return "Binary/Unreadable"
