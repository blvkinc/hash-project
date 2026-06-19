"""
Helpers for OS-wide recommended-path monitoring.

The module collects Tier 1 and Tier 2 filesystem and registry targets, then
feeds them through the normal scan and analysis pipeline.
"""
import logging
import os
from datetime import datetime
from typing import List, Optional

from core.database import SessionLocal
from core.models import FileLog, FileRecord
from core.platform_paths import detect_os, get_default_paths
from core.scanner import compare_and_log, scan_and_baseline

logger = logging.getLogger(__name__)



def is_filesystem_monitor_path(path: str) -> bool:
    """Skip registry-style pseudo paths; keep real filesystem locations only."""
    low = path.lower()
    if low.startswith(('hklm\\', 'hkcu\\', 'hkey_')):
        return False
    if os.name == 'nt':
        return len(path) >= 3 and path[1] == ':'
    return path.startswith('/')


def is_registry_monitor_path(path: str) -> bool:
    low = path.lower()
    return low.startswith(
        ('hklm\\', 'hkcu\\', 'hkey_local_machine\\', 'hkey_current_user\\')
    )


def collect_system_monitor_paths() -> List[str]:
    """Collect existing Tier 1-2 filesystem paths for the current OS."""
    tiered = get_default_paths(target_os=detect_os())
    selected: List[str] = []

    for tier in (1, 2):
        for target in tiered.get(tier, []):
            raw = target.path
            if '*' in raw:
                continue
            if not is_filesystem_monitor_path(raw):
                continue
            watch_path = raw if target.is_directory else os.path.dirname(raw)
            if watch_path and os.path.exists(watch_path):
                selected.append(os.path.abspath(watch_path))

    deduped: List[str] = []
    seen = set()
    for path in selected:
        if path not in seen:
            seen.add(path)
            deduped.append(path)
    return deduped


def collect_system_registry_paths() -> List[str]:
    """Collect Tier 1-2 registry keys for OS-level monitoring."""
    tiered = get_default_paths(target_os=detect_os())
    selected: List[str] = []

    for tier in (1, 2):
        for target in tiered.get(tier, []):
            if getattr(target, 'category', '') != 'registry':
                continue
            raw = target.path
            if not is_registry_monitor_path(raw):
                continue
            selected.append(raw.strip().strip('\\'))

    deduped: List[str] = []
    seen = set()
    for path in selected:
        key = path.upper()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path)
    return deduped



def scan_paths_for_baseline(paths: List[str]) -> None:
    """Background baseline + reconciliation scan for multiple paths."""
    for path in paths:
        try:
            logger.info(f"System monitor baseline scan: {path}")
            result = scan_and_baseline(path)
            changes = compare_and_log(path)
            logger.info(
                f"System monitor baseline complete for {path}: "
                f"{result}, changes={changes}"
            )
        except Exception as exc:
            logger.warning(f"System monitor scan failed for {path}: {exc}")



def handle_registry_change(
    path: str,
    event_type: str,
    old_hash: Optional[str],
    new_hash: Optional[str],
    details: str,
    diff_text: str,
    metadata: dict,
) -> None:
    """Persist registry change events so the normal analysis pipeline can score them."""
    session = SessionLocal()
    try:
        record = session.query(FileRecord).filter(FileRecord.path == path).first()

        if event_type == 'deleted':
            session.add(FileLog(
                path=path,
                event_type='deleted',
                old_hash=old_hash,
                new_hash=None,
                details=details,
                status='pending',
                analysis_json={"diff": diff_text, "metadata": metadata},
            ))
            if record:
                session.delete(record)
            session.commit()
            return

        effective_hash = new_hash or old_hash or '0' * 64
        value_count = 0
        if metadata and isinstance(metadata, dict):
            value_count = int(metadata.get('value_count', 0) or 0)

        if record is None:
            session.add(FileRecord(
                path=path,
                hash=effective_hash,
                is_baseline=False,
                size=value_count,
            ))
        else:
            record.hash = effective_hash
            record.last_seen = datetime.utcnow()
            record.size = value_count

        session.add(FileLog(
            path=path,
            event_type=event_type,
            old_hash=old_hash,
            new_hash=new_hash,
            details=details,
            status='pending',
            analysis_json={"diff": diff_text, "metadata": metadata},
        ))

        session.commit()
    except Exception as exc:
        session.rollback()
        logger.warning(f"Failed to persist registry event for {path}: {exc}")
    finally:
        session.close()
