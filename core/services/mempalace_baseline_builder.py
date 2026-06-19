"""Build MemPalace baseline identity memories from the SQL registry."""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Callable

from sqlalchemy.orm import Session

from core.config import settings
from core.database import SessionLocal
from core.models import FileRegistryEntry
from core.services.file_registry import registry_context
from core.services.mempalace_bridge import (
    backend_status,
    build_baseline_memory,
    enabled as mempalace_enabled,
    upsert_baseline_memories,
)

logger = logging.getLogger(__name__)

IMPORTANT_TIER3_ROLES = {
    "source_code",
    "script",
    "configuration",
    "secret_or_credential_material",
    "executable_or_library",
    "installed_application_binary",
    "powershell_profile",
    "user_startup_item",
    "windows_group_policy_file",
    "dns_override_config",
}

IMPORTANT_TIER3_ASSETS = {
    "auth",
    "binary",
    "code",
    "config",
    "driver",
    "persistence",
}


def build_mempalace_baseline_from_sql(
    *,
    root_path: str | None = None,
    scan_session_id: int | None = None,
    limit: int | None = None,
    batch_size: int | None = None,
    progress_callback: Callable[[dict], None] | None = None,
    session: Session | None = None,
) -> dict[str, Any]:
    """
    Create/update MemPalace baseline identity drawers from SQL registry rows.

    This is intentionally bounded. The SQL registry remains the complete
    ledger; MemPalace receives high-value identity memories that help the
    agent reason about later changes.
    """
    if not bool(getattr(settings, "mempalace_baseline_enabled", True)):
        return {"enabled": False, "stored": 0, "reason": "baseline_memory_disabled"}
    if not mempalace_enabled():
        return {"enabled": False, "stored": 0, "reason": "mempalace_disabled"}

    max_entries = max(0, int(limit if limit is not None else settings.mempalace_baseline_max_entries or 0))
    if max_entries <= 0:
        return {"enabled": True, "stored": 0, "reason": "baseline_memory_limit_zero"}
    safe_batch = max(1, int(batch_size or settings.mempalace_baseline_batch_size or 64))
    started = time.perf_counter()
    own_session = session is None
    db = session or SessionLocal()
    scanned = 0
    eligible = 0
    skipped = 0
    stored = 0
    batches = 0
    errors: list[str] = []
    pending: list[dict[str, Any]] = []
    root_abs = _normalized_root(root_path)

    try:
        _emit_progress(
            progress_callback,
            root_path=root_path,
            processed=0,
            total=max_entries,
            stored=0,
            eligible=0,
            skipped=0,
        )

        query = (
            db.query(FileRegistryEntry)
            .filter(FileRegistryEntry.is_active == True)  # noqa: E712 - SQLAlchemy expression
            .order_by(
                FileRegistryEntry.tier.asc().nullslast(),
                FileRegistryEntry.updated_at.desc(),
                FileRegistryEntry.id.asc(),
            )
        )
        for entry in query.yield_per(500):
            scanned += 1
            context = registry_context(entry)
            if not context:
                skipped += 1
                continue
            if root_abs and not _is_under_root(str(context.get("path") or ""), root_abs):
                continue
            if not _should_store_baseline_identity(context):
                skipped += 1
                continue

            eligible += 1
            pending.append(build_baseline_memory(
                registry=context,
                root_path=root_path,
                scan_session_id=scan_session_id,
            ))

            if len(pending) >= safe_batch:
                result = upsert_baseline_memories(pending)
                stored += int(result.get("stored") or 0)
                batches += 1
                if result.get("error"):
                    errors.append(str(result.get("error")))
                pending.clear()
                _emit_progress(
                    progress_callback,
                    root_path=root_path,
                    processed=eligible,
                    total=max_entries,
                    stored=stored,
                    eligible=eligible,
                    skipped=skipped,
                )

            if eligible >= max_entries:
                break

        if pending:
            result = upsert_baseline_memories(pending)
            stored += int(result.get("stored") or 0)
            batches += 1
            if result.get("error"):
                errors.append(str(result.get("error")))
            pending.clear()

        elapsed = round(time.perf_counter() - started, 3)
        output = {
            "enabled": True,
            "backend": backend_status(),
            "root_path": root_path,
            "scan_session_id": scan_session_id,
            "scanned_registry_entries": scanned,
            "eligible": eligible,
            "skipped": skipped,
            "stored": stored,
            "batches": batches,
            "limit": max_entries,
            "elapsed_seconds": elapsed,
            "errors": errors[:5],
        }
        logger.info(
            "MemPalace baseline build complete: root=%s eligible=%s stored=%s skipped=%s",
            root_path,
            eligible,
            stored,
            skipped,
        )
        _emit_progress(
            progress_callback,
            root_path=root_path,
            processed=eligible,
            total=max_entries,
            stored=stored,
            eligible=eligible,
            skipped=skipped,
            complete=True,
        )
        return output
    except Exception as exc:  # noqa: BLE001 - backend and DB exceptions vary.
        logger.exception("MemPalace baseline build failed for %s: %s", root_path, exc)
        return {
            "enabled": True,
            "root_path": root_path,
            "scan_session_id": scan_session_id,
            "scanned_registry_entries": scanned,
            "eligible": eligible,
            "skipped": skipped,
            "stored": stored,
            "batches": batches,
            "limit": max_entries,
            "elapsed_seconds": round(time.perf_counter() - started, 3),
            "error": str(exc),
            "errors": errors[:5],
        }
    finally:
        if own_session:
            db.close()


def _should_store_baseline_identity(registry: dict[str, Any]) -> bool:
    tier = _as_int(registry.get("tier"))
    if tier in (1, 2):
        return True
    if tier == 3:
        role = str(registry.get("semantic_role") or "")
        asset = str(registry.get("asset_type") or registry.get("file_category") or "")
        return role in IMPORTANT_TIER3_ROLES or asset in IMPORTANT_TIER3_ASSETS
    if tier == 4:
        return bool(getattr(settings, "mempalace_baseline_include_tier4", False))
    return False


def _normalized_root(root_path: str | None) -> str | None:
    if not root_path:
        return None
    try:
        return os.path.normcase(os.path.abspath(os.path.normpath(root_path)))
    except Exception:
        return None


def _is_under_root(path: str, normalized_root: str) -> bool:
    if not path:
        return False
    try:
        normalized_path = os.path.normcase(os.path.abspath(os.path.normpath(path)))
        return os.path.commonpath([normalized_path, normalized_root]) == normalized_root
    except (OSError, ValueError):
        return False


def _emit_progress(
    progress_callback: Callable[[dict], None] | None,
    *,
    root_path: str | None,
    processed: int,
    total: int,
    stored: int,
    eligible: int,
    skipped: int,
    complete: bool = False,
) -> None:
    if progress_callback is None:
        return
    try:
        progress_callback({
            "stage": "memory_baseline",
            "path": root_path,
            "processed": processed,
            "total": max(total, processed),
            "mempalace_baseline": {
                "stored": stored,
                "eligible": eligible,
                "skipped": skipped,
                "complete": complete,
            },
        })
    except Exception:
        logger.debug("MemPalace baseline progress callback failed", exc_info=True)


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
