"""Real-time filesystem monitoring using watchdog."""
import os
import time
import threading
import logging
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent
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
from .services.file_registry import (
    mark_registry_inactive,
    registry_context as build_registry_context,
    upsert_registry_entry,
)

logger = logging.getLogger(__name__)

EXCLUDED_DIRS = {
    '.git', '__pycache__', 'node_modules', '.venv', 'env', 'venv',
    '$RECYCLE.BIN', 'System Volume Information', '.idea', '.vscode',
}
EXCLUDED_FILES = {
    'file_monitor.db', 'file_monitor.db-journal', 'file_monitor.db-wal',
}


def _should_ignore(path: str) -> bool:
    """Check if a path should be ignored based on excluded dirs/files."""
    parts = path.replace('\\', '/').split('/')
    for part in parts:
        if part in EXCLUDED_DIRS:
            return True
    basename = os.path.basename(path)
    if basename in EXCLUDED_FILES:
        return True
    return False


def _read_snippet(file_path: str, max_chars: int = 5000) -> str:
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(min(1024, max_chars))
            if b'\x00' in chunk:
                return "Binary/Unreadable"

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read(max_chars)
    except Exception:
        return "Binary/Unreadable"


def _watch_registry_context(
    session: Session,
    path: str,
    metadata: dict | None,
    file_hash: str | None,
    file_id: int | None = None,
    active: bool = True,
) -> dict | None:
    entry = upsert_registry_entry(
        session=session,
        path=path,
        metadata=metadata,
        file_hash=file_hash,
        fast_hash=file_hash,
        file_id=file_id,
        hash_algorithm=settings.hash_algorithm,
        security_hash_algorithm=settings.security_hash_algorithm,
        is_baseline=False,
        active=active,
    )
    return build_registry_context(entry)


class IntegrityEventHandler(FileSystemEventHandler):
    """Handles filesystem events and logs hash changes to DB."""

    def __init__(self):
        super().__init__()
        # Debounce: track last event time per path to avoid duplicate rapid events
        self._last_event = {}
        self._debounce_seconds = 1.0

    def _debounce(self, path: str) -> bool:
        """Returns True if we should skip this event (too soon after last one)."""
        now = time.time()
        last = self._last_event.get(path, 0)
        if now - last < self._debounce_seconds:
            return True
        self._last_event[path] = now
        return False

    def on_created(self, event: FileSystemEvent):
        if event.is_directory:
            return
        self._handle_event(event.src_path, 'new')

    def on_modified(self, event: FileSystemEvent):
        if event.is_directory:
            return
        self._handle_event(event.src_path, 'modified')

    def on_deleted(self, event: FileSystemEvent):
        if event.is_directory:
            return
        self._handle_delete(event.src_path)

    def on_moved(self, event: FileSystemEvent):
        if event.is_directory:
            return
        self._handle_move(event.src_path, event.dest_path)

    def _handle_event(self, file_path: str, event_type: str):
        """Handle a create or modify event."""
        abs_path = os.path.abspath(file_path)

        if _should_ignore(abs_path):
            return
        if self._debounce(abs_path):
            return

        session: Session = SessionLocal()
        try:
            directory_cache = {}
            # Wait briefly for file to finish writing
            time.sleep(0.2)

            if not os.path.exists(abs_path):
                return

            try:
                new_hash = calculate_file_hash(abs_path)
                metadata = get_file_metadata(abs_path)
            except (PermissionError, OSError) as e:
                logger.warning(f"Cannot access {abs_path}: {e}")
                return

            record = session.query(FileRecord).filter_by(path=abs_path).first()

            if record is None:
                rename_source = self._find_missing_record_with_platform_id(
                    session, metadata.get('platform_file_id'), abs_path
                )
                if rename_source is None:
                    rename_source = self._find_missing_record_with_hash(session, new_hash, abs_path)
                if rename_source is not None:
                    old_path = rename_source.path
                    self._record_rename(
                        session=session,
                        record=rename_source,
                        old_path=old_path,
                        new_path=abs_path,
                        old_hash=rename_source.hash,
                        new_hash=new_hash,
                        metadata=metadata,
                        directory_cache=directory_cache,
                    )
                    session.commit()
                    logger.info(f"[RENAMED] {old_path} -> {abs_path}")
                    return

                # New file
                record = FileRecord(
                    path=abs_path,
                    hash=new_hash,
                    hash_algorithm=settings.hash_algorithm,
                    fast_hash=new_hash,
                    security_hash_algorithm=settings.security_hash_algorithm,
                    is_baseline=False,
                    mtime=metadata['mtime'] if metadata else None,
                    size=metadata['size'] if metadata else None,
                )
                attach_identity_to_record(
                    session=session,
                    record=record,
                    path=abs_path,
                    metadata=metadata,
                    file_hash=new_hash,
                    fast_hash=new_hash,
                    directory_cache=directory_cache,
                )
                session.add(record)
                registry = _watch_registry_context(
                    session=session,
                    path=abs_path,
                    metadata=metadata,
                    file_hash=new_hash,
                    file_id=record.file_id,
                )
                snippet = _read_snippet(abs_path)
                session.add(FileLog(
                    file_id=record.file_id,
                    path=abs_path,
                    event_type='new',
                    old_hash=None,
                    new_hash=new_hash,
                    details="New file detected (real-time)",
                    status='pending',
                    analysis_json={
                        "diff": snippet,
                        "metadata": metadata,
                        "is_baseline": False,
                        "registry": registry,
                    },
                ))
                session.commit()
                logger.info(f"[NEW] {abs_path}")

            elif record.hash != new_hash:
                # Modified file  -  hash actually changed
                old_hash = record.hash
                snippet = _read_snippet(abs_path)
                attach_identity_to_record(
                    session=session,
                    record=record,
                    path=abs_path,
                    metadata=metadata,
                    file_hash=new_hash,
                    fast_hash=new_hash,
                    security_hash=record.security_hash,
                    directory_cache=directory_cache,
                )
                registry = _watch_registry_context(
                    session=session,
                    path=abs_path,
                    metadata=metadata,
                    file_hash=new_hash,
                    file_id=record.file_id,
                )

                session.add(FileLog(
                    file_id=record.file_id,
                    path=abs_path,
                    event_type='modified',
                    old_hash=old_hash,
                    new_hash=new_hash,
                    details=f"Hash changed: {old_hash[:12]}... -> {new_hash[:12]}...",
                    status='pending',
                    analysis_json={
                        "diff": snippet,
                        "metadata": metadata,
                        "is_baseline": False,
                        "registry": registry,
                    },
                ))

                record.hash = new_hash
                record.fast_hash = new_hash
                record.hash_algorithm = settings.hash_algorithm
                record.last_seen = datetime.utcnow()
                record.mtime = metadata['mtime'] if metadata else None
                record.size = metadata['size'] if metadata else None
                record.is_baseline = False

                session.commit()
                logger.info(f"[MODIFIED] {abs_path}")

        except Exception as e:
            session.rollback()
            logger.error(f"Error handling event for {file_path}: {e}")
        finally:
            session.close()

    def _handle_delete(self, file_path: str):
        """Handle a file delete event."""
        abs_path = os.path.abspath(file_path)

        if _should_ignore(abs_path):
            return
        if self._debounce(abs_path):
            return

        session: Session = SessionLocal()
        try:
            record = session.query(FileRecord).filter_by(path=abs_path).first()
            old_hash = record.hash if record else None
            file_id = record.file_id if record else None
            registry_entry = mark_registry_inactive(session, file_id=file_id, path=abs_path)
            registry = build_registry_context(registry_entry)

            session.add(FileLog(
                file_id=file_id,
                path=abs_path,
                event_type='deleted',
                old_hash=old_hash,
                new_hash=None,
                details="File removed (real-time)",
                status='pending',
                analysis_json={
                    "diff": "File deleted",
                    "metadata": None,
                    "is_baseline": False,
                    "registry": registry,
                },
            ))

            if record:
                if record.file_id is not None:
                    mark_identity_inactive(session.get(FileIdentity, record.file_id))
                session.delete(record)

            session.commit()
            logger.info(f"[DELETED] {abs_path}")

        except Exception as e:
            session.rollback()
            logger.error(f"Error handling delete for {file_path}: {e}")
        finally:
            session.close()

    def _handle_move(self, old_path: str, new_path: str):
        """Handle a file rename/move while preserving the file timeline."""
        old_abs = os.path.abspath(old_path)
        new_abs = os.path.abspath(new_path)

        if _should_ignore(old_abs) or _should_ignore(new_abs):
            return

        now = time.time()
        self._last_event[old_abs] = now
        self._last_event[new_abs] = now

        session: Session = SessionLocal()
        try:
            directory_cache = {}
            time.sleep(0.2)

            if not os.path.exists(new_abs):
                session.close()
                self._handle_delete(old_abs)
                return

            try:
                new_hash = calculate_file_hash(new_abs)
                metadata = get_file_metadata(new_abs)
            except (PermissionError, OSError) as e:
                logger.warning(f"Cannot access moved file {new_abs}: {e}")
                return

            record = session.query(FileRecord).filter_by(path=old_abs).first()

            if record is None:
                # If the old path was not tracked, treat the destination as a new file.
                session.close()
                self._handle_event(new_abs, 'new')
                return

            old_hash = record.hash

            self._record_rename(
                session=session,
                record=record,
                old_path=old_abs,
                new_path=new_abs,
                old_hash=old_hash,
                new_hash=new_hash,
                metadata=metadata,
                directory_cache=directory_cache,
            )

            session.commit()
            logger.info(f"[RENAMED] {old_abs} -> {new_abs}")

        except Exception as e:
            session.rollback()
            logger.error(f"Error handling rename from {old_path} to {new_path}: {e}")
        finally:
            session.close()

    def _find_missing_record_with_hash(
        self,
        session: Session,
        file_hash: str,
        new_path: str,
    ) -> FileRecord | None:
        """Find a tracked same-hash path that disappeared before a create event."""
        matches = (
            session.query(FileRecord)
            .filter(FileRecord.hash == file_hash, FileRecord.path != new_path)
            .order_by(FileRecord.last_seen.desc())
            .all()
        )
        for candidate in matches:
            if not os.path.exists(candidate.path):
                return candidate
        return None

    def _find_missing_record_with_platform_id(
        self,
        session: Session,
        platform_file_id: str | None,
        new_path: str,
    ) -> FileRecord | None:
        """Find a moved tracked file using the OS file identity."""
        identity = find_identity_by_platform_id(session, platform_file_id)
        if identity is None:
            return None
        record = (
            session.query(FileRecord)
            .filter(FileRecord.file_id == identity.id, FileRecord.path != new_path)
            .order_by(FileRecord.last_seen.desc())
            .first()
        )
        if record is None and identity.current_path != new_path:
            record = session.query(FileRecord).filter_by(path=identity.current_path).first()
        if record is not None and not os.path.exists(record.path):
            return record
        return None

    def _record_rename(
        self,
        session: Session,
        record: FileRecord,
        old_path: str,
        new_path: str,
        old_hash: str,
        new_hash: str,
        metadata: dict | None,
        directory_cache: dict | None = None,
    ) -> None:
        """Update path identity and append a rename event."""
        attach_identity_to_record(
            session=session,
            record=record,
            path=new_path,
            metadata=metadata,
            file_hash=new_hash,
            fast_hash=new_hash,
            security_hash=record.security_hash,
            directory_cache=directory_cache,
        )
        session.query(FileLog).filter(FileLog.path == old_path).update(
            {FileLog.path: new_path, FileLog.file_id: record.file_id},
            synchronize_session=False,
        )

        record.path = new_path
        record.hash = new_hash
        record.fast_hash = new_hash
        record.hash_algorithm = settings.hash_algorithm
        record.last_seen = datetime.utcnow()
        record.mtime = metadata['mtime'] if metadata else None
        record.size = metadata['size'] if metadata else None
        record.is_baseline = False
        registry = _watch_registry_context(
            session=session,
            path=new_path,
            metadata=metadata,
            file_hash=new_hash,
            file_id=record.file_id,
        )

        session.add(FileLog(
            file_id=record.file_id,
            path=new_path,
            event_type='renamed',
            old_hash=old_hash,
            new_hash=new_hash,
            details=f"File renamed: {old_path} -> {new_path}",
            status='pending',
            analysis_json={
                "diff": f"File renamed from {old_path} to {new_path}",
                "metadata": metadata,
                "is_baseline": False,
                "previous_path": old_path,
                "new_path": new_path,
                "registry": registry,
            },
        ))


class FileWatcher:
    """Manages the watchdog observer lifecycle."""

    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        self.observer = None
        self._running = False

    def start(self):
        """Start watching the directory."""
        if self._running:
            return

        handler = IntegrityEventHandler()
        self.observer = Observer()
        self.observer.schedule(handler, self.path, recursive=True)
        self.observer.start()
        self._running = True
        logger.info(f"Watcher started: {self.path}")

    def stop(self):
        """Stop watching."""
        if self.observer and self._running:
            self.observer.stop()
            self.observer.join(timeout=5)
            self._running = False
            logger.info("Watcher stopped.")

    @property
    def is_running(self) -> bool:
        return self._running
