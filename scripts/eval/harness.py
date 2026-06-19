"""
harness.py  -  isolated test bed for the FIM analysis pipeline.

Provides a single class (`EvalHarness`) that:
  - sets up an isolated sqlite DB in a temp directory,
  - exposes the same scanner / background_analysis / notification_dispatcher
    primitives the production server uses,
  - records every dispatched notification so the runner can compute
    Notification Reduction Ratio, TPR, FNR.

Designed to be imported by scenario modules. Not a pytest test itself.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import sqlalchemy
from sqlalchemy.orm import sessionmaker

# Project root on sys.path so `from core...` works when run as a script.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


@dataclass
class DispatchRecord:
    """One row captured from NotificationDispatcher._record_history."""
    path: str
    priority: str
    risk_score: int
    dispatch_type: str   # 'immediate' | 'batch_digest' | 'escalated_batch' | 'silent_log'


@dataclass
class HarnessResult:
    """Outcome of one scenario run."""
    name: str
    changes_detected: int           # total FileLog events created
    notifications_immediate: int    # priority critical/high
    notifications_batched: int      # priority medium
    notifications_silent: int       # priority low/info
    dispatches: List[DispatchRecord] = field(default_factory=list)

    @property
    def total_notifications(self) -> int:
        return self.notifications_immediate + self.notifications_batched

    @property
    def notification_reduction_ratio(self) -> float:
        """1 - (alerts surfaced to the user / total changes detected)."""
        if self.changes_detected == 0:
            return 0.0
        return 1.0 - (self.total_notifications / self.changes_detected)


class EvalHarness:
    """
    Manages an isolated FIM pipeline against a temp DB.

    Usage:
        with EvalHarness("legit_bulk_update") as h:
            h.scan(h.workdir)               # baseline
            ...mutate files...
            h.scan(h.workdir)               # detect changes
            h.process_pending(batch_size=100)
            result = h.snapshot()
    """

    def __init__(self, name: str):
        self.name = name
        self._tmp = Path(tempfile.mkdtemp(prefix=f"hashmon-eval-{name}-"))
        self.workdir = self._tmp / "target"
        self.workdir.mkdir(parents=True, exist_ok=True)

        # --- Patch core.database BEFORE importing scanner / background_analysis ---
        from core import database as _db
        self._db = _db
        engine = sqlalchemy.create_engine(
            f"sqlite:///{self._tmp / 'eval.db'}",
            connect_args={"check_same_thread": False},
        )
        _db.engine = engine
        _db.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        _db.DATABASE_PATH = str(self._tmp / "eval.db")
        _db.DATABASE_URL = f"sqlite:///{self._tmp / 'eval.db'}"
        _db.init_db()

        # Late imports  -  they pick up the patched SessionLocal.
        from core import scanner, background_analysis
        scanner.SessionLocal = _db.SessionLocal
        background_analysis.SessionLocal = _db.SessionLocal
        self._scanner = scanner
        self._ba = background_analysis

        # Replace the global dispatcher with a fresh one whose history we own.
        from core.notification_dispatcher import NotificationDispatcher
        self._ba.dispatcher = NotificationDispatcher()
        self._dispatcher = self._ba.dispatcher

    # Lifecycle

    def __enter__(self) -> "EvalHarness":
        return self

    def __exit__(self, exc_type, exc, tb):
        self.cleanup()

    def cleanup(self) -> None:
        try:
            shutil.rmtree(self._tmp)
        except OSError:
            pass

    # Operations

    def write(self, relpath: str, content: str) -> Path:
        """Write a file under the work dir."""
        p = self.workdir / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding='utf-8')
        return p

    def delete(self, relpath: str) -> None:
        (self.workdir / relpath).unlink(missing_ok=True)

    def scan(self, path: Optional[Path] = None) -> Dict[str, Any]:
        """Run scan_and_baseline + compare_and_log for the target dir."""
        target = str(path or self.workdir)
        self._scanner.scan_and_baseline(target)
        return self._scanner.compare_and_log(target)

    def process_pending(self, batch_size: int = 100) -> int:
        """Drain the pending-analysis queue. Returns events processed."""
        # Mark workdir as actively watched so Tier 1/2 suppression doesn't fire
        # if the scenario placed files at sensitive paths.
        self._ba.update_monitor_state(True, [str(self.workdir)])
        return self._ba.process_pending_analysis(batch_size=batch_size)

    # Inspection

    def snapshot(self) -> HarnessResult:
        from core.models import FileLog
        session = self._db.SessionLocal()
        try:
            logs = session.query(FileLog).all()
            total = len(logs)
            immediate = sum(1 for l in logs if l.priority in ('critical', 'high'))
            batched = sum(1 for l in logs if l.priority == 'medium')
            silent = sum(1 for l in logs if l.priority in ('low', 'info'))
        finally:
            session.close()

        dispatches = [
            DispatchRecord(
                path=h.get('path', ''),
                priority=h.get('priority', ''),
                risk_score=int(h.get('risk_score') or 0),
                dispatch_type=h.get('dispatch_type', ''),
            )
            for h in self._dispatcher.get_history(limit=10_000)
        ]

        return HarnessResult(
            name=self.name,
            changes_detected=total,
            notifications_immediate=immediate,
            notifications_batched=batched,
            notifications_silent=silent,
            dispatches=dispatches,
        )
