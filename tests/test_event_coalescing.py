"""Tests for pending event coalescing by file identity."""
import os
import sys
from unittest import mock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core import background_analysis
from core.background_analysis import _latest_previous_snippet, coalesce_pending_events
from core.models import Base, FileLog


def _session_factory():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def test_coalesces_duplicate_pending_modified_events_by_file_id():
    Session = _session_factory()
    session = Session()
    try:
        rows = [
            FileLog(
                file_id=42,
                path="Z:/project/app.py",
                event_type="modified",
                old_hash="old",
                new_hash=f"new-{idx}",
                status="pending",
                analysis_json={"diff": f"value = {idx}\n", "metadata": {"is_baseline": False}},
            )
            for idx in range(3)
        ]
        session.add_all(rows)
        session.commit()

        coalesced = coalesce_pending_events(session, window_seconds=120)
        assert coalesced == 2

        refreshed = session.query(FileLog).order_by(FileLog.id).all()
        assert [row.status for row in refreshed] == ["ignored", "ignored", "pending"]
        assert refreshed[0].analysis_json["coalesced_into"] == refreshed[-1].id
        assert refreshed[1].analysis_json["coalesced"] is True
    finally:
        session.close()


def test_coalesced_rows_are_not_used_as_previous_snippet():
    Session = _session_factory()
    session = Session()
    try:
        baseline = FileLog(
            file_id=7,
            path="Z:/project/app.py",
            event_type="new",
            status="analyzed",
            analysis_json={"event_context": {"diff": "baseline\n"}},
        )
        old_pending = FileLog(
            file_id=7,
            path="Z:/project/app.py",
            event_type="modified",
            old_hash="base",
            new_hash="mid",
            status="pending",
            analysis_json={"diff": "intermediate\n", "metadata": {"is_baseline": False}},
        )
        latest = FileLog(
            file_id=7,
            path="Z:/project/app.py",
            event_type="modified",
            old_hash="mid",
            new_hash="latest",
            status="pending",
            analysis_json={"diff": "latest\n", "metadata": {"is_baseline": False}},
        )
        session.add_all([baseline, old_pending, latest])
        session.commit()

        coalesce_pending_events(session, window_seconds=120)

        assert _latest_previous_snippet(
            session, "Z:/project/app.py", latest.id, latest.file_id
        ) == "baseline\n"
    finally:
        session.close()


def test_coalescing_does_not_merge_different_event_types():
    Session = _session_factory()
    session = Session()
    try:
        session.add_all([
            FileLog(
                file_id=9,
                path="Z:/project/app.py",
                event_type="new",
                new_hash="new",
                status="pending",
                analysis_json={"diff": "created\n", "metadata": {"is_baseline": False}},
            ),
            FileLog(
                file_id=9,
                path="Z:/project/app.py",
                event_type="modified",
                old_hash="new",
                new_hash="mod",
                status="pending",
                analysis_json={"diff": "modified\n", "metadata": {"is_baseline": False}},
            ),
        ])
        session.commit()

        coalesced = coalesce_pending_events(session, window_seconds=120)
        statuses = [row.status for row in session.query(FileLog).order_by(FileLog.id)]
        assert coalesced == 0
        assert statuses == ["pending", "pending"]
    finally:
        session.close()


def test_process_pending_analysis_only_analyzes_latest_coalesced_event():
    Session = _session_factory()
    session = Session()
    try:
        for idx in range(3):
            session.add(FileLog(
                file_id=55,
                path="Z:/project/app.py",
                event_type="modified",
                old_hash=f"old-{idx}",
                new_hash=f"new-{idx}",
                status="pending",
                analysis_json={"diff": f"value = {idx}\n", "metadata": {"is_baseline": False}},
            ))
        session.commit()
    finally:
        session.close()

    calls = []

    def fake_analyze(file_path, change_type, diff, metadata):
        calls.append(diff)
        return {
            "risk_score": 2,
            "priority": "low",
            "is_malicious": False,
            "reasoning": "Latest event analyzed.",
            "analysis_source": "test",
        }

    with mock.patch.object(background_analysis, "SessionLocal", Session), \
            mock.patch.object(background_analysis, "analyze_file_change", side_effect=fake_analyze):
        processed = background_analysis.process_pending_analysis(batch_size=10)

    assert processed == 1
    assert len(calls) == 1

    session = Session()
    try:
        statuses = [row.status for row in session.query(FileLog).order_by(FileLog.id)]
        assert statuses == ["ignored", "ignored", "analyzed"]
    finally:
        session.close()
