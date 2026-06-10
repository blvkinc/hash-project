"""Tests for content/context analysis caching."""
import os
import sys
from unittest import mock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core import background_analysis
from core.models import AnalysisCache, Base, FileLog


def _session_factory():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def test_stage_b_reuses_cached_analysis_for_duplicate_content():
    Session = _session_factory()
    session = Session()
    try:
        for path in ("Z:/project/a.py", "Z:/project/b.py"):
            session.add(FileLog(
                path=path,
                event_type="new",
                new_hash="same-content-hash",
                status="pending",
                analysis_json={
                    "diff": "print('hello')\n",
                    "metadata": {"is_baseline": False, "file_category": "unknown"},
                },
            ))
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
            "reasoning": "Duplicate benign content.",
            "analysis_source": "test",
        }

    with mock.patch.object(background_analysis, "SessionLocal", Session), \
            mock.patch.object(background_analysis, "analyze_file_change", side_effect=fake_analyze):
        processed = background_analysis.process_pending_analysis(batch_size=10)

    assert processed == 2
    assert len(calls) == 1

    session = Session()
    try:
        rows = session.query(FileLog).order_by(FileLog.id).all()
        assert [row.status for row in rows] == ["analyzed", "analyzed"]
        assert rows[0].analysis_json.get("analysis_cache_hit") in (None, False)
        assert rows[1].analysis_json["analysis_cache_hit"] is True
        assert rows[1].analysis_json["event_context"]["diff"] == "print('hello')\n"

        cache = session.query(AnalysisCache).first()
        assert cache is not None
        assert cache.hit_count == 1
    finally:
        session.close()


def test_modified_cache_key_includes_change_context():
    Session = _session_factory()
    session = Session()
    try:
        session.add_all([
            FileLog(
                path="Z:/project/app.py",
                event_type="new",
                new_hash="before",
                status="analyzed",
                analysis_json={"event_context": {"diff": "value = 1\n"}},
            ),
            FileLog(
                path="Z:/project/app.py",
                event_type="modified",
                old_hash="before",
                new_hash="after",
                status="pending",
                analysis_json={"diff": "value = 2\n", "metadata": {"is_baseline": False}},
            ),
            FileLog(
                path="Z:/project/other.py",
                event_type="new",
                new_hash="different-before",
                status="analyzed",
                analysis_json={"event_context": {"diff": "enabled = false\n"}},
            ),
            FileLog(
                path="Z:/project/other.py",
                event_type="modified",
                old_hash="different-before",
                new_hash="after",
                status="pending",
                analysis_json={"diff": "value = 2\n", "metadata": {"is_baseline": False}},
            ),
        ])
        session.commit()
    finally:
        session.close()

    calls = []

    def fake_analyze(file_path, change_type, diff, metadata):
        calls.append((file_path, diff))
        return {
            "risk_score": 2,
            "priority": "low",
            "is_malicious": False,
            "reasoning": "Context-specific modified content.",
            "analysis_source": "test",
        }

    with mock.patch.object(background_analysis, "SessionLocal", Session), \
            mock.patch.object(background_analysis, "analyze_file_change", side_effect=fake_analyze):
        processed = background_analysis.process_pending_analysis(batch_size=10)

    assert processed == 2
    assert len(calls) == 2
