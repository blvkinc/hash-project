"""Tests for context-aware change payload parsing and scoring."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.background_analysis import (
    _attach_event_context,
    _build_change_summary,
    _build_contextual_payload,
    _latest_previous_snippet,
)
from core.llm_analyzer import _extract_active_scan_content, _fallback_analysis
from core.models import Base, FileLog


def test_build_contextual_payload_for_modified_contains_diff_markers():
    before = "import os\nos.system('id')\n"
    after = "import os\nprint('safe')\n"

    payload = _build_contextual_payload("app/main.py", "modified", after, before)

    assert "=== PREVIOUS CONTENT (snippet) ===" in payload
    assert "=== CURRENT CONTENT (snippet) ===" in payload
    assert "=== UNIFIED DIFF (before -> after) ===" in payload


def test_extract_active_content_uses_current_and_added_lines_only():
    before = "import os\nos.system('id')\n"
    after = "import os\nprint('safe')\n"
    payload = _build_contextual_payload("app/main.py", "modified", after, before)

    active = _extract_active_scan_content(payload)

    assert "print('safe')" in active
    assert "os.system('id')" not in active


def test_removed_malicious_line_is_not_scored_as_active_threat():
    before = "import os\nos.system('id')\n"
    after = "import os\nprint('safe')\n"
    payload = _build_contextual_payload("app/main.py", "modified", after, before)

    result = _fallback_analysis("app/main.py", "modified", payload)

    assert result["is_malicious"] is False
    assert result["risk_score"] <= 6


def test_non_modified_payload_passthrough():
    content = "echo hello"
    payload = _build_contextual_payload("scripts/new.sh", "new", content, None)
    assert payload == content


def test_analyzed_logs_keep_snippet_for_future_diff():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        previous = FileLog(
            path="app/main.py",
            event_type="new",
            status="analyzed",
            analysis_json={
                "risk_score": 1,
                "priority": "info",
                "event_context": {"diff": "version = 1\n"},
            },
        )
        current = FileLog(
            path="app/main.py",
            event_type="modified",
            status="pending",
            analysis_json={"diff": "version = 2\n"},
        )
        session.add_all([previous, current])
        session.commit()

        assert _latest_previous_snippet(session, "app/main.py", current.id) == "version = 1\n"
    finally:
        session.close()


def test_attach_event_context_preserves_change_summary():
    before = "enabled = false\n"
    after = "enabled = true\n"
    payload = _build_contextual_payload("app/settings.ini", "modified", after, before)
    summary = _build_change_summary("modified", after, before)

    merged = _attach_event_context(
        {"risk_score": 3, "priority": "low"},
        {"diff": after, "metadata": {"size": len(after)}},
        payload,
        before,
        summary,
    )

    assert merged["event_context"]["diff"] == after
    assert merged["event_context"]["previous_snippet_available"] is True
    assert merged["change_summary"]["added_lines"] == 1
