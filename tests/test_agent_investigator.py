from core.config import settings
from core.models import FileLog
from core.services.agent_investigator import (
    run_agent_investigation,
    should_run_agent_investigation,
)
from core.services.file_registry import classify_file
from core.services.registry_analyzer import run_mempalace_context_analysis


def test_agent_investigation_runs_for_critical_content(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "agent_investigation_enabled", True)
    monkeypatch.setattr(settings, "agent_investigation_signature_check", False)
    changed = tmp_path / "key.java"
    changed.write_text("GetAsyncKeyState(13);\n", encoding="utf-8")
    registry = classify_file(str(changed), target_os="windows")
    log = FileLog(
        path=str(changed),
        event_type="modified",
        old_hash="old",
        new_hash="new",
        priority="critical",
        risk_score=9,
    )
    analysis = {
        "priority": "critical",
        "risk_score": 9,
        "semantic_role": registry["semantic_role"],
        "mem_palace": {
            "agent_content": {
                "inspected": True,
                "risk_score": 9,
                "priority": "critical",
                "threat_type": "credential_theft",
                "threat_classification": "Agent-Detected Credential Theft",
                "summary": "Agent content inspection found credential theft indicators.",
                "iocs": [],
            },
            "related_memories": [{"metadata": {"source_file": "key.java"}}],
            "memory_status": {"searched": True, "hits": 1},
        },
    }

    report = run_agent_investigation(
        log=log,
        event_context={"metadata": {"is_baseline": False}},
        analysis=analysis,
        content_payload="GetAsyncKeyState(13);",
        registry_context=registry,
    )

    assert report["ran"] is True
    assert report["trusted_change"] == "suspicious"
    assert report["notification_title"].startswith("SEV-1")
    assert any(
        obs["tool"] == "agent_content_inspection" and obs["status"] == "warn"
        for obs in report["observations"]
    )
    assert "agent_content_inspection" in report["tools_used"]


def test_agent_investigation_skips_low_value_event(monkeypatch):
    monkeypatch.setattr(settings, "agent_investigation_enabled", True)
    log = FileLog(
        path=r"C:\Users\dev\AppData\Local\Temp\cache.tmp",
        event_type="modified",
        priority="info",
        risk_score=1,
    )
    should_run, reason = should_run_agent_investigation(
        log=log,
        event_context={"metadata": {"is_baseline": False}},
        analysis={"priority": "info", "risk_score": 1},
        registry_context={"tier": 4, "semantic_role": "temporary_file"},
    )

    assert should_run is False
    assert reason == "below_investigation_threshold"


def test_agent_investigation_batch_budget_skips_noncritical(monkeypatch):
    monkeypatch.setattr(settings, "agent_investigation_enabled", True)
    log = FileLog(
        path=r"C:\Users\dev\project\app.py",
        event_type="modified",
        priority="high",
        risk_score=7,
    )

    should_run, reason = should_run_agent_investigation(
        log=log,
        event_context={"metadata": {"is_baseline": False}},
        analysis={"priority": "high", "risk_score": 7},
        registry_context={"tier": 3, "semantic_role": "source_code"},
        performance_context={
            "pending_depth": 25,
            "investigations_used": 1,
            "max_per_batch": 1,
        },
    )

    assert should_run is False
    assert reason == "performance_batch_budget_exhausted"


def test_agent_investigation_backlog_guard_skips_noncritical(monkeypatch):
    monkeypatch.setattr(settings, "agent_investigation_enabled", True)
    log = FileLog(
        path=r"C:\Users\dev\service\config.yml",
        event_type="modified",
        priority="high",
        risk_score=7,
    )

    should_run, reason = should_run_agent_investigation(
        log=log,
        event_context={"metadata": {"is_baseline": False}},
        analysis={"priority": "high", "risk_score": 7},
        registry_context={"tier": 2, "semantic_role": "service_configuration"},
        performance_context={
            "pending_depth": 1000,
            "backlog_threshold": 500,
            "backlog_critical_only": True,
        },
    )

    assert should_run is False
    assert reason == "performance_backlog_guard"


def test_agent_investigation_budget_still_allows_critical(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "agent_investigation_enabled", True)
    monkeypatch.setattr(settings, "agent_investigation_signature_check", False)
    changed = tmp_path / "sudoers"
    changed.write_text("root ALL=(ALL:ALL) ALL\n", encoding="utf-8")
    log = FileLog(
        path=str(changed),
        event_type="modified",
        old_hash="old",
        new_hash="new",
        priority="critical",
        risk_score=9,
    )

    report = run_agent_investigation(
        log=log,
        event_context={"metadata": {"is_baseline": False}},
        analysis={"priority": "critical", "risk_score": 9},
        content_payload="root ALL=(ALL:ALL) ALL\n",
        registry_context={"tier": 1, "semantic_role": "privilege_policy"},
        performance_context={
            "pending_depth": 1000,
            "investigations_used": 99,
            "max_per_batch": 1,
            "backlog_threshold": 500,
            "backlog_critical_only": True,
        },
    )

    assert report["ran"] is True
    assert report["reason"] == "critical_priority_event"


def test_agent_investigation_confirms_package_manager_source(monkeypatch):
    monkeypatch.setattr(settings, "agent_investigation_enabled", True)
    monkeypatch.setattr(settings, "agent_investigation_signature_check", False)
    log = FileLog(
        path="/etc/sudoers",
        event_type="modified",
        old_hash="old",
        new_hash="new",
        priority="critical",
        risk_score=9,
    )
    registry = classify_file("/etc/sudoers", target_os="linux")

    report = run_agent_investigation(
        log=log,
        event_context={"metadata": {"is_baseline": False, "package_manager": "apt"}},
        analysis={"priority": "critical", "risk_score": 9},
        content_payload="# sudoers changed\n",
        registry_context=registry,
    )

    assert report["ran"] is True
    assert report["trusted_change"] == "confirmed"
    assert "package_manager:apt" in report["trusted_change_sources"]


def test_mempalace_context_analysis_attaches_agent_investigation(monkeypatch):
    monkeypatch.setattr(settings, "agent_investigation_enabled", True)
    monkeypatch.setattr(settings, "agent_investigation_signature_check", False)
    log = FileLog(
        file_id=202,
        path="/etc/sudoers",
        event_type="modified",
        old_hash="old",
        new_hash="new",
        priority="pending",
        risk_score=None,
    )
    registry = classify_file("/etc/sudoers", target_os="linux")
    analysis = {
        "risk_score": 1,
        "priority": "info",
        "threat_type": "benign",
        "analysis_source": "heuristic",
        "reasoning": "Pipeline verdict was low risk.",
        "findings": [],
        "recommended_actions": [],
        "registry": registry,
    }

    merged = run_mempalace_context_analysis(
        log=log,
        event_context={"metadata": {"is_baseline": False, "registry": registry}},
        content_payload="# sudoers changed\n",
        content_analysis=analysis,
    )

    assert merged["priority"] == "critical"
    assert merged["agent_investigation"]["ran"] is True
    assert merged["agent_investigation"]["trusted_change"] == "suspicious"
    assert merged["agent_notification"]["summary"]
    assert "agent_investigation" in merged["analysis_source"]
