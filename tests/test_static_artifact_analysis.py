"""Regression coverage for source and executable baseline analysis."""
from pathlib import Path
from unittest.mock import MagicMock

from core import background_analysis
from core.file_content import read_analysis_snippet, read_text_snippet
from core import llm_analyzer
from core.llm_analyzer import _fallback_analysis
from core.scanner import _should_queue_deferred_baseline_analysis


REMOTE_CONTROL_SOURCE = """
const wchar_t* host = L"api.telegram.org";
const wchar_t* poll = L"/bot/token/getUpdates";
const wchar_t* reply = L"/bot/token/sendMessage";
const char* action = "/shell ";
const char* command = "cmd.exe /c whoami";
CreateProcessA(nullptr, command, nullptr, nullptr, true, CREATE_NO_WINDOW,
               nullptr, nullptr, nullptr, nullptr);
"""


def test_analysis_reads_ranked_static_strings_without_loading_binary(tmp_path: Path):
    artifact = tmp_path / "vite.exe"
    artifact.write_bytes(
        b"MZ\x00\x00ordinary\x00"
        + "api.telegram.org".encode("utf-16le")
        + b"\x00\x00/getUpdates\x00/sendMessage\x00/shell \x00"
        + b"cmd.exe /c whoami\x00CreateProcessA\x00CREATE_NO_WINDOW\x00"
    )

    assert read_text_snippet(str(artifact)) == "Binary/Unreadable"

    evidence = read_analysis_snippet(str(artifact))
    assert evidence.startswith("[Static binary evidence; file was not executed]")
    assert "format=PE" in evidence
    assert "api.telegram.org" in evidence
    assert "cmd.exe /c whoami" in evidence


def test_corroborated_remote_control_chain_is_critical_after_first_5kb():
    content = "int harmless = 1;\n" * 500 + REMOTE_CONTROL_SOURCE

    analysis = _fallback_analysis(
        "src/assets/vite.cpp",
        "new",
        content,
        metadata={"is_baseline": True},
    )

    assert analysis["priority"] == "critical"
    assert analysis["risk_score"] == 10
    assert analysis["threat_type"] == "rat"


def test_hash_first_baseline_queues_cpp_and_executable_artifacts():
    metadata = {"size": 24_000}

    assert _should_queue_deferred_baseline_analysis(
        "src/assets/vite.cpp", metadata, queued_so_far=0, deferred_limit=100
    )
    assert _should_queue_deferred_baseline_analysis(
        "src/assets/vite.exe",
        {"size": 20_000_000},
        queued_so_far=0,
        deferred_limit=100,
    )


def test_registry_tier_prevents_generic_path_downgrade():
    log = MagicMock()
    log.path = r"C:\Users\alice\project\src\assets\vite.exe"
    log.event_type = "new"

    result = background_analysis._apply_tier_prefilter(
        log,
        registry_context={
            "tier": 3,
            "semantic_role": "executable_or_library",
        },
    )

    assert result is None


def test_confirmed_attack_chain_cannot_be_downgraded_to_benign(monkeypatch):
    monkeypatch.setattr(
        llm_analyzer,
        "_call_ollama",
        lambda _prompt: {
            "risk_score": 1,
            "priority": "info",
            "is_malicious": False,
            "threat_type": "benign",
            "reasoning": "No risk found.",
        },
    )

    analysis = llm_analyzer.analyze_file_change(
        "src/assets/vite.cpp",
        "new",
        REMOTE_CONTROL_SOURCE,
        metadata={"is_baseline": True},
    )

    assert analysis["risk_score"] == 10
    assert analysis["priority"] == "critical"
    assert analysis["threat_type"] == "rat"
    assert analysis["analysis_source"] == "ollama+heuristic_floor"
    assert analysis["model_assessment"]["risk_score"] == 1


def test_confirmed_attack_chain_replaces_unsupported_model_classification(monkeypatch):
    monkeypatch.setattr(
        llm_analyzer,
        "_call_ollama",
        lambda _prompt: {
            "risk_score": 10,
            "priority": "critical",
            "is_malicious": True,
            "threat_type": "reverse_shell",
            "reasoning": "Uses an OpenSSL tunnel.",
        },
    )

    analysis = llm_analyzer.analyze_file_change(
        "src/assets/vite.exe",
        "new",
        REMOTE_CONTROL_SOURCE,
        metadata={"is_baseline": True},
    )

    assert analysis["risk_score"] == 10
    assert analysis["threat_type"] == "rat"
    assert analysis["analysis_source"] == "ollama+heuristic_floor"
    assert "OpenSSL tunnel" not in analysis["reasoning"]


def test_model_threat_labels_are_canonicalized_before_comparison(monkeypatch):
    monkeypatch.setattr(
        llm_analyzer,
        "_call_ollama",
        lambda _prompt: {
            "risk_score": 10,
            "priority": "critical",
            "is_malicious": True,
            "threat_type": "RAT",
            "reasoning": "Observed remote command dispatch and shell execution.",
        },
    )

    analysis = llm_analyzer.analyze_file_change(
        "src/assets/vite.cpp",
        "new",
        REMOTE_CONTROL_SOURCE,
        metadata={"is_baseline": True},
    )

    assert analysis["threat_type"] == "rat"
    assert analysis["analysis_source"] == "ollama"
    assert "model proposed" not in analysis["reasoning"]
