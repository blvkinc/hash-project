"""
test_provider_chain.py — verify the Ollama -> Gemini -> heuristic fallback
order in core.llm_analyzer.analyze_file_change.

Uses mock to intercept HTTP calls so the test doesn't depend on a live
Ollama or Gemini endpoint.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest import mock

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from core import llm_analyzer
from core.config import settings


@pytest.fixture
def _reset_settings():
    """Snapshot + restore the settings fields the tests mutate."""
    saved = (settings.gemini_api_key, settings.ollama_model)
    try:
        yield
    finally:
        settings.gemini_api_key, settings.ollama_model = saved


def _ollama_response(payload: dict):
    """Build a fake requests.Response wrapping the given inner-JSON dict."""
    fake = mock.Mock()
    fake.status_code = 200
    fake.json.return_value = {"response": json.dumps(payload)}
    return fake


def test_ollama_success_short_circuits(_reset_settings):
    """When Ollama returns a parseable analysis, Gemini must not be called."""
    settings.gemini_api_key = "anything-non-empty"  # would otherwise trigger Gemini

    ollama_payload = {
        "risk_score": 9,
        "priority": "critical",
        "is_malicious": True,
        "threat_type": "reverse_shell",
        "reasoning": "looks bad",
    }

    with mock.patch.object(llm_analyzer.requests, "post",
                           return_value=_ollama_response(ollama_payload)) as ollama_post, \
         mock.patch("core.services.gemini_client.analyze_with_gemini") as gemini_call:
        result = llm_analyzer.analyze_file_change(
            "/tmp/evil.sh", "modified", diff="cat /etc/shadow", metadata={},
        )

    assert result["analysis_source"] == "ollama"
    assert result["risk_score"] == 9
    assert result["priority"] == "critical"
    ollama_post.assert_called_once()
    gemini_call.assert_not_called()


def test_gemini_used_when_ollama_unreachable(_reset_settings):
    """Connection error on Ollama -> Gemini is consulted -> its analysis wins."""
    settings.gemini_api_key = "test-key"

    gemini_payload = {
        "risk_score": 8,
        "priority": "high",
        "is_malicious": True,
        "threat_type": "credential_theft",
        "reasoning": "gemini took over",
    }

    import requests as _rq
    with mock.patch.object(llm_analyzer.requests, "post",
                           side_effect=_rq.ConnectionError("ollama down")), \
         mock.patch("core.services.gemini_client.analyze_with_gemini",
                    return_value=gemini_payload) as gemini_call:
        result = llm_analyzer.analyze_file_change(
            "/tmp/x", "modified", diff="x = 1", metadata={},
        )

    assert result["analysis_source"] == "gemini"
    assert result["priority"] == "high"
    gemini_call.assert_called_once()


def test_gemini_skipped_when_key_unset(_reset_settings):
    """Without GEMINI_API_KEY, the chain skips Gemini and lands on heuristic."""
    settings.gemini_api_key = ""

    import requests as _rq
    with mock.patch.object(llm_analyzer.requests, "post",
                           side_effect=_rq.ConnectionError("ollama down")), \
         mock.patch("core.services.gemini_client.analyze_with_gemini") as gemini_call:
        result = llm_analyzer.analyze_file_change(
            "/tmp/y", "modified", diff="benign\n", metadata={},
        )

    # _fallback_analysis sets its own analysis_source — assert we didn't hit Gemini
    # and we still got a structured analysis dict.
    gemini_call.assert_not_called()
    assert "risk_score" in result
    assert "priority" in result


def test_invalid_ollama_json_falls_to_gemini(_reset_settings):
    """Ollama 200 but body isn't valid JSON -> Gemini takes over."""
    settings.gemini_api_key = "test-key"

    fake = mock.Mock()
    fake.status_code = 200
    fake.json.return_value = {"response": "not-json{{{"}

    gemini_payload = {
        "risk_score": 4, "priority": "medium",
        "is_malicious": False, "threat_type": "benign",
        "reasoning": "rescued by gemini",
    }

    with mock.patch.object(llm_analyzer.requests, "post", return_value=fake), \
         mock.patch("core.services.gemini_client.analyze_with_gemini",
                    return_value=gemini_payload):
        result = llm_analyzer.analyze_file_change(
            "/tmp/z", "modified", diff="...", metadata={},
        )

    assert result["analysis_source"] == "gemini"
    assert result["priority"] == "medium"
