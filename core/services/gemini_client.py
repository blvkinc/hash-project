"""REST-only Gemini API client used as fallback for Ollama.

Kept dependency-free (plain `requests`) so the project doesn't have to pull
the full google-genai SDK. Mirrors the JSON contract that llm_analyzer
expects so the orchestrator can hand the result straight to the same
post-processing path used for Ollama responses.

Returns None on any failure (no API key, HTTP error, invalid JSON,
network problem); the caller is responsible for falling back further.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

import requests

from core.config import settings

logger = logging.getLogger(__name__)


def analyze_with_gemini(prompt_text: str) -> Optional[Dict[str, Any]]:
    """
    Send the same prompt we'd send Ollama to Gemini and return the
    parsed JSON analysis dict, or None on any failure.
    """
    api_key = settings.gemini_api_key
    if not api_key:
        return None

    model = settings.gemini_model
    base_url = settings.gemini_url.rstrip("/")
    url = f"{base_url}/{model}:generateContent"

    payload = {
        "contents": [{"parts": [{"text": prompt_text}]}],
        # Forces the model to emit raw JSON (no ```json fences).
        "generationConfig": {
            "responseMimeType": "application/json",
            "temperature": 0.1,
        },
    }

    try:
        resp = requests.post(
            url,
            json=payload,
            params={"key": api_key},
            timeout=settings.gemini_timeout,
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code != 200:
            logger.warning(
                "Gemini returned HTTP %s: %s",
                resp.status_code, resp.text[:200],
            )
            return None

        body = resp.json()
    except (requests.RequestException, ValueError) as exc:
        logger.warning("Gemini request failed: %s", exc)
        return None

    text = _extract_text(body)
    if not text:
        logger.warning("Gemini returned no text candidate.")
        return None

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Strip ```json fences in case the model emits them anyway.
        if "```" in text:
            chunk = text.split("```", 2)
            if len(chunk) >= 2:
                stripped = chunk[1].lstrip("json").strip()
                try:
                    return json.loads(stripped)
                except json.JSONDecodeError:
                    pass
        logger.warning("Gemini returned non-JSON body: %s", text[:200])
        return None


def _extract_text(body: Dict[str, Any]) -> str:
    """Pull the first text part out of a Gemini generateContent response."""
    candidates = body.get("candidates") or []
    for candidate in candidates:
        content = candidate.get("content") or {}
        for part in content.get("parts") or []:
            text = part.get("text")
            if isinstance(text, str) and text.strip():
                return text
    return ""
