"""Preferred-model auto-selection for the local Ollama server.

Picks qwen2.5-coder when available, then mistral; runs a small benchmark
to choose between them when both are installed; otherwise falls back to
llama3.2 / phi3. Honours OLLAMA_MODEL when explicitly set to something
outside the competitor set.
"""
import logging
import os
import time
from typing import List, Optional

import requests

from core.config import settings

logger = logging.getLogger(__name__)


def ollama_base_url() -> str:
    generate_url = settings.ollama_url
    if "/api/" in generate_url:
        return generate_url.split("/api/", 1)[0]
    return generate_url.rsplit("/", 1)[0]


def list_ollama_models(base_url: str) -> List[str]:
    try:
        resp = requests.get(f"{base_url.rstrip('/')}/api/tags", timeout=3)
        if resp.status_code != 200:
            return []
        payload = resp.json() if resp.content else {}
        models = payload.get("models", []) if isinstance(payload, dict) else []
        names = []
        for m in models:
            if isinstance(m, dict) and m.get("name"):
                names.append(str(m["name"]))
        return names
    except Exception:
        return []


def find_model_by_prefix(models: List[str], prefixes: List[str]) -> Optional[str]:
    lower_map = {m.lower(): m for m in models}

    for prefix in prefixes:
        if prefix.lower() in lower_map:
            return lower_map[prefix.lower()]

    for model in models:
        lm = model.lower()
        for prefix in prefixes:
            lp = prefix.lower()
            if lm == lp or lm.startswith(lp + ":"):
                return model
    return None


def benchmark_ollama_model(base_url: str, model: str) -> Optional[float]:
    test_payload = {
        "model": model,
        "prompt": (
            "Return valid JSON only: "
            "{\"risk_score\":0,\"priority\":\"info\","
            "\"is_malicious\":false,\"reasoning\":\"ok\"}"
        ),
        "stream": False,
        "format": "json",
    }
    try:
        start = time.perf_counter()
        resp = requests.post(f"{base_url.rstrip('/')}/api/generate", json=test_payload, timeout=25)
        if resp.status_code != 200:
            return None
        _ = resp.json()
        return time.perf_counter() - start
    except Exception:
        return None


def configure_preferred_ollama_model() -> None:
    """
    Decide which local Ollama model to use at startup.

    Preference order when OLLAMA_MODEL is empty:
        gemma4 > gemma3 > gemma2 > qwen2.5-coder > mistral > llama3.2 > phi3

    When both qwen2.5-coder and mistral are installed (and no gemma is),
    run a small benchmark and pick the faster one. Any explicit
    OLLAMA_MODEL outside the qwen / mistral competitor set is honoured.
    """
    explicit = (settings.ollama_model or "").strip()
    base_url = ollama_base_url()
    models = list_ollama_models(base_url)

    explicit_lower = explicit.lower()
    explicit_is_competitor = (
        explicit_lower.startswith("qwen2.5-coder")
        or explicit_lower.startswith("mistral")
    )

    if explicit and not explicit_is_competitor:
        logger.info(f"Using OLLAMA_MODEL from environment: {explicit}")
        os.environ["OLLAMA_MODEL"] = explicit
        settings.ollama_model = explicit
        return

    # Gemma family takes top priority for auto-selection.
    gemma = find_model_by_prefix(models, [
        "gemma4:latest", "gemma4", "gemma3:12b", "gemma3:4b", "gemma3",
        "gemma2:9b", "gemma2", "gemma:7b", "gemma",
    ])
    if gemma:
        os.environ["OLLAMA_MODEL"] = gemma
        settings.ollama_model = gemma
        logger.info(f"Configured OLLAMA_MODEL={gemma} (gemma family preferred)")
        return

    qwen = find_model_by_prefix(models, ["qwen2.5-coder:7b", "qwen2.5-coder"])
    mistral = find_model_by_prefix(models, ["mistral:7b", "mistral"])

    if explicit and explicit_is_competitor:
        logger.info(f"Evaluating qwen2.5-coder vs mistral (current env model: {explicit})")
        if explicit_lower.startswith("qwen2.5-coder") and not qwen:
            qwen = explicit
        if explicit_lower.startswith("mistral") and not mistral:
            mistral = explicit

    selected = None
    if qwen and mistral:
        q_time = benchmark_ollama_model(base_url, qwen)
        m_time = benchmark_ollama_model(base_url, mistral)

        if q_time is not None and m_time is not None:
            selected = qwen if q_time <= m_time else mistral
            logger.info(
                f"Ollama benchmark: {qwen}={q_time:.2f}s, "
                f"{mistral}={m_time:.2f}s; selected {selected}"
            )
        elif q_time is not None:
            selected = qwen
        elif m_time is not None:
            selected = mistral
    elif qwen:
        selected = qwen
    elif mistral:
        selected = mistral

    if not selected:
        selected = find_model_by_prefix(models, ["llama3.2", "llama3", "phi3", "phi"])

    if selected:
        os.environ["OLLAMA_MODEL"] = selected
        settings.ollama_model = selected
        logger.info(f"Configured OLLAMA_MODEL={selected}")
