"""Embedded file-intelligence agent backed by real MemPalace memory.

The deterministic/LLM reasoning stays inside this app, while durable memory
storage and related-memory retrieval are delegated to the actual ``mempalace``
package through ``core.services.mempalace_bridge``.
"""
from __future__ import annotations

import json
import re
from typing import Any, Literal

import requests
from pydantic import BaseModel, Field, ValidationError

from core.config import settings


Priority = Literal["critical", "high", "medium", "low", "info"]

PRIORITY_BY_SCORE = [
    (9, "critical"),
    (7, "high"),
    (4, "medium"),
    (2, "low"),
    (0, "info"),
]


AGENT_CONTENT_PATTERNS: list[tuple[re.Pattern, str, int, str]] = [
    (re.compile(r"bash\s+-i\s+>&\s*/dev/tcp/|/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+", re.I), "reverse_shell", 10, "Unix reverse shell over /dev/tcp"),
    (re.compile(r"New-Object\s+System\.Net\.Sockets\.TCPClient|TCPClient\s*\(", re.I), "reverse_shell", 10, "PowerShell/.NET TCP client shell pattern"),
    (re.compile(r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\(", re.I), "suspicious_exec", 8, "Java process execution primitive"),
    (re.compile(r"GetAsyncKeyState|SetWindowsHookEx|WH_KEYBOARD|keylog(?:ger|ging)?", re.I), "credential_theft", 9, "Keylogging capability"),
    (re.compile(r"api\.telegram\.org|sendMessage|sendDocument|bot[A-Za-z0-9:_-]{10,}", re.I), "exfiltration", 8, "Telegram bot or messaging exfiltration channel"),
    (re.compile(r"CreateRemoteThread|WriteProcessMemory|VirtualAllocEx|PAGE_EXECUTE", re.I), "process_injection", 10, "Windows process injection primitive"),
    (re.compile(r"reg\s+add\s+.*\\Run\\|CurrentVersion\\Run|schtasks\s+/create|Register-ScheduledTask", re.I), "persistence", 9, "Windows autorun or scheduled-task persistence"),
    (re.compile(r"powershell.*-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}|IEX\s*\(", re.I), "obfuscation", 9, "PowerShell obfuscated execution"),
    (re.compile(r"mimikatz|sekurlsa|lsass|procdump.*lsass|reg\s+save\s+(?:HKLM\\)?SAM", re.I), "credential_theft", 10, "Credential dumping indicator"),
    (re.compile(r"vssadmin\s+delete\s+shadows|YOUR\s+FILES\s+(?:HAVE\s+BEEN|ARE)\s+ENCRYPTED|Fernet\.generate_key", re.I), "ransomware", 10, "Ransomware behavior indicator"),
    (re.compile(r"curl\s+.*(?:--data-binary|-d)\s+@|Invoke-WebRequest.*-Method\s+Post.*-InFile", re.I), "exfiltration", 8, "File upload/exfiltration command"),
]


class MemPalaceFinding(BaseModel):
    """A typed agent finding that can be rendered and stored safely."""

    category: str
    severity: int = Field(ge=0, le=10)
    description: str
    matches: int = Field(default=1, ge=1)
    source: str = "agent"


class MemPalaceContentAssessment(BaseModel):
    """What the MemPalace agent observed by inspecting the change payload itself."""

    inspected: bool = False
    risk_score: int = Field(default=0, ge=0, le=10)
    priority: Priority = "info"
    threat_type: str = "benign"
    threat_classification: str = "No Agent Content Threat"
    summary: str = "No readable content was inspected by the agent."
    findings: list[MemPalaceFinding] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)


class MemPalaceEvent(BaseModel):
    """Context packet sent into the embedded MemPalace agent core."""

    path: str
    event_type: str
    os_family: str = "unknown"
    is_baseline: bool = False
    registry: dict[str, Any] = Field(default_factory=dict)
    registry_signal: dict[str, Any] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    content_excerpt: str = ""
    previous_snippet_available: bool = False
    change_summary: dict[str, Any] | str | None = None
    content_analysis: dict[str, Any] = Field(default_factory=dict)
    memory_status: dict[str, Any] = Field(default_factory=dict)
    related_memories: list[dict[str, Any]] = Field(default_factory=list)


class MemPalaceVerdict(BaseModel):
    """Typed output contract for MemPalace contextual analysis."""

    agent_name: str = "MemPalace File Intelligence"
    adapter: str = "local_typed_core"
    agent_mode: str = "local"
    tools_used: list[str] = Field(default_factory=list)
    os_family: str = "unknown"
    memory_scope: str = "general"
    tier: int | None = None
    semantic_role: str = "general_file"
    asset_type: str = "unknown"
    identity_summary: str
    platform_context: str
    change_interpretation: str
    expected_change_sources: list[str] = Field(default_factory=list)
    risk_score: int = Field(ge=0, le=10)
    priority: Priority
    identity_risk: bool = False
    content_risk: bool = False
    agent_content: MemPalaceContentAssessment = Field(default_factory=MemPalaceContentAssessment)
    external_memory_backend: str = "mempalace"
    memory_status: dict[str, Any] = Field(default_factory=dict)
    related_memories: list[dict[str, Any]] = Field(default_factory=list)
    threat_type: str = "benign"
    threat_classification: str = "Contextual File Integrity Event"
    confidence: Literal["low", "medium", "high"] = "medium"
    reasoning: str
    findings: list[MemPalaceFinding] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)


class PydanticAITypedLLMAdapter:
    """
    Optional PydanticAI adapter.

    PydanticAI uses typed agent outputs through the Agent ``output_type``
    contract. The dependency is intentionally optional so the FIM remains
    local and lightweight when that framework is not installed/configured.
    """

    def __init__(self, model: str | None = None) -> None:
        self.model = model or getattr(settings, "mempalace_agent_model", None) or settings.ollama_model

    def analyze(self, event: MemPalaceEvent) -> MemPalaceVerdict | None:
        if not self._should_call_llm(event):
            return None

        verdict = self._call_pydantic_ai(event)
        if verdict is not None:
            return verdict
        return self._call_ollama(event)

    def _should_call_llm(self, event: MemPalaceEvent) -> bool:
        if not bool(getattr(settings, "mempalace_agent_llm_enabled", True)):
            return False
        mode = str(getattr(settings, "mempalace_agent_mode", "auto") or "auto").lower()
        if mode == "local":
            return False
        if mode == "llm":
            return True
        source = str((event.content_analysis or {}).get("analysis_source") or "").lower()
        if not any(provider in source for provider in ("ollama", "gemini", "llm")):
            return False
        if event.is_baseline:
            return False
        registry_tier = _safe_int((event.registry or {}).get("tier")) or 4
        content_score = _safe_int((event.content_analysis or {}).get("risk_score")) or 0
        has_content = bool((event.content_excerpt or "").strip()) and event.content_excerpt not in {
            "Binary/Unreadable",
            "File deleted",
        }
        return has_content and (
            content_score >= 4
            or registry_tier <= 3
            or event.event_type in {"modified", "deleted", "renamed"}
        )

    def _call_pydantic_ai(self, event: MemPalaceEvent) -> MemPalaceVerdict | None:
        try:
            from pydantic_ai import Agent  # type: ignore
        except Exception:
            return None

        instructions = (
            "You are the MemPalace File Intelligence agent for a file integrity "
            "monitor. Analyze file identity, OS-specific role, event type, "
            "content-analysis result, and expected change sources. Return a "
            "typed MemPalaceVerdict. Be cross-platform: reason about Windows "
            "registry keys, services, scheduled tasks, drivers, System32, "
            "startup folders, Linux auth/system paths, and macOS launch items."
        )
        try:
            agent = Agent(
                self.model,
                instructions=instructions,
                output_type=MemPalaceVerdict,
            )
            result = agent.run_sync(_event_prompt(event))
            verdict = result.output
            verdict.adapter = "pydantic_ai"
            verdict.agent_mode = "llm"
            verdict.tools_used = _dedupe(verdict.tools_used + [
                "registry_memory_lookup",
                "change_payload_inspection",
                "typed_llm_reasoning",
            ])
            return verdict
        except Exception:
            return None

    def _call_ollama(self, event: MemPalaceEvent) -> MemPalaceVerdict | None:
        prompt = _agent_llm_prompt(event)
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
        }
        try:
            response = requests.post(
                settings.ollama_url,
                json=payload,
                timeout=min(float(settings.ollama_timeout), 12.0),
            )
            if response.status_code != 200:
                return None
            envelope = response.json()
        except (requests.RequestException, ValueError):
            return None

        response_text = envelope.get("response", "") if isinstance(envelope, dict) else ""
        parsed = _parse_json_payload(response_text)
        if not parsed:
            return None
        try:
            verdict = MemPalaceVerdict(**parsed)
            verdict.adapter = "ollama"
            verdict.agent_mode = "llm"
            verdict.tools_used = _dedupe(verdict.tools_used + [
                "registry_memory_lookup",
                "change_payload_inspection",
                "ollama_context_reasoning",
            ])
            return verdict
        except ValidationError:
            return None


class MemPalaceAgentCore:
    """Local-first agent core for contextual file identity reasoning."""

    def __init__(self, adapter: PydanticAITypedLLMAdapter | None = None) -> None:
        self.adapter = adapter or PydanticAITypedLLMAdapter()

    def evaluate(self, event: MemPalaceEvent | dict[str, Any]) -> MemPalaceVerdict:
        typed_event = event if isinstance(event, MemPalaceEvent) else MemPalaceEvent(**event)
        llm_verdict = self.adapter.analyze(typed_event)
        if llm_verdict is not None:
            return llm_verdict
        return self._local_verdict(typed_event)

    def _local_verdict(self, event: MemPalaceEvent) -> MemPalaceVerdict:
        registry = event.registry or {}
        content = event.content_analysis or {}
        agent_content = _inspect_content_change(event)
        os_family = event.os_family or infer_os_family(event.path)
        tier = _safe_int(registry.get("tier"))
        role = str(registry.get("semantic_role") or "general_file")
        asset_type = str(registry.get("asset_type") or registry.get("file_category") or "unknown")
        expected_sources = list(registry.get("expected_change_sources") or [])
        related_memories = list(event.related_memories or [])

        content_score = _safe_int(content.get("risk_score")) or 0
        agent_content_score = agent_content.risk_score
        signal_score = _safe_int((event.registry_signal or {}).get("risk_score")) or 0
        identity_score = _identity_score(tier, role, event.event_type, event.is_baseline)
        content_threat = bool(content.get("is_malicious") or content_score >= 7 or agent_content_score >= 7)
        score = max(identity_score, signal_score, content_score, agent_content_score)
        priority = _priority_for_score(score)

        platform_context = _platform_context(os_family, role, event.path)
        change_interpretation = _change_interpretation(event, role, content, agent_content)
        identity_summary = _identity_summary(tier, role, asset_type, registry)
        findings = _agent_findings(event, score, identity_score, content_score, agent_content, role)
        actions = _recommended_actions(os_family, priority, role, event.event_type, content_threat)
        tools = [
            "registry_memory_lookup",
            "change_payload_inspection",
            "agent_content_indicator_scan",
            "context_verdict_reconciliation",
        ]
        if event.memory_status:
            tools.append("actual_mempalace_memory_status")
        if related_memories:
            tools.append("actual_mempalace_related_memory_search")

        if agent_content.risk_score >= content_score and agent_content.threat_type != "benign":
            threat_type = agent_content.threat_type
        elif content.get("threat_type"):
            threat_type = str(content.get("threat_type"))
        else:
            threat_type = "identity_risk" if identity_score >= 7 else "benign"
        classification = str(
            agent_content.threat_classification
            if agent_content.risk_score >= content_score and agent_content.threat_type != "benign"
            else content.get("threat_classification")
            or _classification_for(role, os_family, content_threat, score)
        )
        reasoning = _reasoning(
            event=event,
            identity_summary=identity_summary,
            platform_context=platform_context,
            change_interpretation=change_interpretation,
            score=score,
            priority=priority,
            content=content,
            agent_content=agent_content,
            memory_status=event.memory_status,
            related_memories=related_memories,
        )

        return MemPalaceVerdict(
            agent_mode="local",
            tools_used=tools,
            os_family=os_family,
            memory_scope=_memory_scope(os_family, role, asset_type),
            tier=tier,
            semantic_role=role,
            asset_type=asset_type,
            identity_summary=identity_summary,
            platform_context=platform_context,
            change_interpretation=change_interpretation,
            expected_change_sources=expected_sources,
            risk_score=score,
            priority=priority,
            identity_risk=identity_score >= 7,
            content_risk=content_threat,
            agent_content=agent_content,
            memory_status=event.memory_status,
            related_memories=related_memories[:5],
            threat_type=threat_type,
            threat_classification=classification,
            confidence=_confidence(registry, content, score),
            reasoning=reasoning,
            findings=findings,
            recommended_actions=actions,
        )


def build_mempalace_event(
    *,
    path: str,
    event_type: str,
    event_context: dict[str, Any] | None = None,
    content_excerpt: str = "",
    content_analysis: dict[str, Any] | None = None,
    registry_signal: dict[str, Any] | None = None,
    previous_snippet_available: bool = False,
    change_summary: dict[str, Any] | str | None = None,
    memory_status: dict[str, Any] | None = None,
    related_memories: list[dict[str, Any]] | None = None,
) -> MemPalaceEvent:
    """Create a typed event packet from the background-analysis context."""
    context = event_context or {}
    metadata = context.get("metadata") if isinstance(context.get("metadata"), dict) else {}
    registry = (
        metadata.get("registry")
        or context.get("registry")
        or (content_analysis or {}).get("registry")
        or {}
    )
    signal = registry_signal or metadata.get("registry_signal") or context.get("registry_signal")
    return MemPalaceEvent(
        path=path,
        event_type=event_type,
        os_family=infer_os_family(path),
        is_baseline=bool(metadata.get("is_baseline") or context.get("is_baseline")),
        registry=registry if isinstance(registry, dict) else {},
        registry_signal=signal if isinstance(signal, dict) else None,
        metadata=metadata,
        content_excerpt=(content_excerpt or "")[:5000],
        previous_snippet_available=previous_snippet_available,
        change_summary=change_summary,
        content_analysis=content_analysis or {},
        memory_status=memory_status or {},
        related_memories=related_memories or [],
    )


def merge_mempalace_verdict(
    analysis: dict[str, Any] | None,
    verdict: MemPalaceVerdict | dict[str, Any] | None,
) -> dict[str, Any]:
    """Attach MemPalace verdict and let it raise severity when warranted."""
    merged: dict[str, Any] = dict(analysis or {})
    if verdict is None:
        return merged

    try:
        typed = verdict if isinstance(verdict, MemPalaceVerdict) else MemPalaceVerdict(**verdict)
    except ValidationError:
        return merged

    payload = typed.model_dump()
    current_score = _safe_int(merged.get("risk_score")) or 0
    mem_score = typed.risk_score
    merged["mem_palace"] = payload
    merged["mem_palace_agent"] = True
    merged["registry_agent"] = bool(merged.get("registry_agent") or typed.identity_risk)
    merged.setdefault("registry", (analysis or {}).get("registry"))
    merged["tier"] = merged.get("tier") or typed.tier
    merged["semantic_role"] = merged.get("semantic_role") or typed.semantic_role
    merged["asset_type"] = merged.get("asset_type") or typed.asset_type

    notes = list(merged.get("context_notes") or [])
    notes.append(
        f"MemPalace evaluated {typed.os_family} identity scope "
        f"'{typed.memory_scope}' with {typed.priority.upper()} contextual priority."
    )
    merged["context_notes"] = _dedupe(notes)

    if mem_score > current_score:
        merged["risk_score"] = mem_score
        merged["priority"] = typed.priority
        merged["threat_type"] = typed.threat_type
        merged["threat_classification"] = typed.threat_classification
        merged["confidence"] = _stronger_confidence(merged.get("confidence"), typed.confidence)
        merged["reasoning"] = _join_reasoning(typed.reasoning, merged.get("reasoning"))
        merged["findings"] = [f.model_dump() for f in typed.findings] + list(merged.get("findings") or [])
        merged["recommended_actions"] = _dedupe(
            typed.recommended_actions + list(merged.get("recommended_actions") or [])
        )[:8]
    else:
        merged["risk_score"] = merged.get("risk_score", mem_score)
        merged["priority"] = merged.get("priority") or typed.priority
        merged["reasoning"] = _join_reasoning(
            merged.get("reasoning"),
            f"MemPalace context: {typed.change_interpretation}",
        )
        merged["recommended_actions"] = _dedupe(
            list(merged.get("recommended_actions") or []) + typed.recommended_actions[:2]
        )[:8]

    source = str(merged.get("analysis_source") or "")
    if "mempalace_agent" not in source:
        merged["analysis_source"] = "+".join([item for item in (source, "mempalace_agent") if item])
    return merged


def infer_os_family(path: str) -> str:
    value = (path or "").strip()
    low = value.lower().replace("/", "\\")
    if re.match(r"^[a-z]:\\", low) or low.startswith(("hklm\\", "hkcu\\", "hkcr\\", "hku\\", "hkcc\\")):
        return "windows"
    if low.startswith(("registry::hklm\\", "registry::hkcu\\")):
        return "windows"
    if low.startswith(("/system/", "/library/", "/users/")):
        return "darwin"
    if low.startswith("/"):
        return "linux"
    return "unknown"


def _event_prompt(event: MemPalaceEvent) -> str:
    return json.dumps(event.model_dump(), ensure_ascii=False, indent=2)


def _agent_llm_prompt(event: MemPalaceEvent) -> str:
    return f"""You are MemPalace File Intelligence, a bounded file-integrity agent.
You must analyze the file change yourself, not merely summarize another analyzer.

Use these internal skills:
1. registry_memory_lookup: understand the file identity, tier, role, OS family, and expected change sources.
2. change_payload_inspection: inspect the captured file content or before/current/diff payload.
3. platform_context_reasoning: reason differently for Windows registry/services/tasks/drivers/System32, Linux auth/systemd/cron/sudo/SSH, and macOS LaunchAgent/LaunchDaemon/system paths.
4. verdict_reconciliation: produce one typed verdict with risk, priority, findings, reasoning, and actions.

Return ONLY valid JSON matching this schema:
{{
  "agent_name": "MemPalace File Intelligence",
  "adapter": "ollama",
  "agent_mode": "llm",
  "tools_used": ["registry_memory_lookup", "change_payload_inspection", "platform_context_reasoning", "verdict_reconciliation"],
  "os_family": "windows|linux|darwin|unknown",
  "memory_scope": "os/asset_type/semantic_role",
  "tier": 1,
  "semantic_role": "source_code",
  "asset_type": "code",
  "external_memory_backend": "mempalace",
  "memory_status": {{}},
  "related_memories": [],
  "identity_summary": "one sentence",
  "platform_context": "one sentence",
  "change_interpretation": "what changed and what the content does",
  "expected_change_sources": ["developer_change"],
  "risk_score": 0,
  "priority": "critical|high|medium|low|info",
  "identity_risk": false,
  "content_risk": false,
  "agent_content": {{
    "inspected": true,
    "risk_score": 0,
    "priority": "info",
    "threat_type": "benign",
    "threat_classification": "No Agent Content Threat",
    "summary": "what the agent saw in the file content",
    "findings": [],
    "iocs": []
  }},
  "threat_type": "benign",
  "threat_classification": "Contextual File Integrity Event",
  "confidence": "low|medium|high",
  "reasoning": "detailed reasoning in 4-8 sentences",
  "findings": [],
  "recommended_actions": []
}}

Event packet:
{_event_prompt(event)}
"""


def _parse_json_payload(response_text: str) -> dict[str, Any] | None:
    text = (response_text or "").strip()
    if not text:
        return None
    if "```json" in text:
        text = text.split("```json", 1)[1].split("```", 1)[0].strip()
    elif "```" in text:
        text = text.split("```", 1)[1].split("```", 1)[0].strip()
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        return None


def _inspect_content_change(event: MemPalaceEvent) -> MemPalaceContentAssessment:
    content = event.content_excerpt or ""
    if not content or content in {"Binary/Unreadable", "File deleted"}:
        return MemPalaceContentAssessment()

    active = _active_agent_content(content)
    findings: list[MemPalaceFinding] = []
    max_score = 0
    threat_type = "benign"
    for pattern, category, severity, description in AGENT_CONTENT_PATTERNS:
        matches = pattern.findall(active[:8000])
        count = len(matches)
        if not count:
            continue
        max_score = max(max_score, severity)
        if severity >= max_score:
            threat_type = category
        findings.append(MemPalaceFinding(
            category=f"agent_content_{category}",
            severity=severity,
            description=description,
            matches=count,
            source="mempalace_content",
        ))

    iocs = _extract_agent_iocs(active)
    priority = _priority_for_score(max_score)
    if max_score >= 9:
        classification = _agent_classification(threat_type)
        summary = (
            f"Agent content inspection found {classification.lower()} indicators "
            f"in the captured change payload."
        )
    elif max_score >= 4:
        classification = "Suspicious Content Requiring Review"
        summary = "Agent content inspection found suspicious behavior indicators in the captured change payload."
    else:
        classification = "No Agent Content Threat"
        summary = _summarize_agent_content(active)

    return MemPalaceContentAssessment(
        inspected=True,
        risk_score=max_score,
        priority=priority,
        threat_type=threat_type,
        threat_classification=classification,
        summary=summary,
        findings=findings,
        iocs=iocs,
    )


def _active_agent_content(content: str) -> str:
    marker = "=== CURRENT CONTENT (snippet) ==="
    diff_marker = "=== UNIFIED DIFF (before -> after) ==="
    if marker not in content:
        return content
    current_match = re.search(
        rf"{re.escape(marker)}\n([\s\S]*?)(?:\n{re.escape(diff_marker)}|$)",
        content,
    )
    current = current_match.group(1).strip() if current_match else content
    diff_match = re.search(rf"{re.escape(diff_marker)}\n([\s\S]*)", content)
    if not diff_match:
        return current
    added = [
        line[1:]
        for line in diff_match.group(1).splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]
    return f"{current}\n\n# Added lines inspected by MemPalace:\n{chr(10).join(added)}"


def _extract_agent_iocs(content: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for pattern in (
        r"\b((?:\d{1,3}\.){3}\d{1,3}):(\d{2,5})\b",
        r"\b((?:\d{1,3}\.){3}\d{1,3})\b",
        r"\b([a-zA-Z0-9.-]+\.(?:com|net|org|io|ru|cn|co|dev|xyz))\b",
    ):
        for match in re.finditer(pattern, content):
            value = ":".join(g for g in match.groups() if g) if len(match.groups()) > 1 else match.group(1)
            if value.startswith(("127.", "0.", "255.")) or value in seen:
                continue
            seen.add(value)
            values.append(value)
            if len(values) >= 10:
                return values
    return values


def _agent_classification(threat_type: str) -> str:
    labels = {
        "reverse_shell": "Agent-Detected Reverse Shell",
        "credential_theft": "Agent-Detected Credential Theft",
        "exfiltration": "Agent-Detected Data Exfiltration",
        "process_injection": "Agent-Detected Process Injection",
        "persistence": "Agent-Detected Persistence",
        "obfuscation": "Agent-Detected Obfuscated Execution",
        "ransomware": "Agent-Detected Ransomware Behavior",
        "suspicious_exec": "Agent-Detected Suspicious Execution",
    }
    return labels.get(threat_type, "Agent-Detected Content Threat")


def _summarize_agent_content(content: str) -> str:
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    if not lines:
        return "Agent inspected readable content but found no executable or threat-like indicators."
    first = lines[0][:100]
    return f"Agent inspected readable content and found no strong threat indicators. First meaningful line: {first}"


def _identity_score(tier: int | None, role: str, event_type: str, is_baseline: bool) -> int:
    if is_baseline:
        return 0
    if tier == 1:
        return 10 if event_type == "deleted" else 9
    if tier == 2:
        return 8 if event_type in {"modified", "deleted"} else 7
    if tier == 3 and role in {
        "machine_autorun_registry",
        "user_autorun_registry",
        "windows_scheduled_task",
        "user_startup_item",
        "service_definition",
        "windows_service_registry",
        "source_code",
        "script",
    }:
        return 5
    return 1


def _agent_findings(
    event: MemPalaceEvent,
    score: int,
    identity_score: int,
    content_score: int,
    agent_content: MemPalaceContentAssessment,
    role: str,
) -> list[MemPalaceFinding]:
    findings: list[MemPalaceFinding] = []
    if identity_score >= 4:
        findings.append(MemPalaceFinding(
            category="file_identity",
            severity=identity_score,
            description=f"{event.event_type} event on {role}",
            source="mempalace_identity",
        ))
    findings.extend(agent_content.findings)
    if content_score >= 4:
        findings.append(MemPalaceFinding(
            category="pipeline_content_analysis",
            severity=content_score,
            description="Content analysis reported suspicious or malicious behavior.",
            source="pipeline",
        ))
    if not findings:
        findings.append(MemPalaceFinding(
            category="audit_context",
            severity=score,
            description="File event retained for integrity history.",
            source="mempalace_identity",
        ))
    return findings


def _platform_context(os_family: str, role: str, path: str) -> str:
    if os_family == "windows":
        if "registry" in role:
            return "Windows registry identity: changes may alter autorun, service, policy, or authentication behavior."
        if "scheduled_task" in role:
            return "Windows Task Scheduler identity: task XML can define persistence and command execution."
        if "driver" in role or "system_binary" in role:
            return "Windows system identity: System32, drivers, and core binaries are high-trust execution surfaces."
        if "startup" in role:
            return "Windows startup-folder identity: files here execute when a user signs in."
        return "Windows file identity: evaluate against services, scheduled tasks, registry persistence, and signed deployment context."
    if os_family == "linux":
        return "Linux file identity: evaluate auth files, sudo policy, systemd, cron, binaries, and package-manager context."
    if os_family == "darwin":
        return "macOS file identity: evaluate LaunchAgents, LaunchDaemons, system libraries, authorization, and SIP-protected paths."
    return f"Cross-platform file identity: evaluate role '{role}' and expected change source for this path."


def _change_interpretation(
    event: MemPalaceEvent,
    role: str,
    content: dict[str, Any],
    agent_content: MemPalaceContentAssessment,
) -> str:
    if event.is_baseline:
        return f"Baseline captured current state for {role}; later drift will be compared against this identity."
    if agent_content.risk_score >= 7:
        return (
            f"{event.event_type.title()} event on {role}; MemPalace inspected the captured "
            f"content and classified it as {agent_content.threat_classification} "
            f"with risk {agent_content.risk_score}/10."
        )
    content_label = content.get("threat_classification") or content.get("threat_type")
    if content_label:
        return (
            f"{event.event_type.title()} event on {role}; content analysis classified it as "
            f"{content_label} with risk {content.get('risk_score', 0)}/10."
        )
    return f"{event.event_type.title()} event on {role}; no strong content classification was available."


def _identity_summary(
    tier: int | None,
    role: str,
    asset_type: str,
    registry: dict[str, Any],
) -> str:
    tier_label = registry.get("tier_label") or ("Unclassified" if tier is None else f"Tier {tier}")
    reason = registry.get("reasoning") or "No stored role reasoning was available."
    return f"{tier_label} {asset_type} asset with semantic role '{role}'. {reason}"


def _classification_for(role: str, os_family: str, content_threat: bool, score: int) -> str:
    if content_threat:
        return "MemPalace Contextual Content Threat"
    if score >= 8:
        return f"{os_family.title()} High-Value Identity Change"
    if score >= 4:
        return "Contextual Integrity Review"
    return "Contextual Integrity Log"


def _reasoning(
    *,
    event: MemPalaceEvent,
    identity_summary: str,
    platform_context: str,
    change_interpretation: str,
    score: int,
    priority: str,
    content: dict[str, Any],
    agent_content: MemPalaceContentAssessment,
    memory_status: dict[str, Any] | None = None,
    related_memories: list[dict[str, Any]] | None = None,
) -> str:
    parts = [
        f"MemPalace evaluated this as a {event.os_family or infer_os_family(event.path)} file-intelligence event.",
        identity_summary,
        platform_context,
        f"Agent-native content inspection: {agent_content.summary}",
        _memory_context_summary(memory_status, related_memories),
        change_interpretation,
        f"The contextual verdict is {priority.upper()} with risk {score}/10.",
    ]
    if content.get("reasoning"):
        parts.append("Pipeline content verdict was reconciled with MemPalace context.")
    return " ".join(str(part) for part in parts if part).strip()


def _memory_context_summary(
    memory_status: dict[str, Any] | None,
    related_memories: list[dict[str, Any]] | None,
) -> str:
    """Summarize actual MemPalace memory retrieval for the agent reasoning."""
    memories = related_memories or []
    if memories:
        first = memories[0] if isinstance(memories[0], dict) else {}
        meta = first.get("metadata") if isinstance(first.get("metadata"), dict) else {}
        source = meta.get("source_file") or meta.get("file_path") or first.get("id") or "prior event"
        strategies = _memory_strategies(memory_status, memories)
        strategy_text = f" using {', '.join(strategies[:4])}" if strategies else ""
        return (
            f"Actual MemPalace memory search retrieved {len(memories)} related "
            f"memory record(s){strategy_text}; closest remembered context came from {source}."
        )
    status = memory_status or {}
    if status.get("searched"):
        return "Actual MemPalace memory search ran but found no related memory records for this scope."
    if status.get("error"):
        return f"Actual MemPalace memory was unavailable for this event: {status.get('error')}."
    if status:
        return "Actual MemPalace memory status was recorded for this event."
    return ""


def _memory_strategies(
    memory_status: dict[str, Any] | None,
    related_memories: list[dict[str, Any]] | None,
) -> list[str]:
    values: list[str] = []
    status = memory_status or {}
    raw_status = status.get("retrieval_strategies")
    if isinstance(raw_status, list):
        values.extend(str(item) for item in raw_status if item)
    for memory in related_memories or []:
        if not isinstance(memory, dict):
            continue
        meta = memory.get("metadata") if isinstance(memory.get("metadata"), dict) else {}
        raw = meta.get("retrieval_strategies") or meta.get("retrieval_strategy")
        if isinstance(raw, list):
            values.extend(str(item) for item in raw if item)
        elif isinstance(raw, str):
            values.extend(item.strip() for item in raw.replace("[", "").replace("]", "").replace('"', "").split(",") if item.strip())
    return _dedupe(values)


def _recommended_actions(
    os_family: str,
    priority: str,
    role: str,
    event_type: str,
    content_threat: bool,
) -> list[str]:
    if os_family == "windows":
        actions = [
            "Correlate with Windows Event Log, Sysmon, Task Scheduler, service-control, and registry activity near the timestamp.",
            "Verify the change against Windows Update, MSI installer, signed deployment, or approved administrator activity.",
        ]
        if "registry" in role:
            actions.insert(0, "Inspect the affected registry key/value and export it before remediation.")
        if "scheduled_task" in role:
            actions.insert(0, "Review the scheduled task action, trigger, author, and last-run metadata.")
        if "driver" in role or "system_binary" in role:
            actions.insert(0, "Verify Authenticode signature, file owner, and original path for the Windows binary or driver.")
    elif os_family == "linux":
        actions = [
            "Correlate with package-manager, systemd, cron, sudo, SSH, and auth logs near the timestamp.",
            "Verify whether the change came from an approved package update or administrator session.",
        ]
    elif os_family == "darwin":
        actions = [
            "Correlate with unified logs, launchctl, package receipts, and profile-management activity near the timestamp.",
            "Verify code signature, owner, quarantine attributes, and approved deployment source.",
        ]
    else:
        actions = [
            "Correlate the change with deployment, user, and process activity near the timestamp.",
            "Compare the current file against the last known good state.",
        ]

    if content_threat or priority in {"critical", "high"}:
        actions.append(f"Treat the {role} {event_type} event as unauthorized until a trusted change source is confirmed.")
        actions.append("Preserve the file, hashes, and surrounding telemetry for incident review.")
    else:
        actions.append("Record as expected only after confirming the operational change source.")
    return _dedupe(actions)[:5]


def _memory_scope(os_family: str, role: str, asset_type: str) -> str:
    return "/".join(item for item in (os_family, asset_type, role) if item)


def _priority_for_score(score: int) -> Priority:
    for threshold, priority in PRIORITY_BY_SCORE:
        if score >= threshold:
            return priority  # type: ignore[return-value]
    return "info"


def _confidence(registry: dict[str, Any], content: dict[str, Any], score: int) -> Literal["low", "medium", "high"]:
    if content.get("confidence") == "high" or registry.get("confidence") == "high" or score >= 8:
        return "high"
    if content.get("confidence") == "medium" or registry.get("confidence") == "medium" or score >= 4:
        return "medium"
    return "low"


def _stronger_confidence(left: Any, right: Any) -> str:
    rank = {"low": 1, "medium": 2, "high": 3}
    left_key = str(left or "low").lower()
    right_key = str(right or "low").lower()
    return left_key if rank.get(left_key, 1) >= rank.get(right_key, 1) else right_key


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _dedupe(items: list[Any]) -> list[Any]:
    seen: set[str] = set()
    result: list[Any] = []
    for item in items:
        if not item:
            continue
        key = json.dumps(item, sort_keys=True, default=str) if isinstance(item, dict) else str(item)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _join_reasoning(first: Any, second: Any) -> str:
    sentences: list[str] = []
    seen: set[str] = set()
    for item in (first, second):
        text = str(item or "").strip()
        if not text:
            continue
        for sentence in _split_reasoning_sentences(text):
            key = _reasoning_sentence_key(sentence)
            if not key or key in seen:
                continue
            seen.add(key)
            sentences.append(sentence)
    return " ".join(sentences)


def _split_reasoning_sentences(text: str) -> list[str]:
    normalized = re.sub(r"\s+", " ", str(text or "").strip())
    if not normalized:
        return []
    return [
        item.strip()
        for item in re.findall(r"[^.!?]+(?:[.!?]+(?=\s|$)|$)", normalized)
        if item.strip()
    ]


def _reasoning_sentence_key(sentence: str) -> str:
    text = str(sentence or "").strip()
    text = re.sub(
        r"^(?:[-•]\s*)?(?:pipeline content verdict reconciled by mempalace|content analysis result|mempalace context):\s*",
        "",
        text,
        flags=re.I,
    )
    text = re.sub(r"^[-•]\s*", "", text)
    text = re.sub(r"\s+", " ", text).strip().lower()
    return text.rstrip(".!?")
