"""
Notification routing for analyzed file-change events.

Critical and high-risk events are sent immediately. Medium-risk events are
batched, and low-risk events remain available in the event history.
"""
import os
import time
import logging
import smtplib
import threading
import hashlib
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import deque
from datetime import datetime
from typing import Dict, Any, Optional, List, Deque

from .config import settings

logger = logging.getLogger(__name__)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _severity_label(priority: str, risk_score: Any) -> str:
    """Map alert priority/risk to SOC-style severity labels."""
    priority = (priority or "info").lower()
    risk = _safe_int(risk_score)
    if priority == "critical" or risk >= 9:
        return "SEV-1"
    if priority == "high" or risk >= 7:
        return "SEV-2"
    if priority == "medium" or risk >= 4:
        return "SEV-3"
    if priority == "low" or risk >= 2:
        return "SEV-4"
    return "SEV-5"


def _event_fingerprint(event: Dict[str, Any]) -> str:
    """Stable short identifier for events that do not have a database ID."""
    raw = "|".join([
        str(event.get("host") or socket.gethostname()),
        str(event.get("path") or ""),
        str(event.get("event_type") or ""),
        str(event.get("priority") or ""),
        str(event.get("risk_score") or ""),
        ",".join(str(i) for i in event.get("iocs") or []),
    ])
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _default_actions(event: Dict[str, Any]) -> List[str]:
    severity = event.get("severity") or _severity_label(
        event.get("priority", "info"), event.get("risk_score", 0)
    )
    if severity in ("SEV-1", "SEV-2"):
        return [
            "Confirm whether the change came from an approved deployment or administrator action.",
            "Quarantine or isolate the affected host/path if the change is unauthorized.",
            "Collect the changed file, process history, user context, and network indicators.",
            "Hunt for the same indicator or file hash across other monitored hosts.",
        ]
    if severity == "SEV-3":
        return [
            "Review the change owner and compare against the approved baseline.",
            "Check nearby file events for a broader pattern.",
            "Escalate if the change is unexpected or repeats across systems.",
        ]
    return [
        "Retain for audit trail.",
        "Review only if the change was unexpected for this monitored path.",
    ]


def _normalize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Coerce raw analyser output into an incident-style notification event."""
    normalized = dict(event or {})
    normalized["host"] = normalized.get("host") or socket.gethostname()
    normalized["event_id"] = str(
        normalized.get("event_id")
        or normalized.get("id")
        or _event_fingerprint(normalized)
    )
    normalized["event_type"] = normalized.get("event_type") or "changed"
    normalized["priority"] = (normalized.get("priority") or "info").lower()
    normalized["risk_score"] = _safe_int(normalized.get("risk_score"), 0)
    normalized["severity"] = normalized.get("severity") or _severity_label(
        normalized["priority"], normalized["risk_score"]
    )
    normalized["detected_at"] = normalized.get("timestamp") or datetime.utcnow().isoformat()
    normalized["threat_classification"] = (
        normalized.get("threat_classification")
        or normalized.get("threat_type")
        or "File integrity event"
    )
    normalized["iocs"] = list(normalized.get("iocs") or [])
    normalized["mitre_attack"] = list(normalized.get("mitre_attack") or [])
    agent_notification = normalized.get("agent_notification")
    normalized["agent_notification"] = (
        dict(agent_notification) if isinstance(agent_notification, dict) else {}
    )
    agent_investigation = normalized.get("agent_investigation")
    normalized["agent_investigation"] = (
        dict(agent_investigation) if isinstance(agent_investigation, dict) else {}
    )
    if normalized["agent_notification"].get("summary") and not normalized.get("reasoning"):
        normalized["reasoning"] = normalized["agent_notification"]["summary"]
    normalized["recommended_actions"] = list(
        normalized.get("recommended_actions") or _default_actions(normalized)
    )
    return normalized


def _format_incident_body(event: Dict[str, Any]) -> str:
    """Build an email-ready incident alert body."""
    actions = event.get("recommended_actions") or []
    action_lines = "\n".join(f"- {action}" for action in actions)
    iocs = ", ".join(event.get("iocs") or []) or "None observed"
    mitre = ", ".join(event.get("mitre_attack") or []) or "None mapped"
    change_summary = event.get("change_summary") or {}
    if isinstance(change_summary, dict):
        if change_summary.get("previous_snippet_available"):
            change_text = (
                f"{change_summary.get('added_lines', 0)} line(s) added, "
                f"{change_summary.get('removed_lines', 0)} line(s) removed"
            )
        else:
            change_text = "No previous snippet available for diff comparison"
    else:
        change_text = str(change_summary or "Not provided")
    agent_notification = event.get("agent_notification") or {}
    agent_investigation = event.get("agent_investigation") or {}
    agent_section = ""
    if agent_notification or agent_investigation.get("ran"):
        trusted_change = agent_investigation.get("trusted_change") or agent_notification.get("trusted_change") or "unknown"
        tools = ", ".join(agent_investigation.get("tools_used") or []) or "not recorded"
        agent_section = (
            "Agent Investigation\n"
            "-------------------\n"
            f"Title: {agent_notification.get('title') or 'Not provided'}\n"
            f"Summary: {agent_notification.get('summary') or 'Not provided'}\n"
            f"Trusted Change: {trusted_change}\n"
            f"Tools: {tools}\n\n"
        )

    return (
        "File Integrity Alert\n"
        "====================\n"
        f"Event ID: {event.get('event_id')}\n"
        f"Detected At: {event.get('detected_at')} UTC\n"
        f"Host: {event.get('host')}\n"
        f"Severity: {event.get('severity')} ({event.get('priority', '').upper()})\n"
        f"Risk Score: {event.get('risk_score')}/10\n"
        f"Change Type: {event.get('event_type')}\n"
        f"Path: {event.get('path', 'Unknown')}\n"
        f"Classification: {event.get('threat_classification')}\n"
        f"Confidence: {event.get('confidence') or 'unknown'}\n"
        f"Analysis Source: {event.get('analysis_source') or 'unknown'}\n"
        f"MITRE ATT&CK: {mitre}\n"
        f"IOCs: {iocs}\n"
        f"Change Summary: {change_text}\n\n"
        "Analysis\n"
        "--------\n"
        f"{event.get('reasoning') or 'No reasoning provided.'}\n\n"
        f"{agent_section}"
        "Recommended Actions\n"
        "-------------------\n"
        f"{action_lines or '- Review the event in the dashboard.'}\n"
    )


def _format_digest_body(events: List[Dict[str, Any]], escalated: bool) -> str:
    counts: Dict[str, int] = {}
    for event in events:
        counts[event.get("severity", "SEV-5")] = counts.get(event.get("severity", "SEV-5"), 0) + 1
    counts_text = ", ".join(f"{sev}: {count}" for sev, count in sorted(counts.items()))

    lines = [
        "File Integrity Digest",
        "=====================",
        f"Escalated: {'yes' if escalated else 'no'}",
        f"Events: {len(events)}",
        f"Severity Counts: {counts_text or 'none'}",
        "",
    ]

    for i, event in enumerate(events, 1):
        lines.append(
            f"{i}. [{event.get('severity')}] risk={event.get('risk_score')}/10 "
            f"{event.get('event_type')} {event.get('path')}"
        )
        lines.append(f"   Event ID: {event.get('event_id')}")
        lines.append(f"   Classification: {event.get('threat_classification')}")
        if event.get("reasoning"):
            lines.append(f"   Summary: {str(event.get('reasoning'))[:240]}")
        lines.append("")

    return "\n".join(lines)


# Configuration

class NotificationConfig:
    """Runtime notification settings that can be updated through the API."""

    def __init__(self):
        # Desktop notifications
        self.desktop_enabled: bool = settings.desktop_notifications_enabled

        # Email notifications
        self.email_enabled: bool = settings.email_enabled
        self.smtp_host: str = settings.smtp_host
        self.smtp_port: int = settings.smtp_port
        self.smtp_user: str = settings.smtp_user
        self.smtp_password: str = settings.smtp_password
        self.email_from: str = settings.email_from
        self.email_to: str = settings.email_to

        # Batching
        self.batch_interval_seconds: int = settings.batch_interval_seconds

        # Escalation
        self.escalation_threshold: int = 3          # N medium events ...
        self.escalation_window_seconds: int = 300   # ... within this window

    def to_dict(self) -> Dict[str, Any]:
        return {
            "desktop_enabled": self.desktop_enabled,
            "email_enabled": self.email_enabled,
            "smtp_host": self.smtp_host,
            "smtp_port": self.smtp_port,
            "smtp_user": self.smtp_user,
            "email_from": self.email_from,
            "email_to": self.email_to,
            "batch_interval_seconds": self.batch_interval_seconds,
            "escalation_threshold": self.escalation_threshold,
            "escalation_window_seconds": self.escalation_window_seconds,
        }

    def update_from_dict(self, data: Dict[str, Any]):
        for key in (
            "desktop_enabled", "email_enabled",
            "smtp_host", "smtp_port", "smtp_user", "smtp_password",
            "email_from", "email_to",
            "batch_interval_seconds",
            "escalation_threshold", "escalation_window_seconds",
        ):
            if key in data:
                setattr(self, key, data[key])


#  Desktop Notification Helper

def _send_desktop_notification(title: str, message: str) -> bool:
    """Send a cross-platform desktop notification via plyer."""
    try:
        from plyer import notification as plyer_notification
        plyer_notification.notify(
            title=title,
            message=message[:256],   # some backends limit length
            app_name="Hash Monitor",
            timeout=10,
        )
        logger.info(f"Desktop notification sent: {title}")
        return True
    except ImportError:
        logger.warning("plyer not installed  -  desktop notifications unavailable.")
        return False
    except Exception as e:
        logger.error(f"Desktop notification failed: {e}")
        return False


#  Email Notification Helper

def _send_email_notification(
    subject: str,
    body: str,
    config: NotificationConfig,
) -> bool:
    """Send an email notification via SMTP."""
    if not config.email_enabled:
        return False
    if not config.smtp_host or not config.email_to:
        logger.warning("Email not configured  -  skipping email notification.")
        return False

    try:
        msg = MIMEMultipart()
        msg["From"] = config.email_from
        msg["To"] = config.email_to
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=15) as server:
            server.ehlo()
            if config.smtp_port != 25:
                server.starttls()
            if config.smtp_user:
                server.login(config.smtp_user, config.smtp_password)
            server.sendmail(config.email_from, [config.email_to], msg.as_string())

        logger.info(f"Email notification sent: {subject}")
        return True
    except Exception as e:
        logger.error(f"Email notification failed: {e}")
        return False


#  Notification Dispatcher

class NotificationDispatcher:
    """
    Central dispatcher that receives analysed FileLog events and routes
    them to the correct notification channel.

    Usage:
        dispatcher = NotificationDispatcher()
        dispatcher.enqueue(event_dict)   # called from background_analysis
        # In a separate thread:
        dispatcher.dispatch_loop()
    """

    def __init__(self, config: Optional[NotificationConfig] = None):
        self.config = config or NotificationConfig()

        # Batch queue for medium-severity events
        self._batch_queue: List[Dict[str, Any]] = []
        self._batch_lock = threading.Lock()
        self._last_batch_dispatch = time.time()

        # Recent medium events for escalation detection
        self._recent_medium: Deque[float] = deque()

        # Dispatch history
        self._history: Deque[Dict[str, Any]] = deque(maxlen=200)
        self._history_lock = threading.Lock()

    # Public API

    def enqueue(self, event: Dict[str, Any]):
        """
        Accept an analysed event and route it.

        Expected keys in `event`:
            path, event_type, priority, risk_score, reasoning
        """
        event = _normalize_event(event)
        priority = event.get("priority", "info")
        risk_score = event.get("risk_score", 0)

        if priority in ("critical", "high") or risk_score >= 8:
            self._handle_immediate(event)

        elif priority == "medium" or 4 <= risk_score <= 7:
            self._handle_batched(event)

        else:
            # Low and info events are already recorded in the database.
            self._record_history(event, "silent_log")

    def get_config(self) -> Dict[str, Any]:
        return self.config.to_dict()

    def update_config(self, data: Dict[str, Any]):
        self.config.update_from_dict(data)

    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._history_lock:
            items = list(self._history)
        return items[-limit:]

    # Immediate alerts

    def _handle_immediate(self, event: Dict[str, Any]):
        """Dispatch an immediate desktop + email alert."""
        path = event.get("path", "Unknown")
        priority = event.get("priority", "critical")
        reasoning = event.get("reasoning", "No details available.")
        risk = event.get("risk_score", "?")

        title = f"FIM Alert [{priority.upper()}]"
        body = (
            f"File: {path}\n"
            f"Risk Score: {risk}/10\n"
            f"Reason: {reasoning}"
        )
        severity = event.get("severity", _severity_label(priority, risk))
        classification = event.get("threat_classification") or "File integrity event"
        agent_notification = event.get("agent_notification") or {}
        title = agent_notification.get("title") or f"{severity} File Integrity Alert"
        desktop_body = agent_notification.get("summary") or (
            f"{event.get('event_type', 'changed').upper()} {os.path.basename(path)} | "
            f"Risk {risk}/10 | {classification}"
        )
        body = _format_incident_body(event)

        if self.config.desktop_enabled:
            _send_desktop_notification(title, desktop_body)

        if self.config.email_enabled:
            _send_email_notification(
                subject=(
                    f"[{severity}][Hash Monitor] {priority.upper()} "
                    f"{event.get('event_type', 'change')} - {os.path.basename(path)}"
                ),
                body=body,
                config=self.config,
            )

        self._record_history(event, "immediate")
        logger.info(f"Immediate alert dispatched: {path} ({priority})")

    # Batched digests

    def _handle_batched(self, event: Dict[str, Any]):
        """Add event to the batch queue, check for escalation."""
        now = time.time()

        with self._batch_lock:
            self._batch_queue.append(event)

        # Track for escalation
        self._recent_medium.append(now)
        # Purge entries outside the window
        cutoff = now - self.config.escalation_window_seconds
        while self._recent_medium and self._recent_medium[0] < cutoff:
            self._recent_medium.popleft()

        # Escalation check
        if len(self._recent_medium) >= self.config.escalation_threshold:
            logger.warning(
                f"Escalation triggered: {len(self._recent_medium)} medium events "
                f"in {self.config.escalation_window_seconds}s"
            )
            self._flush_batch(escalated=True)
            self._recent_medium.clear()

    def _flush_batch(self, escalated: bool = False):
        """Send out the accumulated batch as a digest."""
        with self._batch_lock:
            if not self._batch_queue:
                return
            events = list(self._batch_queue)
            self._batch_queue.clear()

        self._last_batch_dispatch = time.time()

        # Build digest body
        lines = []
        if escalated:
            lines.append("ESCALATED - multiple medium-severity changes detected in a short window.\n")
        lines.append(f"Digest contains {len(events)} event(s):\n")

        for i, ev in enumerate(events, 1):
            path = ev.get("path", "Unknown")
            risk = ev.get("risk_score", "?")
            reason = ev.get("reasoning", "")
            lines.append(f"  {i}. [{risk}/10] {path}")
            if reason:
                lines.append(f"     -> {reason}")

        body = _format_digest_body(events, escalated)
        title = "SEV-2 File Integrity Escalation" if escalated else "File Integrity Digest"

        if self.config.desktop_enabled:
            _send_desktop_notification(title, f"{len(events)} event(s) ready for review.")

        if self.config.email_enabled:
            _send_email_notification(
                subject=f"[Hash Monitor] {'ESCALATED ' if escalated else ''}Digest - {len(events)} events",
                body=body,
                config=self.config,
            )

        dispatch_type = "escalated_batch" if escalated else "batch_digest"
        for ev in events:
            self._record_history(ev, dispatch_type)

        logger.info(f"Batch digest dispatched ({len(events)} events, escalated={escalated})")

    #  Dispatch History

    def _record_history(self, event: Dict[str, Any], dispatch_type: str):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_id": event.get("event_id", ""),
            "detected_at": event.get("detected_at", ""),
            "host": event.get("host", ""),
            "path": event.get("path", ""),
            "event_type": event.get("event_type", ""),
            "severity": event.get("severity", ""),
            "priority": event.get("priority", ""),
            "risk_score": event.get("risk_score", 0),
            "dispatch_type": dispatch_type,
            "threat_classification": event.get("threat_classification", ""),
            "confidence": event.get("confidence", ""),
            "analysis_source": event.get("analysis_source", ""),
            "mitre_attack": event.get("mitre_attack", []),
            "iocs": event.get("iocs", []),
            "change_summary": event.get("change_summary", {}),
            "recommended_actions": event.get("recommended_actions", []),
            "reasoning": event.get("reasoning", ""),
            "registry": event.get("registry", {}),
            "mem_palace": event.get("mem_palace", {}),
            "agent_notification": event.get("agent_notification", {}),
            "agent_investigation": event.get("agent_investigation", {}),
            "semantic_role": event.get("semantic_role", ""),
            "asset_tier": event.get("asset_tier"),
        }
        with self._history_lock:
            self._history.append(entry)

    #  Background Loop

    def dispatch_loop(self, interval: float = 10.0):
        """
        Periodically flush the batch queue if the batch interval has elapsed.
        Intended to run in a daemon thread.
        """
        logger.info("Notification dispatch loop started.")
        while True:
            try:
                elapsed = time.time() - self._last_batch_dispatch
                if elapsed >= self.config.batch_interval_seconds:
                    self._flush_batch(escalated=False)
            except Exception as e:
                logger.error(f"Dispatch loop error: {e}")
            time.sleep(interval)
