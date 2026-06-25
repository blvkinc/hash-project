"""OS detection and system-event context for file-change analysis.

Provides context signals that differ by operating system so the
Ollama model can reason about whether a file change is expected
(e.g. after a system update) or suspicious.

Context signals checked:
  Linux:  /var/log/dpkg.log, /var/log/yum.log, /var/log/pacman.log
  Windows: C:\\Windows\\SoftwareDistribution\\ timestamps,
           recent MSI/setup activity
  macOS:  /var/log/install.log, Homebrew logs
"""
import os
import time
import logging
import platform
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List

from .platform_paths import detect_os, get_file_category, get_tier_for_path

logger = logging.getLogger(__name__)

# How far back to look for "recent" system activity (hours)
_RECENCY_WINDOW_HOURS = 4


# System Update Detection

def _file_modified_recently(path: str, hours: int = _RECENCY_WINDOW_HOURS) -> bool:
    """Check if a file was modified within the last N hours."""
    try:
        mtime = os.path.getmtime(path)
        return (time.time() - mtime) < (hours * 3600)
    except (OSError, FileNotFoundError):
        return False


def _dir_has_recent_activity(path: str, hours: int = _RECENCY_WINDOW_HOURS) -> bool:
    """Check if any file in a directory was modified within the last N hours."""
    try:
        if not os.path.isdir(path):
            return False
        for entry in os.scandir(path):
            if entry.is_file():
                if (time.time() - entry.stat().st_mtime) < (hours * 3600):
                    return True
    except (OSError, PermissionError):
        pass
    return False


def _get_linux_update_context() -> Dict[str, Any]:
    """Check Linux package manager logs for recent activity."""
    context = {
        'recent_updates': False,
        'package_manager': None,
        'details': [],
    }

    checks = [
        ('/var/log/dpkg.log', 'dpkg/apt'),
        ('/var/log/yum.log', 'yum'),
        ('/var/log/pacman.log', 'pacman'),
        ('/var/log/dnf.log', 'dnf'),
        ('/var/log/zypp/history', 'zypper'),
    ]

    for log_path, pkg_mgr in checks:
        if _file_modified_recently(log_path):
            context['recent_updates'] = True
            context['package_manager'] = pkg_mgr
            context['details'].append(f'{pkg_mgr} activity detected in {log_path}')

    return context


def _get_windows_update_context() -> Dict[str, Any]:
    """Check Windows system for recent update activity."""
    context = {
        'recent_updates': False,
        'package_manager': None,
        'details': [],
    }

    # Windows Update download folder
    wu_path = r'C:\Windows\SoftwareDistribution\Download'
    if _dir_has_recent_activity(wu_path):
        context['recent_updates'] = True
        context['package_manager'] = 'Windows Update'
        context['details'].append('Recent Windows Update download activity detected')

    # Windows Update log
    wu_log = r'C:\Windows\Logs\WindowsUpdate'
    if _dir_has_recent_activity(wu_log):
        context['recent_updates'] = True
        context['package_manager'] = 'Windows Update'
        context['details'].append('Windows Update log activity detected')

    # Check for recent MSI installations
    msi_log = r'C:\Windows\Logs\MoSetup'
    if _dir_has_recent_activity(msi_log):
        context['details'].append('Recent MSI/setup activity detected')

    return context


def _get_macos_update_context() -> Dict[str, Any]:
    """Check macOS for recent update/install activity."""
    context = {
        'recent_updates': False,
        'package_manager': None,
        'details': [],
    }

    # macOS install log
    if _file_modified_recently('/var/log/install.log'):
        context['recent_updates'] = True
        context['package_manager'] = 'macOS installer'
        context['details'].append('Recent macOS install activity detected')

    # Homebrew logs
    homebrew_log = os.path.expanduser('~/Library/Logs/Homebrew')
    if _dir_has_recent_activity(homebrew_log):
        context['recent_updates'] = True
        context['package_manager'] = context.get('package_manager') or 'Homebrew'
        context['details'].append('Recent Homebrew activity detected')

    return context


def get_recent_system_updates(target_os: Optional[str] = None) -> Dict[str, Any]:
    """
    Check for recent system update activity on the current or specified OS.

    Returns:
        Dict with keys: recent_updates (bool), package_manager (str|None),
                        details (list of strings)
    """
    os_name = target_os or detect_os()

    if os_name == 'linux':
        return _get_linux_update_context()
    elif os_name == 'windows':
        return _get_windows_update_context()
    elif os_name == 'darwin':
        return _get_macos_update_context()

    return {'recent_updates': False, 'package_manager': None, 'details': []}


# LLM Context Builder

def get_os_info() -> Dict[str, str]:
    """Get detailed OS information for the LLM prompt."""
    return {
        'os': detect_os(),
        'os_name': platform.system(),
        'os_version': platform.version(),
        'os_release': platform.release(),
        'architecture': platform.machine(),
    }


def get_context_for_llm(
    file_path: str,
    change_type: str,
    target_os: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Assemble contextual information for the Ollama LLM prompt.

    This gives the model OS-aware signals to reason about whether a
    change to a particular file is expected or suspicious.

    Args:
        file_path: Absolute path of the changed file.
        change_type: 'new', 'modified', or 'deleted'.
        target_os: Override OS detection (for testing).

    Returns:
        Dict containing:
          - os_info: OS name, version, architecture
          - file_category: binary, config, auth, log, data, etc.
          - monitoring_tier: 1-4 or None
          - tier_label: human-readable tier description
          - recent_updates: whether the system was recently updated
          - update_details: list of context strings
    """
    os_name = target_os or detect_os()

    tier = get_tier_for_path(file_path, target_os=os_name)
    tier_labels = {
        1: 'CRITICAL  -  should rarely change outside tracked updates',
        2: 'HIGH  -  prompt alert recommended',
        3: 'MEDIUM  -  batched digest appropriate',
        4: 'LOW  -  silent logging sufficient',
    }

    update_ctx = get_recent_system_updates(target_os=os_name)

    return {
        'os_info': get_os_info(),
        'file_category': get_file_category(file_path, target_os=os_name),
        'monitoring_tier': tier,
        'tier_label': tier_labels.get(tier, 'UNCLASSIFIED  -  not in default monitoring set'),
        'recent_updates': update_ctx['recent_updates'],
        'update_details': update_ctx['details'],
    }


def format_context_for_prompt(context: Dict[str, Any]) -> str:
    """
    Format the context dict into a human-readable string block
    suitable for injection into the Ollama prompt.
    """
    os_info = context.get('os_info', {})
    lines = [
        f"Operating System: {os_info.get('os_name', 'Unknown')} {os_info.get('os_release', '')} ({os_info.get('architecture', '')})",
        f"File Category: {context.get('file_category', 'unknown')}",
        f"Monitoring Tier: {context.get('monitoring_tier', 'N/A')}  -  {context.get('tier_label', 'unclassified')}",
    ]

    if context.get('recent_updates'):
        lines.append(f"Recent System Updates: YES  -  {'; '.join(context.get('update_details', []))}")
    else:
        lines.append("Recent System Updates: None detected in the last few hours")

    return '\n'.join(lines)
