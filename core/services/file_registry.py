"""Persistent file intelligence registry.

The registry is an embedded semantic layer on top of file hashes. It records
what each file is to the system so later changes can be evaluated by identity,
not only by content patterns.
"""
from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from core.config import settings
from core.models import FileRegistryEntry
from core.platform_paths import get_file_category, get_tier_for_path


TIER_LABELS = {
    1: "Critical",
    2: "High",
    3: "Medium",
    4: "Low",
}

EXPECTED_CHANGE_SOURCES = {
    1: ["os_update", "package_manager", "administrator_maintenance"],
    2: ["service_deployment", "package_manager", "windows_update", "administrator_maintenance"],
    3: ["application_deployment", "developer_change", "administrator_maintenance"],
    4: ["application_runtime", "log_rotation", "cache_cleanup"],
    None: ["user_change", "application_runtime"],
}

REGISTRY_PREFIXES = ("hklm\\", "hkcu\\", "hkcr\\", "hku\\", "hkcc\\", "registry::")

SOURCE_EXTENSIONS = {
    ".c", ".cpp", ".cs", ".go", ".h", ".java", ".js", ".jsx", ".lua",
    ".php", ".pl", ".py", ".rb", ".rs", ".ts", ".tsx",
}
SCRIPT_EXTENSIONS = {".bat", ".bash", ".cmd", ".ps1", ".sh", ".zsh"}
CONFIG_EXTENSIONS = {
    ".conf", ".config", ".cfg", ".cnf", ".env", ".ini", ".json", ".plist",
    ".service", ".timer", ".toml", ".xml", ".yaml", ".yml",
}
SECRET_EXTENSIONS = {".crt", ".key", ".pem", ".pfx", ".p12"}
BINARY_EXTENSIONS = {".dll", ".dylib", ".exe", ".ko", ".so", ".sys"}
LOW_VALUE_EXTENSIONS = {".cache", ".log", ".lock", ".tmp", ".swp"}


def classify_file(
    file_path: str,
    metadata: dict[str, Any] | None = None,
    target_os: str | None = None,
) -> dict[str, Any]:
    """Classify a file by identity, location, and role."""
    os_name = target_os or _infer_target_os(file_path)
    category = get_file_category(file_path, target_os=os_name)
    platform_tier = get_tier_for_path(file_path, target_os=os_name)
    normalized = normalize_path(file_path)
    portable = _portable_path(file_path)
    ext = os.path.splitext(portable)[1].lower()

    semantic_role, asset_type, role_tier, reason = _semantic_role_for_path(
        portable, ext, category
    )
    if platform_tier == 4 and role_tier in (1, 2, 3):
        tier = role_tier
    else:
        tier = platform_tier or role_tier
    if tier is None:
        tier = _tier_from_category(category, ext)

    confidence = _confidence(platform_tier, role_tier, category, semantic_role)
    if not reason:
        reason = _reason_for_classification(file_path, tier, category, semantic_role, ext)

    return {
        "path": canonical_path(file_path),
        "normalized_path": normalized,
        "name": os.path.basename(file_path),
        "tier": tier,
        "tier_label": TIER_LABELS.get(tier, "Unclassified"),
        "semantic_role": semantic_role,
        "asset_type": asset_type,
        "file_category": category,
        "confidence": confidence,
        "reasoning": reason,
        "expected_change_sources": EXPECTED_CHANGE_SOURCES.get(
            tier, EXPECTED_CHANGE_SOURCES[None]
        ),
        "size": (metadata or {}).get("size"),
        "mtime": (metadata or {}).get("mtime"),
    }


def upsert_registry_entry(
    session: Session,
    path: str,
    metadata: dict[str, Any] | None = None,
    file_hash: str | None = None,
    fast_hash: str | None = None,
    security_hash: str | None = None,
    file_id: int | None = None,
    hash_algorithm: str | None = None,
    security_hash_algorithm: str | None = None,
    is_baseline: bool = False,
    active: bool = True,
) -> FileRegistryEntry:
    """Create or update the registry entry for a monitored file."""
    abs_path = canonical_path(path)
    normalized = normalize_path(abs_path)
    entry = None

    if file_id is not None:
        entry = (
            session.query(FileRegistryEntry)
            .filter(FileRegistryEntry.file_id == file_id)
            .first()
        )

    if entry is None:
        entry = (
            session.query(FileRegistryEntry)
            .filter(FileRegistryEntry.normalized_path == normalized)
            .order_by(FileRegistryEntry.updated_at.desc())
            .first()
        )

    if entry is None:
        entry = FileRegistryEntry(
            file_id=file_id,
            path=abs_path,
            normalized_path=normalized,
            first_seen=datetime.utcnow(),
        )
        session.add(entry)
    elif entry.path != abs_path:
        entry.path_history = _append_path_history(entry.path_history, entry.path, abs_path)

    classification = classify_file(abs_path, metadata=metadata)
    for key, value in classification.items():
        setattr(entry, key, value)

    if file_id is not None:
        entry.file_id = file_id
    if file_hash is not None:
        entry.current_hash = file_hash
        if is_baseline or not entry.last_known_good_hash:
            entry.last_known_good_hash = file_hash
    if fast_hash is not None:
        entry.current_fast_hash = fast_hash
    if security_hash is not None:
        entry.current_security_hash = security_hash
    entry.hash_algorithm = hash_algorithm or settings.hash_algorithm
    entry.security_hash_algorithm = security_hash_algorithm or settings.security_hash_algorithm
    entry.is_active = active
    entry.last_seen = datetime.utcnow()
    entry.updated_at = datetime.utcnow()
    return entry


def mark_registry_inactive(
    session: Session,
    file_id: int | None = None,
    path: str | None = None,
) -> FileRegistryEntry | None:
    """Mark a registry entry inactive after a delete event."""
    entry = get_registry_entry(session, file_id=file_id, path=path)
    if entry is None:
        return None
    entry.is_active = False
    entry.last_seen = datetime.utcnow()
    entry.updated_at = datetime.utcnow()
    return entry


def get_registry_entry(
    session: Session,
    file_id: int | None = None,
    path: str | None = None,
) -> FileRegistryEntry | None:
    """Fetch a registry entry by stable identity or path."""
    if file_id is not None:
        entry = (
            session.query(FileRegistryEntry)
            .filter(FileRegistryEntry.file_id == file_id)
            .first()
        )
        if entry is not None:
            return entry
    if not path:
        return None
    return (
        session.query(FileRegistryEntry)
        .filter(FileRegistryEntry.normalized_path == normalize_path(path))
        .order_by(FileRegistryEntry.updated_at.desc())
        .first()
    )


def registry_context(
    entry: FileRegistryEntry | dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Return a JSON-safe registry context payload."""
    if entry is None:
        return None
    if isinstance(entry, dict):
        data = dict(entry)
    else:
        data = {
            "file_id": entry.file_id,
            "path": entry.path,
            "tier": entry.tier,
            "tier_label": entry.tier_label,
            "semantic_role": entry.semantic_role,
            "asset_type": entry.asset_type,
            "file_category": entry.file_category,
            "confidence": entry.confidence,
            "reasoning": entry.reasoning,
            "expected_change_sources": entry.expected_change_sources or [],
            "last_known_good_hash": entry.last_known_good_hash,
            "current_hash": entry.current_hash,
            "current_fast_hash": entry.current_fast_hash,
            "current_security_hash": entry.current_security_hash,
            "hash_algorithm": entry.hash_algorithm,
            "security_hash_algorithm": entry.security_hash_algorithm,
            "path_history": entry.path_history or [],
            "is_active": entry.is_active,
            "first_seen": entry.first_seen.isoformat() if entry.first_seen else None,
            "last_seen": entry.last_seen.isoformat() if entry.last_seen else None,
            "updated_at": entry.updated_at.isoformat() if entry.updated_at else None,
        }
    return {key: value for key, value in data.items() if value is not None}


def normalize_path(path: str) -> str:
    """Normalize paths for stable lookup across path separator variants."""
    if is_registry_path(path):
        return path.strip().replace("/", "\\").lower()
    try:
        normalized = os.path.abspath(os.path.normpath(path))
    except Exception:
        normalized = path
    return os.path.normcase(normalized)


def canonical_path(path: str) -> str:
    """Return a stable display/storage path without corrupting registry keys."""
    if is_registry_path(path):
        return path.strip().replace("/", "\\")
    stripped = path.strip()
    if re.match(r"^[a-zA-Z]:[\\/]", stripped):
        return os.path.normpath(stripped)
    return os.path.abspath(path)


def is_registry_path(path: str) -> bool:
    low = (path or "").strip().lower().replace("/", "\\")
    return low.startswith(REGISTRY_PREFIXES)


def _infer_target_os(file_path: str) -> str:
    stripped = file_path.strip()
    lower = stripped.lower()
    registry_lower = lower.replace("/", "\\")
    if re.match(r"^[a-z]:[\\/]", lower) or registry_lower.startswith(REGISTRY_PREFIXES):
        return "windows"
    if lower.startswith(("/system/", "/library/", "/users/")):
        return "darwin"
    if lower.startswith("/"):
        return "linux"
    return None  # Let platform_paths use the host OS.


def _portable_path(file_path: str) -> str:
    if is_registry_path(file_path):
        return file_path.strip().replace("\\", "/").lower()
    return canonical_path(file_path).replace("\\", "/").lower()


def _semantic_role_for_path(
    portable_path: str,
    ext: str,
    category: str,
) -> tuple[str, str, int | None, str]:
    if portable_path.endswith("/etc/passwd"):
        return ("user_account_database", "auth", 1, "Controls local user account identity.")
    if portable_path.endswith("/etc/shadow"):
        return ("password_hash_store", "auth", 1, "Stores local password hashes.")
    if portable_path.endswith("/etc/sudoers") or "/etc/sudoers.d/" in portable_path:
        return ("privilege_policy", "auth", 1, "Controls sudo privilege delegation.")
    if portable_path.endswith("/authorized_keys") and "/.ssh/" in portable_path:
        return ("ssh_authorized_keys", "auth", 1, "Controls SSH key-based access.")
    if "/etc/ssh/" in portable_path:
        return ("ssh_server_configuration", "auth", 1, "Controls SSH server or client trust settings.")
    if "/etc/pam.d/" in portable_path:
        return ("pam_authentication_policy", "auth", 1, "Controls PAM authentication behavior.")
    if "/etc/cron" in portable_path or "/var/spool/cron/" in portable_path:
        return ("scheduled_task", "persistence", 2, "Defines scheduled command execution.")
    if "/etc/systemd/system/" in portable_path or ext == ".service":
        return ("service_definition", "persistence", 2, "Defines a managed service or startup behavior.")
    if any(
        portable_path.startswith(prefix)
        for prefix in ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/")
    ):
        return ("system_binary", "binary", 1, "Executable in a core operating-system binary path.")
    if "/lib/modules/" in portable_path:
        return ("kernel_module", "binary", 1, "Kernel module path.")
    if portable_path.startswith("/boot/"):
        return ("boot_chain_artifact", "binary", 1, "Boot chain or kernel artifact.")

    if portable_path.startswith("hklm/software/microsoft/windows/currentversion/runonce"):
        return ("machine_autorun_registry", "persistence", 1, "Controls machine-level RunOnce autostart execution.")
    if portable_path.startswith("hklm/software/microsoft/windows/currentversion/run"):
        return ("machine_autorun_registry", "persistence", 1, "Controls machine-level autostart execution.")
    if portable_path.startswith("hkcu/software/microsoft/windows/currentversion/run"):
        return ("user_autorun_registry", "persistence", 3, "Controls user-level autostart execution.")
    if portable_path.startswith("hklm/system/currentcontrolset/services"):
        return ("windows_service_registry", "persistence", 1, "Controls Windows service and driver startup configuration.")
    if portable_path.startswith("hklm/software/microsoft/windows nt/currentversion/winlogon"):
        return ("winlogon_registry_policy", "auth", 1, "Controls Windows logon shell, userinit, and notification behavior.")
    if portable_path.startswith("hklm/software/policies") or "/software/microsoft/windows/currentversion/policies" in portable_path:
        return ("windows_policy_registry", "config", 2, "Controls Windows policy and security settings.")
    if portable_path.startswith(("hklm/", "hkcu/", "hkcr/", "hku/", "hkcc/")):
        return ("windows_registry_key", "registry", 2, "Windows registry key affecting system or user configuration.")

    if re.search(r"c:/windows/system32/config/(sam|security|system)$", portable_path):
        return ("windows_registry_hive", "auth", 1, "Stores core Windows local security state.")
    if re.search(r"c:/windows/system32/config/(software|default)$", portable_path):
        return ("windows_registry_hive", "config", 2, "Stores core Windows configuration registry state.")
    if portable_path.endswith("/windows/system32/drivers/etc/hosts"):
        return ("dns_override_config", "config", 2, "Controls local DNS overrides.")
    if "/windows/system32/tasks/" in portable_path:
        return ("windows_scheduled_task", "persistence", 2, "Defines Windows scheduled task execution.")
    if "/windows/system32/grouppolicy/" in portable_path:
        return ("windows_group_policy_file", "config", 2, "Controls local Windows group policy behavior.")
    if "/windows/system32/winevt/logs/" in portable_path:
        return ("windows_event_log", "log", 2, "Stores Windows event telemetry; deletion or rewrite can indicate evidence tampering.")
    if "/windows/system32/windowspowershell/v1.0/profile.ps1" in portable_path:
        return ("powershell_profile", "persistence", 2, "PowerShell profile script executes in interactive PowerShell sessions.")
    if "/windows/system32/drivers/" in portable_path or ext == ".sys":
        return ("kernel_driver", "driver", 2, "Kernel-mode driver artifact.")
    if "/windows/system32/" in portable_path or "/windows/syswow64/" in portable_path:
        return ("windows_system_binary", "binary", 1, "Executable or library in a Windows system binary path.")
    if "/start menu/programs/startup/" in portable_path:
        return ("user_startup_item", "persistence", 2, "Runs automatically at user login.")
    if "/appdata/roaming/microsoft/windows/powershell/" in portable_path:
        return ("powershell_profile", "persistence", 3, "User PowerShell profile or module path can affect interactive execution.")
    if "/appdata/roaming/microsoft/windows/start menu/programs/startup/" in portable_path:
        return ("user_startup_item", "persistence", 2, "Runs automatically at user login.")
    if "/program files/" in portable_path or "/program files (x86)/" in portable_path:
        return ("installed_application_binary", "binary", 2, "Installed application executable or support file.")

    if ext in SECRET_EXTENSIONS or category == "auth":
        return ("secret_or_credential_material", "auth", 2, "Credential, certificate, or key material.")
    if ext in BINARY_EXTENSIONS or category in {"binary", "driver", "library"}:
        return ("executable_or_library", category or "binary", 3, "Executable, driver, or library artifact.")
    if ext in SCRIPT_EXTENSIONS:
        return ("script", "code", 3, "Executable script file.")
    if ext in SOURCE_EXTENSIONS:
        return ("source_code", "code", 3, "Application source code.")
    if ext in CONFIG_EXTENSIONS or category == "config":
        return ("configuration", "config", 3, "Configuration file.")
    if ext in LOW_VALUE_EXTENSIONS or category == "log":
        return ("log_or_runtime_artifact", "runtime", 4, "Runtime log, temporary, or cache artifact.")
    if "temp/" in portable_path or "/tmp/" in portable_path or "/cache/" in portable_path:
        return ("temporary_or_cache_artifact", "runtime", 4, "Temporary or cache path.")

    return ("general_file", category or "unknown", None, "")


def _tier_from_category(category: str, ext: str) -> int | None:
    if category == "auth":
        return 2
    if category in {"binary", "driver", "library", "config"} or ext in CONFIG_EXTENSIONS:
        return 3
    if category in {"log", "data"} or ext in LOW_VALUE_EXTENSIONS:
        return 4
    return None


def _confidence(
    platform_tier: int | None,
    role_tier: int | None,
    category: str,
    semantic_role: str,
) -> str:
    if platform_tier is not None or role_tier in (1, 2):
        return "high"
    if semantic_role != "general_file" or category != "unknown":
        return "medium"
    return "low"


def _reason_for_classification(
    file_path: str,
    tier: int | None,
    category: str,
    semantic_role: str,
    ext: str,
) -> str:
    if tier:
        return (
            f"Classified as Tier {tier} {TIER_LABELS.get(tier, '').lower()} "
            f"because its path/category maps to {semantic_role or category}."
        )
    if ext:
        return f"Classified by extension {ext} and category {category or 'unknown'}."
    return "No high-confidence semantic role was identified for this file."


def _append_path_history(
    history: list[dict[str, Any]] | None,
    old_path: str,
    new_path: str,
) -> list[dict[str, Any]]:
    items = list(history or [])
    if not items or items[-1].get("old_path") != old_path or items[-1].get("new_path") != new_path:
        items.append({
            "old_path": old_path,
            "new_path": new_path,
            "changed_at": datetime.utcnow().isoformat(),
        })
    return items[-20:]
