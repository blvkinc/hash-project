"""
platform_paths.py  -  Cross-platform monitoring path definitions.

Provides tiered default monitoring paths for Linux, Windows, and macOS,
based on research from Tripwire, OSSEC, Wazuh, Microsoft Defender FIM,
and osquery best practices.

Tiers:
  1  -  CRITICAL: Immediate notification (system binaries, auth, boot chain)
  2  -  HIGH:     Prompt alert within minutes (drivers, tasks, libraries)
  3  -  MEDIUM:   Batched digest hourly/daily (package DBs, SSH keys, profiles)
  4  -  LOW:      Silent log, review on demand (temps, caches, log growth)
"""
import os
import platform
from dataclasses import dataclass, field
from typing import Dict, List, Optional


#  Data Structures

@dataclass
class MonitorTarget:
    """A single monitoring target (file or directory)."""
    path: str
    description: str
    category: str  # binary, config, auth, log, data, registry, driver, library
    is_directory: bool = True
    recursive: bool = True


#  LINUX Monitoring Paths

LINUX_PATHS: Dict[int, List[MonitorTarget]] = {
    1: [
        # System binaries  -  trojan replacements for login, su, ps, ls
        MonitorTarget('/bin', 'Core system binaries', 'binary'),
        MonitorTarget('/sbin', 'System administration binaries', 'binary'),
        MonitorTarget('/usr/bin', 'User-space binaries', 'binary'),
        MonitorTarget('/usr/sbin', 'User-space admin binaries', 'binary'),
        # Authentication files
        MonitorTarget('/etc/passwd', 'User account database', 'auth', is_directory=False),
        MonitorTarget('/etc/shadow', 'Password hashes', 'auth', is_directory=False),
        MonitorTarget('/etc/sudoers', 'Sudo privileges', 'auth', is_directory=False),
        MonitorTarget('/etc/ssh', 'SSH server configuration', 'auth'),
        # Kernel and boot chain
        MonitorTarget('/boot', 'Boot loader and kernel images', 'binary'),
        MonitorTarget('/lib/modules', 'Kernel modules', 'binary'),
        # PAM authentication
        MonitorTarget('/etc/pam.d', 'Pluggable authentication modules', 'auth'),
    ],
    2: [
        # Broad /etc monitoring
        MonitorTarget('/etc/crontab', 'System crontab', 'config', is_directory=False),
        MonitorTarget('/etc/cron.d', 'Cron job definitions', 'config'),
        MonitorTarget('/etc/systemd/system', 'Custom systemd services', 'config'),
        # Shared libraries
        MonitorTarget('/lib', 'System shared libraries', 'library'),
        MonitorTarget('/usr/lib', 'User-space shared libraries', 'library'),
        # Authentication logs (modification, not appending)
        MonitorTarget('/var/log/auth.log', 'Authentication log', 'log', is_directory=False),
        MonitorTarget('/var/log/secure', 'Security log (RHEL)', 'log', is_directory=False),
        # User crontabs
        MonitorTarget('/var/spool/cron', 'User crontabs', 'config'),
    ],
    3: [
        # Package manager databases
        MonitorTarget('/var/lib/dpkg', 'Dpkg package database', 'data'),
        MonitorTarget('/var/lib/rpm', 'RPM package database', 'data'),
        MonitorTarget('/var/lib/pacman', 'Pacman package database', 'data'),
        # Third-party installs
        MonitorTarget('/opt', 'Third-party application installs', 'binary'),
        # User SSH keys (template  -  expand per user at runtime)
        MonitorTarget('/home', 'User home directories (SSH keys, profiles)', 'config'),
    ],
    4: [
        # Log growth (appending is normal)
        MonitorTarget('/var/log', 'System logs (growth monitoring)', 'log'),
        # Temp and cache
        MonitorTarget('/tmp', 'Temporary files', 'data'),
        MonitorTarget('/var/cache', 'Package cache', 'data'),
    ],
}


#  WINDOWS Monitoring Paths

WINDOWS_PATHS: Dict[int, List[MonitorTarget]] = {
    1: [
        # Core OS binaries  -  svchost.exe should ONLY reside in System32
        MonitorTarget(r'C:\Windows\System32', 'Core OS binaries (System32)', 'binary'),
        MonitorTarget(r'C:\Windows\SysWOW64', '32-bit system binaries on 64-bit', 'binary'),
        # SAM, SECURITY, SYSTEM registry hive files
        MonitorTarget(r'C:\Windows\System32\config\SAM', 'SAM hive (local accounts)', 'auth', is_directory=False),
        MonitorTarget(r'C:\Windows\System32\config\SECURITY', 'SECURITY hive', 'auth', is_directory=False),
        MonitorTarget(r'C:\Windows\System32\config\SYSTEM', 'SYSTEM hive', 'auth', is_directory=False),
        # Registry persistence keys (represented as paths for reference)
        MonitorTarget(r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'Machine-level autorun (registry)', 'registry', is_directory=False),
        MonitorTarget(r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'Machine-level RunOnce (registry)', 'registry', is_directory=False),
        MonitorTarget(r'HKLM\SYSTEM\CurrentControlSet\Services', 'Windows services (registry)', 'registry'),
        MonitorTarget(r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'Winlogon hooks (registry)', 'registry', is_directory=False),
    ],
    2: [
        # Kernel drivers (rootkit territory)
        MonitorTarget(r'C:\Windows\System32\drivers', 'Kernel-mode drivers', 'driver'),
        # Scheduled tasks
        MonitorTarget(r'C:\Windows\System32\Tasks', 'Scheduled tasks', 'config'),
        # Installed applications
        MonitorTarget(r'C:\Program Files', 'Installed application binaries (x64)', 'binary'),
        MonitorTarget(r'C:\Program Files (x86)', 'Installed application binaries (x86)', 'binary'),
        # Windows Event Logs
        MonitorTarget(r'C:\Windows\System32\winevt\Logs', 'Windows event logs', 'log'),
        # Group Policy
        MonitorTarget(r'C:\Windows\System32\GroupPolicy', 'Group policy files', 'config'),
        # Hosts file
        MonitorTarget(r'C:\Windows\System32\drivers\etc\hosts', 'Hosts file (DNS override)', 'config', is_directory=False),
        # Registry policy keys
        MonitorTarget(r'HKLM\SOFTWARE\Policies', 'Group policy settings (registry)', 'registry'),
        MonitorTarget(r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies', 'Windows policies (registry)', 'registry'),
    ],
    3: [
        # Application data
        MonitorTarget(r'C:\ProgramData', 'Application data', 'data'),
        # User-level startup persistence
        MonitorTarget(
            r'C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup',
            'User-level startup folder', 'config'
        ),
        # Prefetch  -  indicates new executables being run
        MonitorTarget(r'C:\Windows\Prefetch', 'Prefetch data (executable history)', 'data'),
        # User-level autorun registry
        MonitorTarget(r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'User-level autorun (registry)', 'registry', is_directory=False),
    ],
    4: [
        # Temp directories
        MonitorTarget(r'C:\Windows\Temp', 'Windows temp directory', 'data'),
        # User temp/downloads
        MonitorTarget(r'C:\Users', 'User profile directories (documents, downloads)', 'data'),
    ],
}


#  macOS Monitoring Paths

MACOS_PATHS: Dict[int, List[MonitorTarget]] = {
    1: [
        # System binaries (SIP-protected)
        MonitorTarget('/usr/bin', 'User-space binaries', 'binary'),
        MonitorTarget('/usr/sbin', 'Admin binaries', 'binary'),
        MonitorTarget('/bin', 'Core binaries', 'binary'),
        MonitorTarget('/sbin', 'System admin binaries', 'binary'),
        # Core system frameworks
        MonitorTarget('/System/Library', 'Core system frameworks and libraries', 'library'),
        # LaunchDaemons  -  adversaries install daemons for persistence
        MonitorTarget('/Library/LaunchDaemons', 'System-level launch daemons', 'config'),
        MonitorTarget('/System/Library/LaunchDaemons', 'Apple launch daemons', 'config'),
        # Authentication
        MonitorTarget('/etc/pam.d', 'PAM authentication modules', 'auth'),
        MonitorTarget('/etc/authorization', 'Authorization configuration', 'auth', is_directory=False),
        # Local directory service (user accounts)
        MonitorTarget('/var/db/dslocal', 'Local directory service database', 'auth'),
    ],
    2: [
        # User-level persistence agents
        MonitorTarget('/Library/LaunchAgents', 'System-level launch agents', 'config'),
        # Library preferences and support
        MonitorTarget('/Library/Preferences', 'System application preferences', 'config'),
        MonitorTarget('/Library/Application Support', 'Application support files', 'data'),
        # User-installed binaries (Homebrew)
        MonitorTarget('/usr/local/bin', 'User-installed binaries (Homebrew)', 'binary'),
        # Network redirection
        MonitorTarget('/etc/hosts', 'Hosts file (DNS override)', 'config', is_directory=False),
        MonitorTarget('/etc/resolv.conf', 'DNS resolver config', 'config', is_directory=False),
        # Security framework
        MonitorTarget('/Library/Security', 'Security framework extensions', 'config'),
    ],
    3: [
        # Homebrew and user tools
        MonitorTarget('/usr/local', 'User-installed tools (Homebrew root)', 'binary'),
        # Third-party frameworks
        MonitorTarget('/Library/Frameworks', 'Third-party frameworks', 'library'),
    ],
    4: [
        # Spotlight / cache
        MonitorTarget('/var/folders', 'macOS temporary/cache folders', 'data'),
        MonitorTarget('/tmp', 'Temporary files', 'data'),
    ],
}


#  Noisy Directories (per-OS)  -  expected frequent changes

NOISY_DIRS: Dict[str, List[str]] = {
    'linux': [
        '/var/cache',
        '/var/lib/apt/lists',
        '/var/tmp',
        '/run',
        '/proc',
        '/sys',
        '/dev',
    ],
    'windows': [
        r'C:\Windows\Temp',
        r'C:\Windows\Prefetch',
        r'C:\Windows\WinSxS',
        r'C:\Windows\SoftwareDistribution\Download',
        r'C:\Windows\Logs',
        r'C:\$Recycle.Bin',
    ],
    'darwin': [
        '/var/folders',
        '/private/var/folders',
        '/Library/Caches',
        '/System/Library/Caches',
        '/private/var/db/diagnostics',
    ],
}


#  File Category Classification

# Maps path prefixes to categories for contextual LLM prompts.
# Order matters  -  more specific prefixes first.

_CATEGORY_RULES_LINUX = [
    ('/etc/passwd', 'auth'), ('/etc/shadow', 'auth'), ('/etc/sudoers', 'auth'),
    ('/etc/ssh', 'auth'), ('/etc/pam.d', 'auth'),
    ('/boot', 'binary'), ('/lib/modules', 'binary'),
    ('/bin', 'binary'), ('/sbin', 'binary'), ('/usr/bin', 'binary'), ('/usr/sbin', 'binary'),
    ('/lib', 'library'), ('/usr/lib', 'library'),
    ('/etc', 'config'),
    ('/var/log', 'log'),
    ('/var/spool/cron', 'config'), ('/var/lib', 'data'),
    ('/opt', 'binary'), ('/home', 'data'), ('/tmp', 'data'),
]

_CATEGORY_RULES_WINDOWS = [
    (r'C:\Windows\System32\config', 'auth'),
    (r'C:\Windows\System32\drivers\etc\hosts', 'config'),
    (r'C:\Windows\System32\drivers', 'driver'),
    (r'C:\Windows\System32\Tasks', 'config'),
    (r'C:\Windows\System32\winevt', 'log'),
    (r'C:\Windows\System32\GroupPolicy', 'config'),
    (r'C:\Windows\System32', 'binary'),
    (r'C:\Windows\SysWOW64', 'binary'),
    (r'C:\Program Files', 'binary'),
    (r'C:\ProgramData', 'data'),
    (r'C:\Windows\Temp', 'data'),
    (r'C:\Windows\Prefetch', 'data'),
    (r'C:\Windows\Logs', 'log'),
    (r'C:\Windows', 'binary'),
]

_CATEGORY_RULES_MACOS = [
    ('/etc/pam.d', 'auth'), ('/etc/authorization', 'auth'),
    ('/var/db/dslocal', 'auth'),
    ('/System/Library/LaunchDaemons', 'config'),
    ('/Library/LaunchDaemons', 'config'), ('/Library/LaunchAgents', 'config'),
    ('/System/Library', 'library'),
    ('/Library/Security', 'config'), ('/Library/Preferences', 'config'),
    ('/usr/local/bin', 'binary'),
    ('/bin', 'binary'), ('/sbin', 'binary'), ('/usr/bin', 'binary'), ('/usr/sbin', 'binary'),
    ('/var/log', 'log'),
    ('/var/folders', 'data'), ('/tmp', 'data'),
    ('/Library', 'data'),
]

_CATEGORY_RULES = {
    'linux': _CATEGORY_RULES_LINUX,
    'windows': _CATEGORY_RULES_WINDOWS,
    'darwin': _CATEGORY_RULES_MACOS,
}


#  Public API

def detect_os() -> str:
    """Detect the current operating system. Returns 'linux', 'windows', or 'darwin'."""
    system = platform.system().lower()
    if system == 'windows':
        return 'windows'
    elif system == 'darwin':
        return 'darwin'
    return 'linux'  # Default to linux for unknown Unix-like systems


def get_all_os_paths() -> Dict[str, Dict[int, List[MonitorTarget]]]:
    """Return the full path registry for all operating systems."""
    return {
        'linux': LINUX_PATHS,
        'windows': WINDOWS_PATHS,
        'darwin': MACOS_PATHS,
    }


def get_default_paths(tier: Optional[int] = None, target_os: Optional[str] = None) -> Dict[int, List[MonitorTarget]]:
    """
    Get default monitoring paths for the specified or detected OS.

    Args:
        tier: If specified, return only paths for this tier (1-4).
              If None, return all tiers.
        target_os: 'linux', 'windows', or 'darwin'. Auto-detected if None.

    Returns:
        Dict mapping tier numbers to lists of MonitorTarget.
    """
    os_name = target_os or detect_os()
    all_paths = get_all_os_paths()
    os_paths = all_paths.get(os_name, LINUX_PATHS)

    if tier is not None:
        return {tier: os_paths.get(tier, [])}
    return os_paths


def get_noisy_dirs(target_os: Optional[str] = None) -> List[str]:
    """Get the list of noisy directories to exclude for the given or detected OS."""
    os_name = target_os or detect_os()
    return NOISY_DIRS.get(os_name, [])


def get_file_category(file_path: str, target_os: Optional[str] = None) -> str:
    """
    Classify a file path into a category based on its location.

    Returns one of: 'binary', 'config', 'auth', 'log', 'data',
                     'registry', 'driver', 'library', 'unknown'
    """
    os_name = target_os or detect_os()
    rules = _CATEGORY_RULES.get(os_name, [])

    # Normalise path separators for comparison
    normalised = file_path.replace('/', os.sep).replace('\\', os.sep)
    lower_path = normalised.lower()

    for prefix, category in rules:
        normalised_prefix = prefix.replace('/', os.sep).replace('\\', os.sep).lower()
        if lower_path.startswith(normalised_prefix):
            return category

    # Fallback by extension
    ext = os.path.splitext(file_path)[1].lower()
    ext_categories = {
        '.exe': 'binary', '.dll': 'binary', '.so': 'binary', '.dylib': 'binary',
        '.sys': 'driver', '.ko': 'driver',
        '.conf': 'config', '.cfg': 'config', '.ini': 'config', '.yaml': 'config',
        '.yml': 'config', '.json': 'config', '.xml': 'config', '.plist': 'config',
        '.log': 'log',
        '.key': 'auth', '.pem': 'auth', '.crt': 'auth', '.pfx': 'auth',
    }
    return ext_categories.get(ext, 'unknown')


def get_tier_for_path(file_path: str, target_os: Optional[str] = None) -> Optional[int]:
    """
    Determine which monitoring tier a file path falls into.

    Returns the tier number (1-4) or None if the path doesn't match any tier.
    """
    os_name = target_os or detect_os()
    os_paths = get_default_paths(target_os=os_name)

    normalised = file_path.replace('/', os.sep).replace('\\', os.sep).lower()

    matches = []
    for tier_num in sorted(os_paths.keys()):
        for target in os_paths[tier_num]:
            target_path = target.path.replace('/', os.sep).replace('\\', os.sep).lower()
            # Skip registry keys  -  they aren't filesystem paths
            if target.category == 'registry':
                continue
            if normalised.startswith(target_path):
                matches.append((len(target_path), tier_num))

    if matches:
        matches.sort(key=lambda item: (-item[0], item[1]))
        return matches[0][1]

    return None


def get_paths_summary(target_os: Optional[str] = None) -> Dict:
    """
    Get a JSON-serializable summary of monitoring paths for the API.

    Returns:
        Dict with tier numbers as keys and lists of path info dicts as values.
    """
    os_name = target_os or detect_os()
    os_paths = get_default_paths(target_os=os_name)

    summary = {}
    for tier, targets in os_paths.items():
        summary[str(tier)] = [
            {
                'path': t.path,
                'description': t.description,
                'category': t.category,
                'is_directory': t.is_directory,
            }
            for t in targets
        ]
    return summary
