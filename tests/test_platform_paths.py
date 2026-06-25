"""Unit tests for cross-platform monitoring modules.

Tests platform_paths.py and os_context.py to verify:
  - OS detection returns valid values
  - Default paths are populated for every tier
  - Noisy directories are OS-specific
  - File category classification is accurate
  - LLM context builder produces well-formed output
"""
import os
import sys
import unittest
import platform

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.platform_paths import (
    detect_os, get_default_paths, get_noisy_dirs,
    get_file_category, get_tier_for_path, get_paths_summary,
    get_all_os_paths, MonitorTarget,
    LINUX_PATHS, WINDOWS_PATHS, MACOS_PATHS,
)
from core.os_context import (
    get_os_info, get_context_for_llm, format_context_for_prompt,
    get_recent_system_updates,
)


class TestDetectOS(unittest.TestCase):
    """Tests for OS detection."""

    def test_returns_valid_string(self):
        result = detect_os()
        self.assertIn(result, ('linux', 'windows', 'darwin'))

    def test_matches_platform_system(self):
        system = platform.system().lower()
        result = detect_os()
        if system == 'windows':
            self.assertEqual(result, 'windows')
        elif system == 'darwin':
            self.assertEqual(result, 'darwin')
        else:
            self.assertEqual(result, 'linux')


class TestDefaultPaths(unittest.TestCase):
    """Tests for monitoring path retrieval."""

    def test_all_tiers_populated(self):
        for os_name in ('linux', 'windows', 'darwin'):
            paths = get_default_paths(target_os=os_name)
            self.assertIn(1, paths, f"Tier 1 missing for {os_name}")
            self.assertIn(2, paths, f"Tier 2 missing for {os_name}")
            self.assertIn(3, paths, f"Tier 3 missing for {os_name}")
            self.assertIn(4, paths, f"Tier 4 missing for {os_name}")

    def test_tier_1_non_empty(self):
        for os_name in ('linux', 'windows', 'darwin'):
            paths = get_default_paths(tier=1, target_os=os_name)
            self.assertTrue(len(paths[1]) > 0, f"Tier 1 empty for {os_name}")

    def test_single_tier_request(self):
        paths = get_default_paths(tier=2, target_os='linux')
        self.assertIn(2, paths)
        self.assertNotIn(1, paths)
        self.assertNotIn(3, paths)

    def test_monitor_target_fields(self):
        paths = get_default_paths(tier=1, target_os='linux')
        target = paths[1][0]
        self.assertIsInstance(target, MonitorTarget)
        self.assertTrue(len(target.path) > 0)
        self.assertTrue(len(target.description) > 0)
        self.assertTrue(len(target.category) > 0)

    def test_all_os_paths_returns_all(self):
        all_paths = get_all_os_paths()
        self.assertIn('linux', all_paths)
        self.assertIn('windows', all_paths)
        self.assertIn('darwin', all_paths)


class TestNoisyDirs(unittest.TestCase):
    """Tests for noisy directory exclusions."""

    def test_linux_excludes(self):
        dirs = get_noisy_dirs(target_os='linux')
        self.assertIsInstance(dirs, list)
        self.assertTrue(len(dirs) > 0)
        # /var/cache should always be noisy on Linux
        self.assertIn('/var/cache', dirs)

    def test_windows_excludes(self):
        dirs = get_noisy_dirs(target_os='windows')
        self.assertTrue(len(dirs) > 0)

    def test_macos_excludes(self):
        dirs = get_noisy_dirs(target_os='darwin')
        self.assertTrue(len(dirs) > 0)


class TestFileCategory(unittest.TestCase):
    """Tests for file category classification."""

    def test_linux_binary(self):
        self.assertEqual(get_file_category('/usr/bin/ls', target_os='linux'), 'binary')

    def test_linux_auth(self):
        self.assertEqual(get_file_category('/etc/shadow', target_os='linux'), 'auth')

    def test_linux_config(self):
        self.assertEqual(get_file_category('/etc/nginx/nginx.conf', target_os='linux'), 'config')

    def test_linux_log(self):
        self.assertEqual(get_file_category('/var/log/syslog', target_os='linux'), 'log')

    def test_windows_binary(self):
        cat = get_file_category(r'C:\Windows\System32\cmd.exe', target_os='windows')
        self.assertEqual(cat, 'binary')

    def test_windows_auth(self):
        cat = get_file_category(r'C:\Windows\System32\config\SAM', target_os='windows')
        self.assertEqual(cat, 'auth')

    def test_windows_driver(self):
        cat = get_file_category(r'C:\Windows\System32\drivers\ntfs.sys', target_os='windows')
        self.assertEqual(cat, 'driver')

    def test_macos_library(self):
        cat = get_file_category('/System/Library/Frameworks/AppKit.framework', target_os='darwin')
        self.assertEqual(cat, 'library')

    def test_macos_auth(self):
        cat = get_file_category('/var/db/dslocal/nodes/Default', target_os='darwin')
        self.assertEqual(cat, 'auth')

    def test_extension_fallback(self):
        cat = get_file_category('/some/random/file.pem', target_os='linux')
        self.assertEqual(cat, 'auth')

    def test_unknown(self):
        cat = get_file_category('/random/data.xyz', target_os='linux')
        self.assertEqual(cat, 'unknown')


class TestTierLookup(unittest.TestCase):
    """Tests for tier-for-path lookup."""

    def test_linux_tier1(self):
        tier = get_tier_for_path('/bin/ls', target_os='linux')
        self.assertEqual(tier, 1)

    def test_linux_tier2(self):
        tier = get_tier_for_path('/var/log/auth.log', target_os='linux')
        self.assertEqual(tier, 2)

    def test_unknown_path(self):
        tier = get_tier_for_path('/random/unknown/file.txt', target_os='linux')
        self.assertIsNone(tier)


class TestPathsSummary(unittest.TestCase):
    """Tests for the JSON-serializable paths summary."""

    def test_summary_structure(self):
        summary = get_paths_summary(target_os='windows')
        self.assertIsInstance(summary, dict)
        self.assertIn('1', summary)
        self.assertIn('2', summary)
        for tier_paths in summary.values():
            self.assertIsInstance(tier_paths, list)
            if tier_paths:
                item = tier_paths[0]
                self.assertIn('path', item)
                self.assertIn('description', item)
                self.assertIn('category', item)


class TestOSContext(unittest.TestCase):
    """Tests for os_context.py."""

    def test_os_info(self):
        info = get_os_info()
        self.assertIn('os', info)
        self.assertIn('os_name', info)
        self.assertIn(info['os'], ('linux', 'windows', 'darwin'))

    def test_context_for_llm_structure(self):
        ctx = get_context_for_llm('/usr/bin/ls', 'modified', target_os='linux')
        self.assertIn('os_info', ctx)
        self.assertIn('file_category', ctx)
        self.assertIn('monitoring_tier', ctx)
        self.assertIn('tier_label', ctx)
        self.assertIn('recent_updates', ctx)
        self.assertIn('update_details', ctx)

    def test_context_file_category(self):
        ctx = get_context_for_llm('/etc/shadow', 'modified', target_os='linux')
        self.assertEqual(ctx['file_category'], 'auth')

    def test_context_tier(self):
        ctx = get_context_for_llm('/bin/ls', 'modified', target_os='linux')
        self.assertEqual(ctx['monitoring_tier'], 1)

    def test_format_prompt(self):
        ctx = get_context_for_llm('/bin/ls', 'modified', target_os='linux')
        prompt_block = format_context_for_prompt(ctx)
        self.assertIsInstance(prompt_block, str)
        self.assertIn('Operating System', prompt_block)
        self.assertIn('File Category', prompt_block)
        self.assertIn('Monitoring Tier', prompt_block)

    def test_recent_updates_returns_dict(self):
        updates = get_recent_system_updates()
        self.assertIn('recent_updates', updates)
        self.assertIsInstance(updates['recent_updates'], bool)
        self.assertIn('details', updates)


if __name__ == '__main__':
    unittest.main()
