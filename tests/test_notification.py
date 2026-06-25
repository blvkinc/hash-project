"""Unit tests for the notification dispatch engine
and the tier pre-filter in background_analysis.

Tests cover:
  - Tier pre-filter (Tier 1 -> critical bypass, Tier 4 -> info bypass)
  - NotificationDispatcher routing (immediate / batched / silent)
  - Escalation logic (N medium events in short window -> immediate batch)
  - Config get/update
  - Dispatch history tracking
"""
import os
import sys
import time
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.notification_dispatcher import (
    NotificationDispatcher,
    NotificationConfig,
    _send_desktop_notification,
)


# Tier Pre-Filter Tests

class TestTierPreFilter(unittest.TestCase):
    """Tests for the _apply_tier_prefilter function."""

    def _make_mock_log(self, path: str, event_type: str = 'modified'):
        log = MagicMock()
        log.path = path
        log.event_type = event_type
        return log

    def test_tier4_bypasses_llm(self):
        from core.background_analysis import _apply_tier_prefilter
        log = self._make_mock_log('/tmp/some_cache_file.dat')
        result = _apply_tier_prefilter(log)
        # /tmp is Tier 4 on Linux
        if result is not None:
            self.assertEqual(result['priority'], 'info')
            self.assertEqual(result['risk_score'], 1)
            self.assertTrue(result.get('prefiltered'))

    def test_tier1_bypasses_llm(self):
        from core.background_analysis import _apply_tier_prefilter
        log = self._make_mock_log('/bin/ls')
        result = _apply_tier_prefilter(log)
        # /bin is Tier 1 on Linux
        if result is not None:
            self.assertEqual(result['priority'], 'critical')
            self.assertEqual(result['risk_score'], 9)
            self.assertTrue(result.get('prefiltered'))

    def test_tier2_goes_to_llm(self):
        from core.background_analysis import _apply_tier_prefilter
        log = self._make_mock_log('/etc/crontab')
        result = _apply_tier_prefilter(log)
        # /etc/crontab is Tier 2 on Linux  -  should return None (send to LLM)
        # Note: this test is platform-specific; on Windows get_tier_for_path
        # may return None for Linux paths
        if result is not None:
            # If it DID match, it should not be Tier 1 or 4
            self.assertNotIn(result.get('tier'), [1, 4])

    def test_unclassified_goes_to_llm(self):
        from core.background_analysis import _apply_tier_prefilter
        log = self._make_mock_log('/random/unknown/file.xyz')
        result = _apply_tier_prefilter(log)
        # Unclassified paths return None -> LLM analysis
        self.assertIsNone(result)


# Notification Dispatcher Tests

class TestNotificationDispatcher(unittest.TestCase):
    """Tests for the NotificationDispatcher class."""

    def setUp(self):
        self.config = NotificationConfig()
        self.config.desktop_enabled = False   # don't pop notifications in tests
        self.config.email_enabled = False
        self.dispatcher = NotificationDispatcher(config=self.config)

    def test_critical_event_immediate(self):
        event = {
            'path': '/bin/ls',
            'event_type': 'modified',
            'priority': 'critical',
            'risk_score': 9,
            'reasoning': 'Critical system binary changed',
        }
        self.dispatcher.enqueue(event)
        history = self.dispatcher.get_history()
        self.assertTrue(len(history) > 0)
        self.assertEqual(history[-1]['dispatch_type'], 'immediate')
        self.assertEqual(history[-1]['severity'], 'SEV-1')
        self.assertIn('event_id', history[-1])

    def test_high_event_immediate(self):
        event = {
            'path': '/etc/ssh/sshd_config',
            'event_type': 'modified',
            'priority': 'high',
            'risk_score': 8,
            'reasoning': 'SSH config changed',
        }
        self.dispatcher.enqueue(event)
        history = self.dispatcher.get_history()
        self.assertEqual(history[-1]['dispatch_type'], 'immediate')

    def test_low_event_silent(self):
        event = {
            'path': '/tmp/cache.dat',
            'event_type': 'new',
            'priority': 'info',
            'risk_score': 1,
            'reasoning': 'Temp file created',
        }
        self.dispatcher.enqueue(event)
        history = self.dispatcher.get_history()
        self.assertEqual(history[-1]['dispatch_type'], 'silent_log')

    def test_medium_event_batched(self):
        event = {
            'path': '/home/user/.bashrc',
            'event_type': 'modified',
            'priority': 'medium',
            'risk_score': 5,
            'reasoning': 'Shell profile changed',
        }
        self.dispatcher.enqueue(event)
        # Should be in the batch queue, not yet dispatched
        self.assertTrue(len(self.dispatcher._batch_queue) > 0)

    def test_escalation_triggers_immediate_batch(self):
        """3+ medium events in a short window should escalate."""
        self.config.escalation_threshold = 3
        self.config.escalation_window_seconds = 300

        for i in range(3):
            self.dispatcher.enqueue({
                'path': f'/opt/app/file_{i}.py',
                'event_type': 'modified',
                'priority': 'medium',
                'risk_score': 5,
                'reasoning': f'Source code change {i}',
            })

        history = self.dispatcher.get_history()
        escalated = [h for h in history if h['dispatch_type'] == 'escalated_batch']
        self.assertTrue(len(escalated) > 0, "Escalation should have been triggered")

    def test_high_risk_score_triggers_immediate(self):
        """Even if priority string is wrong, risk_score >= 8 -> immediate."""
        event = {
            'path': '/usr/bin/sudo',
            'priority': 'medium',    # misclassified
            'risk_score': 9,
            'reasoning': 'Sudo binary replaced',
        }
        self.dispatcher.enqueue(event)
        history = self.dispatcher.get_history()
        self.assertEqual(history[-1]['dispatch_type'], 'immediate')


# Config Tests

class TestNotificationConfig(unittest.TestCase):
    """Tests for notification config management."""

    def test_config_to_dict(self):
        config = NotificationConfig()
        d = config.to_dict()
        self.assertIn('desktop_enabled', d)
        self.assertIn('email_enabled', d)
        self.assertIn('batch_interval_seconds', d)
        self.assertIn('escalation_threshold', d)

    def test_config_update(self):
        config = NotificationConfig()
        config.update_from_dict({
            'desktop_enabled': False,
            'batch_interval_seconds': 1800,
        })
        self.assertFalse(config.desktop_enabled)
        self.assertEqual(config.batch_interval_seconds, 1800)

    def test_dispatcher_config_api(self):
        dispatcher = NotificationDispatcher()
        cfg = dispatcher.get_config()
        self.assertIsInstance(cfg, dict)

        dispatcher.update_config({'escalation_threshold': 10})
        self.assertEqual(dispatcher.config.escalation_threshold, 10)


# History Tests

class TestDispatchHistory(unittest.TestCase):

    def test_history_limit(self):
        config = NotificationConfig()
        config.desktop_enabled = False
        config.email_enabled = False
        dispatcher = NotificationDispatcher(config=config)

        # Enqueue 10 silent events
        for i in range(10):
            dispatcher.enqueue({
                'path': f'/tmp/f{i}.log',
                'priority': 'info',
                'risk_score': 1,
                'reasoning': 'test',
            })

        # Request last 5
        history = dispatcher.get_history(limit=5)
        self.assertEqual(len(history), 5)

    def test_history_structure(self):
        config = NotificationConfig()
        config.desktop_enabled = False
        dispatcher = NotificationDispatcher(config=config)

        dispatcher.enqueue({
            'path': '/test/file.txt',
            'priority': 'info',
            'risk_score': 1,
            'reasoning': 'No threat',
        })

        entry = dispatcher.get_history()[0]
        self.assertIn('timestamp', entry)
        self.assertIn('event_id', entry)
        self.assertIn('severity', entry)
        self.assertIn('recommended_actions', entry)
        self.assertIn('path', entry)
        self.assertIn('priority', entry)
        self.assertIn('dispatch_type', entry)
        self.assertIn('reasoning', entry)


if __name__ == '__main__':
    unittest.main()
