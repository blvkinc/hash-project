"""Regression tests for background analyser path containment checks."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.background_analysis import _is_under_active_watch, update_monitor_state


def test_active_watch_requires_real_path_containment(tmp_path):
    watched = tmp_path / "target"
    watched.mkdir()
    sibling = tmp_path / "target-other"
    sibling.mkdir()
    child = watched / "nested" / "event.txt"

    update_monitor_state(False, [str(watched)])

    assert _is_under_active_watch(str(child)) is True
    assert _is_under_active_watch(str(sibling / "event.txt")) is False
