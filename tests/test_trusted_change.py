from datetime import datetime, timezone

from core.config import settings
from core.services.trusted_change import correlate_trusted_change


def test_trusted_change_confirms_package_manager_metadata():
    report = correlate_trusted_change(
        file_path="/etc/sudoers",
        event_type="modified",
        event_context={"metadata": {"package_manager": "apt"}},
        registry_context={"expected_change_sources": ["os_update", "package_manager"]},
        event_timestamp=datetime(2026, 6, 16, 10, 0, tzinfo=timezone.utc),
        os_family="linux",
    )

    assert report["result"] == "confirmed"
    assert "package_manager:apt" in report["trusted_sources"]
    assert report["matched_sources"] == ["package_manager:apt"]


def test_trusted_change_confirms_active_maintenance_window(monkeypatch):
    monkeypatch.setattr(settings, "trusted_maintenance_windows", "")
    report = correlate_trusted_change(
        file_path="/etc/ssh/sshd_config",
        event_type="modified",
        event_context={
            "metadata": {
                "maintenance_window": {
                    "id": "patch-42",
                    "start": "2026-06-16T09:30:00+00:00",
                    "end": "2026-06-16T10:30:00+00:00",
                }
            }
        },
        registry_context={"expected_change_sources": ["administrator_maintenance"]},
        event_timestamp=datetime(2026, 6, 16, 10, 0, tzinfo=timezone.utc),
        os_family="linux",
    )

    assert report["result"] == "confirmed"
    assert report["maintenance_window_active"] is True
    assert report["matched_sources"] == ["metadata_maintenance_window:patch-42"]


def test_trusted_change_confirms_runtime_windows_update(monkeypatch):
    monkeypatch.setattr(
        "core.services.trusted_change.get_recent_system_updates",
        lambda target_os=None: {
            "recent_updates": True,
            "package_manager": "Windows Update",
            "details": ["Windows Update log activity detected"],
        },
    )
    report = correlate_trusted_change(
        file_path=r"C:\Windows\System32\drivers\etc\hosts",
        event_type="modified",
        event_context={"metadata": {}},
        registry_context={"expected_change_sources": ["windows_update"]},
        event_timestamp=datetime(2026, 6, 16, 10, 0, tzinfo=timezone.utc),
        os_family="windows",
    )

    assert report["result"] == "confirmed"
    assert "os_update_context:Windows Update" in report["trusted_sources"]
    assert report["evidence"][0]["category"] == "windows_update"


def test_trusted_change_marks_mismatched_source_unknown():
    report = correlate_trusted_change(
        file_path="/var/log/app.log",
        event_type="modified",
        event_context={"metadata": {"package_manager": "apt"}},
        registry_context={"expected_change_sources": ["log_rotation"]},
        event_timestamp=datetime(2026, 6, 16, 10, 0, tzinfo=timezone.utc),
        os_family="linux",
    )

    assert report["result"] == "unknown"
    assert report["trusted_sources"] == []
    assert report["evidence"][0]["status"] == "mismatch"
