"""Regression coverage for scan scope and stoppable background workers."""

import threading

from core import background_analysis
from core.file_content import UNREADABLE_CONTENT, read_text_snippet
from core.notification_dispatcher import NotificationDispatcher
from core.scanner import _walk_directory_with_stats
from core.watcher import _should_ignore


def test_dependency_directories_remain_in_scan_scope(tmp_path):
    included = [
        tmp_path / ".git" / "config",
        tmp_path / "node_modules" / "package" / "index.js",
        tmp_path / ".venv" / "Lib" / "site-packages" / "module.py",
    ]
    excluded = tmp_path / "__pycache__" / "module.pyc"

    for path in [*included, excluded]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture\n", encoding="utf-8")

    files, stats = _walk_directory_with_stats(str(tmp_path))
    scanned_paths = set(files)

    assert all(str(path.resolve()) in scanned_paths for path in included)
    assert str(excluded.resolve()) not in scanned_paths
    assert stats["excluded_file_count"] == 1
    assert stats["excluded_dir_count"] == 1

    assert _should_ignore(str(included[0])) is False
    assert _should_ignore(str(included[1])) is False
    assert _should_ignore(str(included[2])) is False
    assert _should_ignore(str(excluded)) is True


def test_text_snippet_strips_utf8_bom_and_rejects_binary(tmp_path):
    text_file = tmp_path / "script.py"
    text_file.write_bytes(b"\xef\xbb\xbfprint('ok')\n")
    binary_file = tmp_path / "module.bin"
    binary_file.write_bytes(b"header\x00payload")

    assert read_text_snippet(str(text_file)) == "print('ok')\n"
    assert read_text_snippet(str(binary_file)) == UNREADABLE_CONTENT


def test_analysis_worker_honours_stop_event(monkeypatch):
    worker_ran = threading.Event()
    stop_event = threading.Event()

    def process_once():
        worker_ran.set()
        return 0

    monkeypatch.setattr(background_analysis, "process_pending_analysis", process_once)
    worker = threading.Thread(
        target=background_analysis.run_analysis_loop,
        args=(10.0, stop_event),
    )
    worker.start()

    assert worker_ran.wait(timeout=1.0)
    stop_event.set()
    worker.join(timeout=1.0)
    assert worker.is_alive() is False


def test_notification_worker_honours_stop_event():
    dispatcher = NotificationDispatcher()
    stop_event = threading.Event()
    stop_event.set()

    worker = threading.Thread(
        target=dispatcher.dispatch_loop,
        args=(10.0, stop_event),
    )
    worker.start()
    worker.join(timeout=1.0)

    assert worker.is_alive() is False


def test_application_lifespan_stops_both_workers(monkeypatch):
    from fastapi.testclient import TestClient
    from core import api

    analysis_started = threading.Event()
    notifications_started = threading.Event()
    analysis_stopped = threading.Event()
    notifications_stopped = threading.Event()
    services_stopped = threading.Event()

    def wait_for_analysis_stop(_interval, stop_event):
        analysis_started.set()
        stop_event.wait(timeout=2.0)
        analysis_stopped.set()

    def wait_for_notification_stop(_interval, stop_event):
        notifications_started.set()
        stop_event.wait(timeout=2.0)
        notifications_stopped.set()

    monkeypatch.setattr(api, "configure_preferred_ollama_model", lambda: None)
    monkeypatch.setattr(api, "run_analysis_loop", wait_for_analysis_stop)
    monkeypatch.setattr(api.dispatcher, "dispatch_loop", wait_for_notification_stop)
    monkeypatch.setattr(api, "_stop_runtime_services", services_stopped.set)

    with TestClient(api.app) as client:
        assert client.get("/api/health").status_code == 200
        assert analysis_started.wait(timeout=1.0)
        assert notifications_started.wait(timeout=1.0)

    assert services_stopped.is_set()
    assert analysis_stopped.wait(timeout=1.0)
    assert notifications_stopped.wait(timeout=1.0)
