"""Coordinate one FileWatcher per monitored directory.

Extracted from core.api to keep route handlers focused on HTTP concerns.
"""
import os
import threading
from typing import Dict, List, Optional

from core.watcher import FileWatcher


class WatchManager:
    """Manage multiple directory watchers concurrently."""

    def __init__(self):
        self._watchers: Dict[str, FileWatcher] = {}
        self._lock = threading.Lock()

    def start(self, path: str) -> bool:
        abs_path = os.path.abspath(path)
        with self._lock:
            existing = self._watchers.get(abs_path)
            if existing and existing.is_running:
                return False
            watcher = FileWatcher(abs_path)
            watcher.start()
            self._watchers[abs_path] = watcher
            return True

    def stop(self, path: Optional[str] = None) -> int:
        with self._lock:
            if path:
                abs_path = os.path.abspath(path)
                watcher = self._watchers.pop(abs_path, None)
                if watcher and watcher.is_running:
                    watcher.stop()
                    return 1
                return 0

            stopped = 0
            for abs_path, watcher in list(self._watchers.items()):
                if watcher and watcher.is_running:
                    watcher.stop()
                    stopped += 1
                self._watchers.pop(abs_path, None)
            return stopped

    def active_paths(self) -> List[str]:
        with self._lock:
            dead = []
            active = []
            for path, watcher in self._watchers.items():
                if watcher and watcher.is_running:
                    active.append(path)
                else:
                    dead.append(path)
            for path in dead:
                self._watchers.pop(path, None)
            return sorted(active)

    def is_active(self) -> bool:
        return bool(self.active_paths())
