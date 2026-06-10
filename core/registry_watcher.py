"""
registry_watcher.py - Lightweight Windows registry polling watcher.

Monitors a set of registry keys and emits change events when values/subkeys change.
Designed to complement filesystem monitoring for persistence-sensitive keys.
"""

import hashlib
import json
import logging
import os
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

try:
    import winreg  # type: ignore
except Exception:  # pragma: no cover - non-Windows environments
    winreg = None  # type: ignore

logger = logging.getLogger(__name__)


def is_registry_supported() -> bool:
    return os.name == 'nt' and winreg is not None


class RegistryWatcher:
    """Poll registry paths and emit change callbacks."""

    def __init__(
        self,
        paths: List[str],
        on_change: Callable[[str, str, Optional[str], Optional[str], str, str, dict], None],
        poll_interval: float = 5.0,
    ):
        self.paths = self._dedupe_paths(paths)
        self.on_change = on_change
        self.poll_interval = max(1.0, float(poll_interval))

        self._snapshots: Dict[str, dict] = {}
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._running = False
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self) -> bool:
        if not is_registry_supported() or not self.paths:
            return False

        with self._lock:
            if self._running:
                return False
            self._running = True
            self._stop_event.clear()
            self._initialize_snapshots()
            self._thread = threading.Thread(target=self._run_loop, daemon=True)
            self._thread.start()

        logger.info(f"Registry watcher started for {len(self.paths)} path(s).")
        return True

    def stop(self) -> None:
        with self._lock:
            if not self._running:
                return
            self._running = False
            self._stop_event.set()
            t = self._thread
            self._thread = None

        if t:
            t.join(timeout=5.0)
        logger.info("Registry watcher stopped.")

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            for path in self.paths:
                try:
                    self._poll_path(path)
                except Exception as exc:
                    logger.debug(f"Registry polling error for {path}: {exc}")
            self._stop_event.wait(self.poll_interval)

    def _initialize_snapshots(self) -> None:
        self._snapshots = {}
        for path in self.paths:
            snap = self._snapshot_path(path)
            if snap is not None:
                self._snapshots[path] = snap

    def _poll_path(self, path: str) -> None:
        current = self._snapshot_path(path)
        if current is None:
            return

        previous = self._snapshots.get(path)
        if previous is None:
            self._snapshots[path] = current
            return

        if previous == current:
            return

        event_type, details, diff_text = self._describe_change(path, previous, current)
        old_hash = self._hash_snapshot(previous) if previous.get('exists') else None
        new_hash = self._hash_snapshot(current) if current.get('exists') else None
        metadata = {
            'source': 'registry',
            'path': path,
            'previous': previous,
            'current': current,
            'value_count': len(current.get('values', [])) if current.get('exists') else 0,
        }

        self.on_change(path, event_type, old_hash, new_hash, details, diff_text, metadata)
        self._snapshots[path] = current

    def _snapshot_path(self, path: str) -> Optional[dict]:
        parsed = self._parse_registry_path(path)
        if not parsed:
            return None

        hive, subkey = parsed
        try:
            access = winreg.KEY_READ  # type: ignore[attr-defined]
            with winreg.OpenKey(hive, subkey, 0, access) as key_handle:  # type: ignore[arg-type]
                subkey_count, value_count, _ = winreg.QueryInfoKey(key_handle)
                values = []
                for i in range(value_count):
                    try:
                        name, data, value_type = winreg.EnumValue(key_handle, i)
                    except OSError:
                        continue
                    values.append({
                        'name': name or '(Default)',
                        'type': self._registry_type_name(value_type),
                        'data': self._normalize_value_data(data),
                    })

                values.sort(key=lambda v: (v['name'], v['type']))
                return {
                    'exists': True,
                    'subkey_count': int(subkey_count),
                    'values': values,
                }

        except FileNotFoundError:
            return {
                'exists': False,
                'subkey_count': 0,
                'values': [],
            }
        except PermissionError:
            # Skip inaccessible keys to avoid noisy false changes.
            return None
        except OSError:
            return None

    def _describe_change(self, path: str, previous: dict, current: dict) -> Tuple[str, str, str]:
        was_present = bool(previous.get('exists'))
        is_present = bool(current.get('exists'))

        if not was_present and is_present:
            return (
                'new',
                'Registry key created or became readable',
                f'Registry key {path} was absent and is now present.',
            )

        if was_present and not is_present:
            return (
                'deleted',
                'Registry key deleted or became unavailable',
                f'Registry key {path} was present and is now absent.',
            )

        prev_map = self._values_as_map(previous)
        curr_map = self._values_as_map(current)

        added = sorted([name for name in curr_map.keys() if name not in prev_map])
        removed = sorted([name for name in prev_map.keys() if name not in curr_map])
        changed = sorted([name for name in curr_map.keys() if name in prev_map and curr_map[name] != prev_map[name]])

        parts = []
        if added:
            parts.append(f"added values: {', '.join(added[:6])}")
        if removed:
            parts.append(f"removed values: {', '.join(removed[:6])}")
        if changed:
            parts.append(f"changed values: {', '.join(changed[:6])}")

        if current.get('subkey_count') != previous.get('subkey_count'):
            parts.append(
                f"subkey count {previous.get('subkey_count', 0)} -> {current.get('subkey_count', 0)}"
            )

        if not parts:
            parts = ['registry data changed']

        details = 'Registry key values changed'
        diff = f"Registry key {path}: " + '; '.join(parts)
        return 'modified', details, diff

    @staticmethod
    def _values_as_map(snapshot: dict) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for value in snapshot.get('values', []):
            key = str(value.get('name', '(Default)'))
            typ = str(value.get('type', 'UNKNOWN'))
            data = json.dumps(value.get('data'), sort_keys=True)
            out[key] = f"{typ}:{data}"
        return out

    @staticmethod
    def _hash_snapshot(snapshot: dict) -> str:
        blob = json.dumps(snapshot, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(blob.encode('utf-8')).hexdigest()

    @staticmethod
    def _normalize_value_data(data):
        if data is None:
            return None
        if isinstance(data, bytes):
            hexed = data.hex()
            return hexed[:256] + ('...' if len(hexed) > 256 else '')
        if isinstance(data, (list, tuple)):
            return [str(x)[:256] for x in data][:24]
        text = str(data)
        return text[:512] + ('...' if len(text) > 512 else '')

    @staticmethod
    def _registry_type_name(value_type: int) -> str:
        mapping = {
            getattr(winreg, 'REG_SZ', -1): 'REG_SZ',
            getattr(winreg, 'REG_EXPAND_SZ', -1): 'REG_EXPAND_SZ',
            getattr(winreg, 'REG_DWORD', -1): 'REG_DWORD',
            getattr(winreg, 'REG_QWORD', -1): 'REG_QWORD',
            getattr(winreg, 'REG_MULTI_SZ', -1): 'REG_MULTI_SZ',
            getattr(winreg, 'REG_BINARY', -1): 'REG_BINARY',
        }
        return mapping.get(value_type, f'REG_TYPE_{value_type}')

    @staticmethod
    def _parse_registry_path(path: str) -> Optional[Tuple[int, str]]:
        if not path:
            return None

        clean = path.strip().strip('\\')
        if not clean:
            return None

        if '\\' in clean:
            hive_name, subkey = clean.split('\\', 1)
        else:
            hive_name, subkey = clean, ''

        hive_name = hive_name.upper()
        hive_map = {
            'HKLM': getattr(winreg, 'HKEY_LOCAL_MACHINE', None),
            'HKEY_LOCAL_MACHINE': getattr(winreg, 'HKEY_LOCAL_MACHINE', None),
            'HKCU': getattr(winreg, 'HKEY_CURRENT_USER', None),
            'HKEY_CURRENT_USER': getattr(winreg, 'HKEY_CURRENT_USER', None),
            'HKCR': getattr(winreg, 'HKEY_CLASSES_ROOT', None),
            'HKEY_CLASSES_ROOT': getattr(winreg, 'HKEY_CLASSES_ROOT', None),
            'HKU': getattr(winreg, 'HKEY_USERS', None),
            'HKEY_USERS': getattr(winreg, 'HKEY_USERS', None),
        }

        hive = hive_map.get(hive_name)
        if hive is None:
            return None

        return hive, subkey

    @staticmethod
    def _dedupe_paths(paths: List[str]) -> List[str]:
        seen = set()
        ordered = []
        for raw in paths or []:
            p = (raw or '').strip().strip('\\')
            if not p:
                continue
            upper = p.upper()
            if upper in seen:
                continue
            seen.add(upper)
            ordered.append(p)
        return ordered
