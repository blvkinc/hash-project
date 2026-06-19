import hashlib
import logging
import os

from .config import settings

logger = logging.getLogger(__name__)


def _blake3_max_threads(blake3_module) -> int:
    """Resolve configured BLAKE3 worker count."""
    raw = str(settings.blake3_max_threads or "auto").strip().lower()
    if raw in {"auto", "all", "-1"}:
        return blake3_module.blake3.AUTO
    try:
        return max(1, int(raw))
    except ValueError:
        if not getattr(_blake3_max_threads, "_warned", False):
            logger.warning(
                "Invalid FIM_BLAKE3_MAX_THREADS=%r; using BLAKE3 auto threading.",
                raw,
            )
            _blake3_max_threads._warned = True  # type: ignore[attr-defined]
        return blake3_module.blake3.AUTO


def _get_hasher(algorithm: str):
    """
    Return a fresh hash-state object for the requested algorithm.

    Supports anything in hashlib + 'blake3' (optional dep). Falls back
    to sha256 with a single warning if blake3 was requested but the
    library isn't installed  -  we never silently corrupt a baseline.
    """
    algorithm = (algorithm or 'sha256').lower()

    if algorithm in {'xxh3_128', 'xxhash', 'xxh3'}:
        try:
            import xxhash
            return xxhash.xxh3_128()
        except ImportError:
            if not getattr(_get_hasher, "_xxhash_warned", False):
                logger.warning(
                    "settings.hash_algorithm=%s but the xxhash package is "
                    "not installed; falling back to BLAKE3.",
                    algorithm,
                )
                _get_hasher._xxhash_warned = True  # type: ignore[attr-defined]
            algorithm = 'blake3'

    if algorithm == 'blake3':
        try:
            import blake3
            return blake3.blake3(max_threads=_blake3_max_threads(blake3))
        except ImportError:
            if not getattr(_get_hasher, "_warned", False):
                logger.warning(
                    "settings.hash_algorithm=blake3 but the blake3 package is "
                    "not installed; falling back to sha256. Install with "
                    "`pip install blake3` to enable."
                )
                _get_hasher._warned = True  # type: ignore[attr-defined]
            return hashlib.sha256()

    try:
        return getattr(hashlib, algorithm)()
    except AttributeError as exc:
        raise ValueError(f"Unknown hash algorithm: {algorithm}") from exc


def calculate_file_hash(filepath: str, algorithm: str | None = None) -> str:
    """
    Calculate the hex digest of a file in large chunks.

    When `algorithm` is None, reads `settings.hash_algorithm` (default xxh3_128).
    """
    hash_func = _get_hasher(algorithm or settings.hash_algorithm)
    chunk_size = max(8192, int(settings.hash_chunk_size or 0))
    buffer = bytearray(chunk_size)
    view = memoryview(buffer)
    with open(filepath, 'rb', buffering=0) as f:
        while True:
            bytes_read = f.readinto(buffer)
            if not bytes_read:
                break
            hash_func.update(view[:bytes_read])
    return hash_func.hexdigest()


def calculate_security_file_hash(filepath: str) -> str:
    """Calculate the configured cryptographic security hash for a file."""
    return calculate_file_hash(filepath, algorithm=settings.security_hash_algorithm)


def platform_file_id_from_stat(file_stat: os.stat_result) -> str | None:
    """
    Return the OS-reported stable file identity when available.

    On NTFS this maps to Python's stat inode/file-index data. It gives the
    scanner a metadata-only way to connect renames before falling back to a
    content hash comparison.
    """
    st_ino = getattr(file_stat, 'st_ino', None)
    st_dev = getattr(file_stat, 'st_dev', None)
    if st_ino in (None, 0) or st_dev is None:
        return None
    return f"{st_dev}:{st_ino}"


def get_file_metadata(filepath: str) -> dict:
    """
    Extracts metadata from a file.
    Returns a dictionary containing size, mtime, mode, owner, group.
    Note: Owner/Group IDs (uid/gid) are more relevant on Unix systems.
    """
    try:
        file_stat = os.stat(filepath)
        metadata = {
            'path': filepath,
            'size': file_stat.st_size,
            'mtime': file_stat.st_mtime,
            'platform_file_id': platform_file_id_from_stat(file_stat),
            'mode': file_stat.st_mode,
            'uid': file_stat.st_uid,
            'gid': file_stat.st_gid,
        }
        return metadata
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"Error getting metadata for {filepath}: {e}")
        return None
