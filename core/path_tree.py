"""Helpers for maintaining a lightweight directory tree index."""
from __future__ import annotations

import os
from datetime import datetime
from typing import MutableMapping

from sqlalchemy.orm import Session

from .models import DirectoryNode, FileRecord


def ensure_directory_node(
    session: Session,
    directory_path: str,
    cache: MutableMapping[str, DirectoryNode] | None = None,
) -> DirectoryNode:
    """Return/create the directory node for an absolute directory path."""
    full_path = os.path.abspath(directory_path)
    if cache is not None and full_path in cache:
        return cache[full_path]

    existing = session.query(DirectoryNode).filter_by(full_path=full_path).first()
    if existing:
        existing.last_seen = datetime.utcnow()
        if cache is not None:
            cache[full_path] = existing
        return existing

    parent_path = os.path.dirname(full_path)
    if parent_path and parent_path != full_path:
        parent = ensure_directory_node(session, parent_path, cache)
        parent_id = parent.id
        depth = parent.depth + 1
    else:
        parent_id = None
        depth = 0

    node = DirectoryNode(
        parent_id=parent_id,
        name=_directory_name(full_path),
        full_path=full_path,
        depth=depth,
        last_seen=datetime.utcnow(),
    )
    session.add(node)
    session.flush()

    if cache is not None:
        cache[full_path] = node
    return node


def assign_file_location(
    session: Session,
    record: FileRecord,
    file_path: str,
    cache: MutableMapping[str, DirectoryNode] | None = None,
) -> DirectoryNode:
    """Attach a file record to its directory node and current basename."""
    directory = ensure_directory_node(session, os.path.dirname(file_path), cache)
    record.directory_id = directory.id
    record.name = os.path.basename(file_path)
    return directory


def _directory_name(path: str) -> str:
    trimmed = path.rstrip("\\/")
    name = os.path.basename(trimmed)
    return name or path

