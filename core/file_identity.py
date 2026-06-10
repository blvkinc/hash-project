"""Helpers for stable file identity tracking."""
from __future__ import annotations

import os
from datetime import datetime
from typing import MutableMapping

from sqlalchemy.orm import Session

from .models import DirectoryNode, FileIdentity, FileRecord
from .path_tree import ensure_directory_node


def ensure_file_identity(
    session: Session,
    path: str,
    metadata: dict | None = None,
    file_hash: str | None = None,
    fast_hash: str | None = None,
    security_hash: str | None = None,
    directory_cache: MutableMapping[str, DirectoryNode] | None = None,
    platform_file_id: str | None = None,
) -> FileIdentity:
    """Return/create the stable identity for a monitored file."""
    abs_path = os.path.abspath(path)
    platform_id = platform_file_id or _metadata_platform_file_id(metadata)
    identity = None

    if platform_id:
        identity = (
            session.query(FileIdentity)
            .filter(FileIdentity.platform_file_id == platform_id)
            .order_by(FileIdentity.updated_at.desc())
            .first()
        )

    if identity is None:
        identity = (
            session.query(FileIdentity)
            .filter(FileIdentity.current_path == abs_path, FileIdentity.is_active.is_(True))
            .order_by(FileIdentity.updated_at.desc())
            .first()
        )

    if identity is None:
        identity = FileIdentity(
            platform_file_id=platform_id,
            current_path=abs_path,
            is_active=True,
            created_at=datetime.utcnow(),
        )
        session.add(identity)

    update_file_identity(
        session=session,
        identity=identity,
        path=abs_path,
        metadata=metadata,
        file_hash=file_hash,
        fast_hash=fast_hash,
        security_hash=security_hash,
        directory_cache=directory_cache,
        platform_file_id=platform_id,
    )
    session.flush()
    return identity


def update_file_identity(
    session: Session,
    identity: FileIdentity,
    path: str,
    metadata: dict | None = None,
    file_hash: str | None = None,
    fast_hash: str | None = None,
    security_hash: str | None = None,
    directory_cache: MutableMapping[str, DirectoryNode] | None = None,
    platform_file_id: str | None = None,
) -> FileIdentity:
    """Refresh identity metadata after scan/watch events."""
    abs_path = os.path.abspath(path)
    directory = ensure_directory_node(session, os.path.dirname(abs_path), directory_cache)
    platform_id = platform_file_id or _metadata_platform_file_id(metadata)

    if platform_id:
        identity.platform_file_id = platform_id
    identity.current_path = abs_path
    identity.current_directory_id = directory.id
    identity.current_name = os.path.basename(abs_path)
    if file_hash is not None:
        identity.current_hash = file_hash
    if fast_hash is not None:
        identity.current_fast_hash = fast_hash
    if security_hash is not None:
        identity.current_security_hash = security_hash
    if metadata:
        identity.size = metadata.get('size')
        identity.mtime = metadata.get('mtime')
    identity.is_active = True
    identity.updated_at = datetime.utcnow()
    return identity


def attach_identity_to_record(
    session: Session,
    record: FileRecord,
    path: str,
    metadata: dict | None = None,
    file_hash: str | None = None,
    fast_hash: str | None = None,
    security_hash: str | None = None,
    directory_cache: MutableMapping[str, DirectoryNode] | None = None,
    platform_file_id: str | None = None,
) -> FileIdentity:
    """Ensure a record has a stable file identity and current tree location."""
    identity = ensure_file_identity(
        session=session,
        path=path,
        metadata=metadata,
        file_hash=file_hash,
        fast_hash=fast_hash,
        security_hash=security_hash,
        directory_cache=directory_cache,
        platform_file_id=platform_file_id,
    )
    record.file_id = identity.id
    record.directory_id = identity.current_directory_id
    record.name = identity.current_name
    return identity


def find_identity_by_platform_id(
    session: Session,
    platform_file_id: str | None,
) -> FileIdentity | None:
    """Find the most recent identity for an OS platform file ID."""
    if not platform_file_id:
        return None
    return (
        session.query(FileIdentity)
        .filter(FileIdentity.platform_file_id == platform_file_id)
        .order_by(FileIdentity.updated_at.desc())
        .first()
    )


def mark_identity_inactive(identity: FileIdentity | None) -> None:
    """Mark a file identity inactive after deletion."""
    if identity is None:
        return
    identity.is_active = False
    identity.updated_at = datetime.utcnow()


def _metadata_platform_file_id(metadata: dict | None) -> str | None:
    if not metadata:
        return None
    value = metadata.get('platform_file_id')
    return str(value) if value else None
