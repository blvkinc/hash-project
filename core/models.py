from sqlalchemy import Column, Integer, String, DateTime, Boolean, JSON, Float
from sqlalchemy.orm import declarative_base
from datetime import datetime

Base = declarative_base()


class FileIdentity(Base):
    """Stable logical identity for a monitored file across path changes."""
    __tablename__ = 'file_identities'

    id = Column(Integer, primary_key=True)
    platform_file_id = Column(String, nullable=True, index=True)
    current_path = Column(String, nullable=False, index=True)
    current_directory_id = Column(Integer, nullable=True, index=True)
    current_name = Column(String, nullable=True, index=True)
    current_hash = Column(String, nullable=True, index=True)
    current_fast_hash = Column(String, nullable=True, index=True)
    current_security_hash = Column(String, nullable=True, index=True)
    size = Column(Integer, nullable=True)
    mtime = Column(Float, nullable=True)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, index=True)

    def __repr__(self):
        return f"<FileIdentity(path='{self.current_path}', active={self.is_active})>"


class FileRecord(Base):
    """Stores the current known state of each monitored file."""
    __tablename__ = 'file_records'

    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, nullable=True, index=True)
    path = Column(String, unique=True, index=True, nullable=False)
    directory_id = Column(Integer, nullable=True, index=True)
    name = Column(String, nullable=True, index=True)
    hash = Column(String, nullable=False, index=True)
    hash_algorithm = Column(String, nullable=True, index=True)
    fast_hash = Column(String, nullable=True, index=True)
    security_hash = Column(String, nullable=True, index=True)
    security_hash_algorithm = Column(String, nullable=True, index=True)
    last_seen = Column(DateTime, default=datetime.utcnow, index=True)
    is_baseline = Column(Boolean, default=True)
    mtime = Column(Float, nullable=True)
    size = Column(Integer, nullable=True)

    def __repr__(self):
        return f"<FileRecord(path='{self.path}', hash='{self.hash[:8]}...')>"


class FileRegistryEntry(Base):
    """Persistent semantic registry for a monitored file identity."""
    __tablename__ = 'file_registry_entries'

    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, nullable=True, unique=True, index=True)
    path = Column(String, nullable=False, index=True)
    normalized_path = Column(String, nullable=False, index=True)
    name = Column(String, nullable=True, index=True)
    tier = Column(Integer, nullable=True, index=True)
    tier_label = Column(String, nullable=True, index=True)
    semantic_role = Column(String, nullable=True, index=True)
    asset_type = Column(String, nullable=True, index=True)
    file_category = Column(String, nullable=True, index=True)
    confidence = Column(String, default='low', index=True)
    reasoning = Column(String, nullable=True)
    expected_change_sources = Column(JSON, nullable=True)
    last_known_good_hash = Column(String, nullable=True, index=True)
    current_hash = Column(String, nullable=True, index=True)
    current_fast_hash = Column(String, nullable=True, index=True)
    current_security_hash = Column(String, nullable=True, index=True)
    hash_algorithm = Column(String, nullable=True, index=True)
    security_hash_algorithm = Column(String, nullable=True, index=True)
    size = Column(Integer, nullable=True)
    mtime = Column(Float, nullable=True)
    path_history = Column(JSON, nullable=True)
    is_active = Column(Boolean, default=True, index=True)
    first_seen = Column(DateTime, default=datetime.utcnow, index=True)
    last_seen = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, index=True)

    def __repr__(self):
        return f"<FileRegistryEntry(path='{self.path}', tier={self.tier}, role='{self.semantic_role}')>"


class DirectoryNode(Base):
    """Directory tree node used for scalable file browsing and grouping."""
    __tablename__ = 'directory_nodes'

    id = Column(Integer, primary_key=True)
    parent_id = Column(Integer, nullable=True, index=True)
    name = Column(String, nullable=False, index=True)
    full_path = Column(String, unique=True, index=True, nullable=False)
    depth = Column(Integer, default=0, index=True)
    last_seen = Column(DateTime, default=datetime.utcnow, index=True)

    def __repr__(self):
        return f"<DirectoryNode(path='{self.full_path}')>"


class ScanSession(Base):
    """Persisted scan run summary and performance counters."""
    __tablename__ = 'scan_sessions'

    id = Column(Integer, primary_key=True)
    root_path = Column(String, nullable=False, index=True)
    trigger = Column(String, default='manual', index=True)
    mode = Column(String, default='metadata_first', index=True)
    status = Column(String, default='queued', index=True)
    started_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime, nullable=True, index=True)
    total_discovered = Column(Integer, default=0)
    baseline_new = Column(Integer, default=0)
    baseline_updated = Column(Integer, default=0)
    baseline_reanalyzed = Column(Integer, default=0)
    baseline_reanalyze_skipped = Column(Integer, default=0)
    baseline_analysis_checked = Column(Integer, default=0)
    baseline_analysis_queued = Column(Integer, default=0)
    baseline_analysis_skipped = Column(Integer, default=0)
    changes_new = Column(Integer, default=0)
    changes_modified = Column(Integer, default=0)
    changes_deleted = Column(Integer, default=0)
    changes_renamed = Column(Integer, default=0)
    hashed = Column(Integer, default=0)
    metadata_skipped = Column(Integer, default=0)
    platform_renames = Column(Integer, default=0)
    errors = Column(Integer, default=0)
    error = Column(String, nullable=True)
    result_json = Column(JSON, nullable=True)

    def __repr__(self):
        return f"<ScanSession(path='{self.root_path}', status='{self.status}')>"


class AnalysisCache(Base):
    """Reusable analysis verdict keyed by content/change context."""
    __tablename__ = 'analysis_cache'

    id = Column(Integer, primary_key=True)
    cache_key = Column(String, unique=True, nullable=False, index=True)
    content_hash = Column(String, nullable=True, index=True)
    context_hash = Column(String, nullable=True, index=True)
    event_type = Column(String, nullable=False, index=True)
    analysis_source = Column(String, nullable=True, index=True)
    priority = Column(String, nullable=True, index=True)
    risk_score = Column(Integer, nullable=True, index=True)
    verdict_json = Column(JSON, nullable=False)
    hit_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, index=True)
    last_hit_at = Column(DateTime, nullable=True, index=True)

    def __repr__(self):
        return f"<AnalysisCache(key='{self.cache_key[:12]}...', hits={self.hit_count})>"


class FileLog(Base):
    """Event log  -  one row per detected change."""
    __tablename__ = 'file_logs'

    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, nullable=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    path = Column(String, nullable=False, index=True)
    event_type = Column(String, nullable=False, index=True)  # new / modified / deleted / renamed
    old_hash = Column(String, nullable=True, index=True)     # hash before change
    new_hash = Column(String, nullable=True, index=True)     # hash after change
    details = Column(String, nullable=True)
    priority = Column(String, default='pending', index=True)  # critical / high / medium / low / info / pending
    risk_score = Column(Integer, nullable=True)
    analysis_json = Column(JSON, nullable=True)
    status = Column(String, default='pending', index=True)    # pending / analyzed / error / recorded
    analyzed_at = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<FileLog(path='{self.path}', event='{self.event_type}', priority='{self.priority}')>"
