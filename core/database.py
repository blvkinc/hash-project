from sqlalchemy import create_engine
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker
from .config import settings
from .models import Base

DATABASE_PATH = settings.database_path
DATABASE_URL = f"sqlite:///{DATABASE_PATH}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Create all tables. Safe to call multiple times."""
    Base.metadata.create_all(bind=engine)
    _ensure_columns()
    _ensure_indexes()


def _ensure_columns():
    """Apply lightweight additive migrations for existing SQLite DBs."""
    with engine.begin() as conn:
        record_columns = _table_columns(conn, "file_records")
        if "file_id" not in record_columns:
            conn.execute(text("ALTER TABLE file_records ADD COLUMN file_id INTEGER"))
        if "directory_id" not in record_columns:
            conn.execute(text("ALTER TABLE file_records ADD COLUMN directory_id INTEGER"))
        if "name" not in record_columns:
            conn.execute(text("ALTER TABLE file_records ADD COLUMN name VARCHAR"))
        if "hash_algorithm" not in record_columns:
            conn.execute(text("ALTER TABLE file_records ADD COLUMN hash_algorithm VARCHAR"))
        if "fast_hash" not in record_columns:
            conn.execute(text("ALTER TABLE file_records ADD COLUMN fast_hash VARCHAR"))
        if "security_hash" not in record_columns:
            conn.execute(text("ALTER TABLE file_records ADD COLUMN security_hash VARCHAR"))
        if "security_hash_algorithm" not in record_columns:
            conn.execute(text("ALTER TABLE file_records ADD COLUMN security_hash_algorithm VARCHAR"))

        log_columns = _table_columns(conn, "file_logs")
        if "file_id" not in log_columns:
            conn.execute(text("ALTER TABLE file_logs ADD COLUMN file_id INTEGER"))

        identity_columns = _table_columns(conn, "file_identities")
        if "current_fast_hash" not in identity_columns:
            conn.execute(text("ALTER TABLE file_identities ADD COLUMN current_fast_hash VARCHAR"))
        if "current_security_hash" not in identity_columns:
            conn.execute(text("ALTER TABLE file_identities ADD COLUMN current_security_hash VARCHAR"))

        registry_columns = _table_columns(conn, "file_registry_entries")
        registry_column_defs = {
            "file_id": "INTEGER",
            "path": "VARCHAR",
            "normalized_path": "VARCHAR",
            "name": "VARCHAR",
            "tier": "INTEGER",
            "tier_label": "VARCHAR",
            "semantic_role": "VARCHAR",
            "asset_type": "VARCHAR",
            "file_category": "VARCHAR",
            "confidence": "VARCHAR",
            "reasoning": "VARCHAR",
            "expected_change_sources": "JSON",
            "last_known_good_hash": "VARCHAR",
            "current_hash": "VARCHAR",
            "current_fast_hash": "VARCHAR",
            "current_security_hash": "VARCHAR",
            "hash_algorithm": "VARCHAR",
            "security_hash_algorithm": "VARCHAR",
            "size": "INTEGER",
            "mtime": "FLOAT",
            "path_history": "JSON",
            "is_active": "BOOLEAN",
            "first_seen": "DATETIME",
            "last_seen": "DATETIME",
            "updated_at": "DATETIME",
        }
        for column_name, column_type in registry_column_defs.items():
            if column_name not in registry_columns:
                conn.execute(text(
                    f"ALTER TABLE file_registry_entries ADD COLUMN {column_name} {column_type}"
                ))


def _table_columns(conn, table_name: str) -> set[str]:
    rows = conn.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
    return {row[1] for row in rows}


def _ensure_indexes():
    """Create query indexes for existing SQLite databases."""
    statements = [
        "CREATE INDEX IF NOT EXISTS idx_directory_nodes_parent ON directory_nodes(parent_id)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_directory_nodes_full_path ON directory_nodes(full_path)",
        "CREATE INDEX IF NOT EXISTS idx_directory_nodes_depth ON directory_nodes(depth)",
        "CREATE INDEX IF NOT EXISTS idx_directory_nodes_last_seen ON directory_nodes(last_seen)",
        "CREATE INDEX IF NOT EXISTS idx_scan_sessions_root_path ON scan_sessions(root_path)",
        "CREATE INDEX IF NOT EXISTS idx_scan_sessions_trigger ON scan_sessions(trigger)",
        "CREATE INDEX IF NOT EXISTS idx_scan_sessions_mode ON scan_sessions(mode)",
        "CREATE INDEX IF NOT EXISTS idx_scan_sessions_status ON scan_sessions(status)",
        "CREATE INDEX IF NOT EXISTS idx_scan_sessions_started_at ON scan_sessions(started_at)",
        "CREATE INDEX IF NOT EXISTS idx_scan_sessions_completed_at ON scan_sessions(completed_at)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_analysis_cache_key ON analysis_cache(cache_key)",
        "CREATE INDEX IF NOT EXISTS idx_analysis_cache_content_hash ON analysis_cache(content_hash)",
        "CREATE INDEX IF NOT EXISTS idx_analysis_cache_context_hash ON analysis_cache(context_hash)",
        "CREATE INDEX IF NOT EXISTS idx_analysis_cache_event_type ON analysis_cache(event_type)",
        "CREATE INDEX IF NOT EXISTS idx_analysis_cache_priority ON analysis_cache(priority)",
        "CREATE INDEX IF NOT EXISTS idx_analysis_cache_risk_score ON analysis_cache(risk_score)",
        "CREATE INDEX IF NOT EXISTS idx_analysis_cache_updated_at ON analysis_cache(updated_at)",
        "CREATE INDEX IF NOT EXISTS idx_analysis_cache_last_hit_at ON analysis_cache(last_hit_at)",
        "CREATE INDEX IF NOT EXISTS idx_file_identities_platform_file_id ON file_identities(platform_file_id)",
        "CREATE INDEX IF NOT EXISTS idx_file_identities_current_path ON file_identities(current_path)",
        "CREATE INDEX IF NOT EXISTS idx_file_identities_current_directory_id ON file_identities(current_directory_id)",
        "CREATE INDEX IF NOT EXISTS idx_file_identities_current_name ON file_identities(current_name)",
        "CREATE INDEX IF NOT EXISTS idx_file_identities_current_hash ON file_identities(current_hash)",
        "CREATE INDEX IF NOT EXISTS idx_file_identities_current_fast_hash ON file_identities(current_fast_hash)",
        "CREATE INDEX IF NOT EXISTS idx_file_identities_current_security_hash ON file_identities(current_security_hash)",
        "CREATE INDEX IF NOT EXISTS idx_file_identities_is_active ON file_identities(is_active)",
        "CREATE INDEX IF NOT EXISTS idx_file_identities_updated_at ON file_identities(updated_at)",
        "CREATE INDEX IF NOT EXISTS idx_file_records_file_id ON file_records(file_id)",
        "CREATE INDEX IF NOT EXISTS idx_file_records_directory_id ON file_records(directory_id)",
        "CREATE INDEX IF NOT EXISTS idx_file_records_name ON file_records(name)",
        "CREATE INDEX IF NOT EXISTS idx_file_records_hash ON file_records(hash)",
        "CREATE INDEX IF NOT EXISTS idx_file_records_hash_algorithm ON file_records(hash_algorithm)",
        "CREATE INDEX IF NOT EXISTS idx_file_records_fast_hash ON file_records(fast_hash)",
        "CREATE INDEX IF NOT EXISTS idx_file_records_security_hash ON file_records(security_hash)",
        "CREATE INDEX IF NOT EXISTS idx_file_records_last_seen ON file_records(last_seen)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_file_registry_entries_file_id ON file_registry_entries(file_id)",
        "CREATE INDEX IF NOT EXISTS idx_file_registry_entries_path ON file_registry_entries(path)",
        "CREATE INDEX IF NOT EXISTS idx_file_registry_entries_normalized_path ON file_registry_entries(normalized_path)",
        "CREATE INDEX IF NOT EXISTS idx_file_registry_entries_tier ON file_registry_entries(tier)",
        "CREATE INDEX IF NOT EXISTS idx_file_registry_entries_tier_label ON file_registry_entries(tier_label)",
        "CREATE INDEX IF NOT EXISTS idx_file_registry_entries_semantic_role ON file_registry_entries(semantic_role)",
        "CREATE INDEX IF NOT EXISTS idx_file_registry_entries_asset_type ON file_registry_entries(asset_type)",
        "CREATE INDEX IF NOT EXISTS idx_file_registry_entries_file_category ON file_registry_entries(file_category)",
        "CREATE INDEX IF NOT EXISTS idx_file_registry_entries_confidence ON file_registry_entries(confidence)",
        "CREATE INDEX IF NOT EXISTS idx_file_registry_entries_current_hash ON file_registry_entries(current_hash)",
        "CREATE INDEX IF NOT EXISTS idx_file_registry_entries_current_fast_hash ON file_registry_entries(current_fast_hash)",
        "CREATE INDEX IF NOT EXISTS idx_file_registry_entries_current_security_hash ON file_registry_entries(current_security_hash)",
        "CREATE INDEX IF NOT EXISTS idx_file_registry_entries_is_active ON file_registry_entries(is_active)",
        "CREATE INDEX IF NOT EXISTS idx_file_registry_entries_updated_at ON file_registry_entries(updated_at)",
        "CREATE INDEX IF NOT EXISTS idx_file_logs_file_id ON file_logs(file_id)",
        "CREATE INDEX IF NOT EXISTS idx_file_logs_status ON file_logs(status)",
        "CREATE INDEX IF NOT EXISTS idx_file_logs_priority ON file_logs(priority)",
        "CREATE INDEX IF NOT EXISTS idx_file_logs_event_type ON file_logs(event_type)",
        "CREATE INDEX IF NOT EXISTS idx_file_logs_timestamp ON file_logs(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_file_logs_old_hash ON file_logs(old_hash)",
        "CREATE INDEX IF NOT EXISTS idx_file_logs_new_hash ON file_logs(new_hash)",
        "CREATE INDEX IF NOT EXISTS idx_file_logs_status_priority ON file_logs(status, priority)",
        "CREATE INDEX IF NOT EXISTS idx_file_logs_file_timestamp ON file_logs(file_id, timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_file_logs_path_timestamp ON file_logs(path, timestamp)",
    ]
    with engine.begin() as conn:
        for statement in statements:
            conn.execute(text(statement))


def get_db():
    """Dependency generator for DB sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
