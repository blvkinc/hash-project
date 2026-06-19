import os
import sys
from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.config import settings
from core.models import Base, FileRegistryEntry
from core.services import mempalace_baseline_builder as builder


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _entry(path, tier, role, asset, file_id):
    now = datetime.utcnow()
    return FileRegistryEntry(
        file_id=file_id,
        path=str(path),
        normalized_path=os.path.normcase(os.path.abspath(str(path))),
        name=os.path.basename(str(path)),
        tier=tier,
        tier_label={1: "Critical", 2: "High", 3: "Medium", 4: "Low"}.get(tier),
        semantic_role=role,
        asset_type=asset,
        file_category=asset,
        confidence="high",
        reasoning=f"{role} baseline identity.",
        expected_change_sources=["developer_change"],
        last_known_good_hash=f"hash-{file_id}",
        current_hash=f"hash-{file_id}",
        current_fast_hash=f"hash-{file_id}",
        hash_algorithm="xxh3_128",
        security_hash_algorithm="blake3",
        is_active=True,
        first_seen=now,
        last_seen=now,
        updated_at=now,
    )


def test_baseline_builder_selects_important_registry_rows(monkeypatch, tmp_path):
    session = _session()
    root = tmp_path / "target"
    root.mkdir()
    critical = root / "sudoers"
    source = root / "app.py"
    low = root / "debug.log"
    outside = tmp_path / "outside.py"
    session.add_all([
        _entry(critical, 1, "privilege_policy", "auth", 1),
        _entry(source, 3, "source_code", "code", 2),
        _entry(low, 4, "log_or_runtime_artifact", "runtime", 3),
        _entry(outside, 3, "source_code", "code", 4),
    ])
    session.commit()

    written = []

    def fake_upsert(memories):
        written.extend(memories)
        return {"enabled": True, "stored": len(memories), "backend": "fake"}

    monkeypatch.setattr(settings, "mempalace_baseline_enabled", True)
    monkeypatch.setattr(settings, "mempalace_baseline_max_entries", 20)
    monkeypatch.setattr(settings, "mempalace_baseline_batch_size", 2)
    monkeypatch.setattr(settings, "mempalace_baseline_include_tier4", False)
    monkeypatch.setattr(builder, "mempalace_enabled", lambda: True)
    monkeypatch.setattr(builder, "backend_status", lambda: {"available": True, "backend": "fake"})
    monkeypatch.setattr(builder, "upsert_baseline_memories", fake_upsert)

    result = builder.build_mempalace_baseline_from_sql(
        root_path=str(root),
        scan_session_id=99,
        session=session,
    )

    assert result["stored"] == 2
    assert result["eligible"] == 2
    assert len(written) == 2
    paths = {memory["metadata"]["source_file"] for memory in written}
    assert str(critical) in paths
    assert str(source) in paths
    assert str(low) not in paths
    assert str(outside) not in paths
    assert all(memory["metadata"]["memory_type"] == "fim_baseline_identity" for memory in written)


def test_baseline_builder_can_include_tier4_when_configured(monkeypatch, tmp_path):
    session = _session()
    root = tmp_path / "target"
    root.mkdir()
    low = root / "debug.log"
    session.add(_entry(low, 4, "log_or_runtime_artifact", "runtime", 10))
    session.commit()

    monkeypatch.setattr(settings, "mempalace_baseline_enabled", True)
    monkeypatch.setattr(settings, "mempalace_baseline_include_tier4", True)
    monkeypatch.setattr(builder, "mempalace_enabled", lambda: True)
    monkeypatch.setattr(builder, "backend_status", lambda: {"available": True, "backend": "fake"})
    monkeypatch.setattr(
        builder,
        "upsert_baseline_memories",
        lambda memories: {"enabled": True, "stored": len(memories), "backend": "fake"},
    )

    result = builder.build_mempalace_baseline_from_sql(
        root_path=str(root),
        limit=10,
        session=session,
    )

    assert result["stored"] == 1
    assert result["eligible"] == 1
