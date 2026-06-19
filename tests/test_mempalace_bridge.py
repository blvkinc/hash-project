import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.config import settings
from core.services import mempalace_bridge


def test_mempalace_bridge_writes_event_memory_with_real_api_shape(monkeypatch, tmp_path):
    calls = {}

    class FakeCollection:
        def upsert(self, *, documents, ids, metadatas):
            calls["documents"] = documents
            calls["ids"] = ids
            calls["metadatas"] = metadatas

    def fake_get_collection(palace_path, *, collection_name, create, backend):
        calls["palace_path"] = palace_path
        calls["collection_name"] = collection_name
        calls["create"] = create
        calls["backend"] = backend
        return FakeCollection()

    monkeypatch.setattr(settings, "mempalace_enabled", True)
    monkeypatch.setattr(settings, "mempalace_path", str(tmp_path / "palace"))
    monkeypatch.setattr(settings, "mempalace_backend", "sqlite_exact")
    monkeypatch.setattr(settings, "mempalace_collection", "fim_file_memories")
    monkeypatch.setattr(mempalace_bridge, "_import_mempalace_collection", lambda: fake_get_collection)

    result = mempalace_bridge.upsert_event_memory(
        log_id=12,
        file_id=7,
        path=r"C:\Users\dev\project\key.java",
        event_type="modified",
        old_hash="abc",
        new_hash="def",
        registry={
            "tier": 3,
            "tier_label": "Medium",
            "semantic_role": "source_code",
            "asset_type": "code",
        },
        analysis={
            "risk_score": 9,
            "priority": "critical",
            "threat_type": "credential_theft",
            "threat_classification": "Agent-Detected Credential Theft",
            "analysis_source": "heuristic+mempalace_agent",
            "reasoning": "The changed Java file contains keylogging behavior.",
        },
        content_excerpt="GetAsyncKeyState(13);",
    )

    assert result["stored"] is True
    assert calls["create"] is True
    assert calls["backend"] == "sqlite_exact"
    assert calls["ids"] == ["fim-log-12"]
    assert "File Integrity Memory" in calls["documents"][0]
    assert "GetAsyncKeyState" in calls["documents"][0]
    assert calls["metadatas"][0]["wing"] == "IntegrityGuard"
    assert calls["metadatas"][0]["source_file"].endswith("key.java")


def test_mempalace_bridge_searches_related_memories(monkeypatch, tmp_path):
    def fake_search_memories(**kwargs):
        return {
            "results": [
                {
                    "id": "fim-log-12",
                    "text": "Prior keylogger alert",
                    "metadata": {
                        "source_file": r"C:\Users\dev\project\key.java",
                        "semantic_role": "source_code",
                    },
                    "distance": 0.12,
                    "similarity": 0.88,
                    "matched_via": "drawer",
                }
            ]
        }

    monkeypatch.setattr(settings, "mempalace_enabled", True)
    monkeypatch.setattr(settings, "mempalace_path", str(tmp_path / "palace"))
    monkeypatch.setattr(settings, "mempalace_backend", "sqlite_exact")
    monkeypatch.setattr(settings, "mempalace_collection", "fim_file_memories")
    monkeypatch.setattr(mempalace_bridge, "_import_mempalace_search", lambda: fake_search_memories)

    hits, status = mempalace_bridge.search_related_memories(
        path=r"C:\Users\dev\project\key.java",
        event_type="modified",
        registry={
            "tier": 3,
            "semantic_role": "source_code",
            "asset_type": "code",
        },
        content_excerpt="GetAsyncKeyState(13);",
    )

    assert status["searched"] is True
    assert status["hits"] == 1
    assert hits[0].id == "fim-log-12"
    assert hits[0].metadata["semantic_role"] == "source_code"


def test_mempalace_bridge_searches_multiple_memory_strategies(monkeypatch, tmp_path):
    seen_queries = []

    def fake_search_memories(**kwargs):
        query = kwargs["query"]
        seen_queries.append(query)
        if "prior verdict" in query:
            return {
                "results": [{
                    "id": "fim-log-verdict",
                    "text": "Prior critical credential theft verdict",
                    "metadata": {
                        "source_file": "old-key.java",
                        "semantic_role": "source_code",
                    },
                    "distance": 0.08,
                }]
            }
        if "similar content indicators" in query:
            return {
                "results": [{
                    "id": "fim-log-content",
                    "text": "Prior keylogging content indicator",
                    "metadata": {
                        "source_file": "keylogger.java",
                        "semantic_role": "source_code",
                    },
                    "distance": 0.09,
                }]
            }
        return {"results": []}

    monkeypatch.setattr(settings, "mempalace_enabled", True)
    monkeypatch.setattr(settings, "mempalace_path", str(tmp_path / "palace"))
    monkeypatch.setattr(settings, "mempalace_backend", "sqlite_exact")
    monkeypatch.setattr(settings, "mempalace_collection", "fim_file_memories")
    monkeypatch.setattr(mempalace_bridge, "_import_mempalace_search", lambda: fake_search_memories)

    hits, status = mempalace_bridge.search_related_memories(
        path=r"C:\Users\dev\project\key.java",
        event_type="modified",
        registry={
            "tier": 3,
            "semantic_role": "source_code",
            "asset_type": "code",
            "path_history": [{
                "old_path": r"C:\Users\dev\project\old-key.java",
                "new_path": r"C:\Users\dev\project\key.java",
            }],
        },
        content_excerpt="GetAsyncKeyState(13);",
        analysis={
            "priority": "critical",
            "risk_score": 9,
            "threat_type": "credential_theft",
            "threat_classification": "Agent-Detected Credential Theft",
        },
    )

    assert status["searched"] is True
    assert status["query_count"] >= 5
    assert {hit.id for hit in hits} == {"fim-log-verdict", "fim-log-content"}
    assert "previous_verdict" in status["retrieval_strategies"]
    assert "content_indicators" in status["retrieval_strategies"]
    assert any("path history" in query for query in seen_queries)
    assert hits[0].metadata["retrieval_strategies"]


def test_mempalace_bridge_normalizes_searcher_top_level_fields():
    hits = mempalace_bridge._hits_from_search_result({
        "results": [{
            "text": "Prior alert",
            "source_file": "key.java",
            "wing": "IntegrityGuard",
            "room": "code/source_code",
            "similarity": 0.91,
            "matched_via": "drawer",
        }]
    })

    assert hits[0].id == "key.java"
    assert hits[0].metadata["source_file"] == "key.java"
    assert hits[0].metadata["wing"] == "IntegrityGuard"
