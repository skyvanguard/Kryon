"""Tests for kryon.learning.experiences (ChromaDB-backed).

Skipped automatically when chromadb is not installed (`rag` extra). When
present, tests run against a tmp_path collection isolated per-test.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

# Skip the entire module if the optional dep isn't installed.
chromadb = pytest.importorskip("chromadb")  # noqa: F841


# ---------- Fixture: isolated collection per test ----------


@pytest.fixture(autouse=True)
def _isolated_collection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Reset the experiences module singletons + point to tmp_path.

    Without this, tests would share state across runs (the module caches
    `_client` and `_collection` at module level).
    """
    monkeypatch.setenv("KRYON_EXPERIENCES_DIR", str(tmp_path / "chroma"))
    # Disable Ollama embedder — fall back to ChromaDB default so tests
    # don't need a running embedding server.
    monkeypatch.delenv("KRYON_EMBEDDING_BASE_URL", raising=False)

    from kryon.learning import experiences as exp_mod

    # Clear singletons so the next call rebuilds against tmp_path.
    monkeypatch.setattr(exp_mod, "_client", None)
    monkeypatch.setattr(exp_mod, "_collection", None)
    yield
    # Cleanup: reset singletons again so the next test starts cold.
    monkeypatch.setattr(exp_mod, "_client", None)
    monkeypatch.setattr(exp_mod, "_collection", None)


# ---------- Helpers ----------


def _sample_experience(host: str = "x.example.com", outcome: str = "success") -> dict:
    return {
        "target_profile": {
            "host": host,
            "resolved_ip": "10.0.0.1",
            "ports": [80, 443],
            "services": {"80": "http", "443": "https"},
            "tech": ["wordpress", "nginx"],
            "os_hint": "linux",
        },
        "chain": [
            {"tool": "nmap", "args": "-sV", "status": "ok", "output": "scan ok"},
            {"tool": "whatweb", "args": "x", "status": "ok", "output": "wp"},
        ],
        "outcome": outcome,
        "outcome_signals": {"shell_gained": False, "directories_found": 3},
        "agent_path": ["recon-scout"],
        "duration_s": 120,
        "summary": f"audit {host} → {outcome}",
    }


# ---------- add_experience ----------


def test_add_assigns_id_when_missing() -> None:
    from kryon.learning import add_experience

    eid = add_experience(_sample_experience())
    assert eid.startswith("eng_")
    assert len(eid) > 4


def test_add_preserves_provided_id() -> None:
    from kryon.learning import add_experience

    exp = _sample_experience()
    exp["id"] = "eng_custom_001"
    eid = add_experience(exp)
    assert eid == "eng_custom_001"


def test_add_increments_count() -> None:
    from kryon.learning import add_experience, count_experiences

    assert count_experiences() == 0
    add_experience(_sample_experience())
    assert count_experiences() == 1
    add_experience(_sample_experience(host="y.example.com"))
    assert count_experiences() == 2


# ---------- get_experience ----------


def test_get_returns_none_for_missing_id() -> None:
    from kryon.learning import get_experience

    assert get_experience("eng_nonexistent") is None


def test_get_roundtrips_structured_fields() -> None:
    from kryon.learning import add_experience, get_experience

    eid = add_experience(_sample_experience())
    got = get_experience(eid)

    assert got is not None
    assert got["id"] == eid
    # Structured fields survive JSON roundtrip via metadata.
    assert got["target_profile"]["host"] == "x.example.com"
    assert got["target_profile"]["ports"] == [80, 443]
    assert got["target_profile"]["tech"] == ["wordpress", "nginx"]
    assert len(got["chain"]) == 2
    assert got["chain"][0]["tool"] == "nmap"
    assert got["outcome"] == "success"
    assert got["outcome_signals"]["directories_found"] == 3
    assert got["agent_path"] == ["recon-scout"]


# ---------- list_experiences ----------


def test_list_empty_on_cold_start() -> None:
    from kryon.learning import list_experiences

    assert list_experiences() == []


def test_list_returns_newest_first() -> None:
    import time

    from kryon.learning import add_experience, list_experiences

    add_experience(_sample_experience(host="first.example.com"))
    time.sleep(0.01)  # ensure created_at differs
    add_experience(_sample_experience(host="second.example.com"))

    rows = list_experiences()
    assert len(rows) == 2
    # newest first
    assert rows[0]["target_profile"]["host"] == "second.example.com"
    assert rows[1]["target_profile"]["host"] == "first.example.com"


def test_list_respects_limit() -> None:
    from kryon.learning import add_experience, list_experiences

    for i in range(5):
        add_experience(_sample_experience(host=f"h{i}.example.com"))

    rows = list_experiences(limit=3)
    assert len(rows) == 3


# ---------- recall_similar ----------


def test_recall_returns_empty_on_cold_start() -> None:
    from kryon.learning import recall_similar

    assert recall_similar({"host": "x", "tech": ["wordpress"]}) == []
    assert recall_similar("anything") == []


def test_recall_finds_added_experience_with_dict_query() -> None:
    from kryon.learning import add_experience, recall_similar

    add_experience(_sample_experience(host="alpha.example.com"))
    results = recall_similar({"host": "alpha.example.com", "tech": ["wordpress"]}, k=3)
    assert len(results) >= 1
    assert results[0]["target_profile"]["host"] == "alpha.example.com"
    # score is normalized to [0, 1]
    assert 0.0 <= results[0]["score"] <= 1.0


def test_recall_finds_with_text_query() -> None:
    from kryon.learning import add_experience, recall_similar

    add_experience(_sample_experience(host="beta.example.com"))
    results = recall_similar("beta.example.com wordpress", k=3)
    assert len(results) >= 1


def test_recall_with_empty_query_returns_empty() -> None:
    from kryon.learning import add_experience, recall_similar

    add_experience(_sample_experience())
    assert recall_similar("") == []
    assert recall_similar({}) == []


# ---------- delete_experience ----------


def test_delete_existing_returns_true() -> None:
    from kryon.learning import add_experience, count_experiences, delete_experience

    eid = add_experience(_sample_experience())
    assert count_experiences() == 1
    assert delete_experience(eid) is True
    assert count_experiences() == 0


def test_delete_nonexistent_returns_false() -> None:
    from kryon.learning import delete_experience

    assert delete_experience("eng_nope") is False


def test_delete_idempotent() -> None:
    from kryon.learning import add_experience, delete_experience

    eid = add_experience(_sample_experience())
    assert delete_experience(eid) is True
    assert delete_experience(eid) is False


# ---------- Edge cases ----------


def test_outcome_field_persists_across_outcomes() -> None:
    """All four outcome classes survive serialization."""
    from kryon.learning import add_experience, get_experience

    for outcome in ("success", "partial", "recon-only", "fail"):
        eid = add_experience(_sample_experience(outcome=outcome))
        got = get_experience(eid)
        assert got is not None
        assert got["outcome"] == outcome


def test_minimal_experience_with_missing_fields_does_not_crash() -> None:
    """Some callers may pass sparse dicts. Defaults must fill the gaps."""
    from kryon.learning import add_experience, get_experience

    eid = add_experience({"summary": "minimal", "outcome": "fail"})
    got = get_experience(eid)
    assert got is not None
    assert got["target_profile"] == {}
    assert got["chain"] == []
    assert got["outcome"] == "fail"
