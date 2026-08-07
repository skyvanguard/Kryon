"""ChromaDB-backed tests for kryon.learning.findings_library.

Skipped when chromadb (rag extra) is not installed. Pure helpers
(`url_shape`, fingerprint) live in `test_findings_library_pure.py`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# Skip module if optional dep is missing.
chromadb = pytest.importorskip("chromadb")  # noqa: F841


# ---------- Fixture: isolated collection per test ----------


@pytest.fixture(autouse=True)
def _isolated_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Reset module singletons + point persist dir to tmp."""
    monkeypatch.setenv("KRYON_FINDINGS_DIR", str(tmp_path / "chroma_fnd"))
    # Many findings_library implementations also share KRYON_EXPERIENCES_DIR
    # or fall back to defaults — point both to tmp to stay isolated.
    monkeypatch.setenv("KRYON_EXPERIENCES_DIR", str(tmp_path / "chroma_exp"))
    monkeypatch.delenv("KRYON_EMBEDDING_BASE_URL", raising=False)

    from kryon.learning import findings_library as lib

    # Reset module singletons.
    monkeypatch.setattr(lib, "_client", None, raising=False)
    monkeypatch.setattr(lib, "_collection", None, raising=False)
    yield
    monkeypatch.setattr(lib, "_client", None, raising=False)
    monkeypatch.setattr(lib, "_collection", None, raising=False)


# ---------- Helpers ----------


def _sample_finding(
    cwe: str = "CWE-89",
    url: str = "https://bank.com/api/account/12345",
    host: str = "bank.com",
    probe: str = "sqli-union",
) -> dict:
    return {
        "engagement_id": "eng_test",
        "cwe_id": cwe,
        "probe_id": probe,
        "severity": "high",
        "status": "confirmed",
        "url": url,
        "host": host,
        "title": "SQL injection in account endpoint",
        "evidence": "id=1' OR 1=1-- returns all rows",
        "remediation": "use parameterized queries",
        "tech_fingerprint": "php/laravel mysql",
        "compliance_citations": [{"framework": "PCI-DSS", "control": "6.5.1"}],
    }


# ---------- add_finding ----------


def test_add_returns_deterministic_id() -> None:
    from kryon.learning.findings_library import add_finding

    fid_a = add_finding(_sample_finding())
    # Same content → same fingerprint → same id (dedup).
    fid_b = add_finding(_sample_finding())
    assert fid_a == fid_b
    assert fid_a.startswith("fnd_")


def test_add_different_cwe_produces_different_ids() -> None:
    from kryon.learning.findings_library import add_finding

    fid_a = add_finding(_sample_finding(cwe="CWE-89"))
    fid_b = add_finding(_sample_finding(cwe="CWE-79"))
    assert fid_a != fid_b


def test_count_increments() -> None:
    from kryon.learning.findings_library import add_finding, count_findings

    assert count_findings() == 0
    add_finding(_sample_finding(cwe="CWE-89"))
    add_finding(_sample_finding(cwe="CWE-79"))
    assert count_findings() == 2


def test_dedup_does_not_double_count() -> None:
    from kryon.learning.findings_library import add_finding, count_findings

    add_finding(_sample_finding())
    add_finding(_sample_finding())  # same fingerprint
    assert count_findings() == 1


# ---------- add_findings_batch ----------


def test_batch_add_persists_all_unique() -> None:
    from kryon.learning.findings_library import add_findings_batch, count_findings

    findings = [
        _sample_finding(cwe="CWE-89"),
        _sample_finding(cwe="CWE-79"),
        _sample_finding(cwe="CWE-22"),
    ]
    ids = add_findings_batch(findings)
    assert len(ids) == 3
    assert len(set(ids)) == 3
    assert count_findings() == 3


# ---------- recall_similar ----------


def test_recall_empty_on_cold_start() -> None:
    from kryon.learning.findings_library import recall_similar

    assert recall_similar("anything") == []


def test_recall_finds_added_finding() -> None:
    from kryon.learning.findings_library import add_finding, recall_similar

    add_finding(_sample_finding())
    results = recall_similar("SQL injection account", k=3)
    assert len(results) >= 1
    assert results[0]["cwe_id"] == "CWE-89"
    # roundtrip: structured fields survive
    assert results[0]["compliance_citations"][0]["framework"] == "PCI-DSS"


# ---------- recall_by_url_shape ----------


def test_recall_by_url_shape_clusters_similar_paths() -> None:
    from kryon.learning.findings_library import (
        add_finding,
        recall_by_url_shape,
        url_shape,
    )

    # Two findings on different bank hosts, same shape.
    add_finding(
        _sample_finding(
            url="https://bcp.com.py/api/account/100",
            host="bcp.com.py",
        )
    )
    add_finding(
        _sample_finding(
            url="https://citibank.com/api/account/200",
            host="citibank.com",
        )
    )

    shape = url_shape("https://other.com/api/account/999")
    results = recall_by_url_shape(shape, k=5)
    # At least one match — both findings normalize to the same shape.
    hosts = {r.get("host") for r in results}
    assert "bcp.com.py" in hosts or "citibank.com" in hosts


# ---------- delete_finding / clear_all ----------


def test_delete_existing_returns_true() -> None:
    from kryon.learning.findings_library import (
        add_finding,
        count_findings,
        delete_finding,
    )

    fid = add_finding(_sample_finding())
    assert count_findings() == 1
    assert delete_finding(fid) is True
    assert count_findings() == 0


def test_delete_nonexistent_returns_false() -> None:
    from kryon.learning.findings_library import delete_finding

    assert delete_finding("fnd_nope") is False


def test_clear_all_returns_count_and_empties() -> None:
    from kryon.learning.findings_library import (
        add_finding,
        clear_all,
        count_findings,
    )

    add_finding(_sample_finding(cwe="CWE-89"))
    add_finding(_sample_finding(cwe="CWE-79"))
    n = clear_all()
    assert n == 2
    assert count_findings() == 0


# ---------- stats ----------


def test_stats_reports_counts_after_adds() -> None:
    from kryon.learning.findings_library import add_finding, stats

    add_finding(_sample_finding(cwe="CWE-89"))
    add_finding(_sample_finding(cwe="CWE-79"))
    s = stats()
    assert isinstance(s, dict)
    assert s.get("total", 0) == 2
