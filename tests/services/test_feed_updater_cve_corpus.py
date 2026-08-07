"""M7 — the ``cve-corpus`` feed: refresh the 0-day hunter's novelty backbone.

Pipeline scrape→enrich→ingest is fully injected here, so nothing touches
the network, git, or ChromaDB. The feed is gated on KRYON_EMBEDDING_BASE_URL
(like the rest of the RAG surface, OFF by default / banca-safe) and, like every
other feed, is best-effort and isolated.
"""

from __future__ import annotations

from kryon.services.feed_updater import (
    ALL_FEEDS,
    DEFAULT_FEEDS,
    run_updates,
    update_cve_corpus,
)

_ADV = [
    {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "cve_id": "CVE-2024-1",
        "fix_commits": [{"owner": "o", "repo": "r", "sha": "deadbeef"}],
    }
]


# --- gating ---------------------------------------------------------------


def test_cve_corpus_skipped_without_embedding_backend(monkeypatch):
    monkeypatch.delenv("KRYON_EMBEDDING_BASE_URL", raising=False)
    r = update_cve_corpus()
    assert r.status == "skipped"
    assert r.name == "cve-corpus"
    assert "EMBEDDING" in r.detail.upper()


# --- happy path (all three stages injected) -------------------------------


def test_cve_corpus_ok_ingests_enriched_entries(monkeypatch):
    monkeypatch.setenv("KRYON_EMBEDDING_BASE_URL", "http://embed:11434")
    seen = {}

    def _scrape(*, limit, ecosystems):
        seen["limit"] = limit
        return _ADV

    def _enrich(advisories, *, out_path):
        seen["enriched"] = list(advisories)
        return {"entries_written": 1, "output": out_path}

    def _ingest(path):
        seen["ingested_path"] = path
        return 1

    r = update_cve_corpus(scraper=_scrape, enricher=_enrich, ingester=_ingest)
    assert r.ok
    assert "1 entries ingested" in r.detail
    assert seen["enriched"] == _ADV


def test_cve_corpus_ok_when_no_advisories(monkeypatch):
    monkeypatch.setenv("KRYON_EMBEDDING_BASE_URL", "http://embed:11434")

    def _boom(*a, **k):  # must NOT be reached
        raise AssertionError("enricher called on empty scrape")

    r = update_cve_corpus(scraper=lambda **k: [], enricher=_boom, ingester=_boom)
    assert r.ok
    assert "0 advisories" in r.detail


def test_cve_corpus_ok_when_nothing_enriched(monkeypatch):
    monkeypatch.setenv("KRYON_EMBEDDING_BASE_URL", "http://embed:11434")

    def _no_ingest(path):  # must NOT be reached when 0 diffs enriched
        raise AssertionError("ingester called with 0 enriched entries")

    r = update_cve_corpus(
        scraper=lambda **k: _ADV,
        enricher=lambda adv, *, out_path: {"entries_written": 0},
        ingester=_no_ingest,
    )
    assert r.ok
    assert "0 diffs" in r.detail


# --- isolation: any stage raising → failed, never propagates --------------


def test_cve_corpus_failed_when_scrape_raises(monkeypatch):
    monkeypatch.setenv("KRYON_EMBEDDING_BASE_URL", "http://embed:11434")

    def _raise(**k):
        raise RuntimeError("advisory clone failed")

    r = update_cve_corpus(scraper=_raise)
    assert r.status == "failed"
    assert "advisory clone failed" in r.detail


def test_cve_corpus_failed_when_ingest_raises(monkeypatch):
    monkeypatch.setenv("KRYON_EMBEDDING_BASE_URL", "http://embed:11434")
    r = update_cve_corpus(
        scraper=lambda **k: _ADV,
        enricher=lambda adv, *, out_path: {"entries_written": 3},
        ingester=lambda p: (_ for _ in ()).throw(RuntimeError("chroma down")),
    )
    assert r.status == "failed"
    assert "chroma down" in r.detail


def test_cve_corpus_limit_env_override(monkeypatch):
    monkeypatch.setenv("KRYON_EMBEDDING_BASE_URL", "http://embed:11434")
    monkeypatch.setenv("KRYON_CVE_CORPUS_LIMIT", "7")
    captured = {}

    def _scrape(*, limit, ecosystems):
        captured["limit"] = limit
        return []

    update_cve_corpus(scraper=_scrape)
    assert captured["limit"] == 7


# --- registration in the orchestrator -------------------------------------


def test_cve_corpus_is_opt_in_not_default():
    assert "cve-corpus" not in DEFAULT_FEEDS
    assert "cve-corpus" in ALL_FEEDS


def test_run_updates_dispatches_cve_corpus(monkeypatch):
    import kryon.services.feed_updater as fu

    monkeypatch.setattr(fu, "update_cve_corpus", lambda **k: fu.UpdateResult("cve-corpus", "ok", "stub"))
    res = run_updates(["cve-corpus"])
    assert [r.name for r in res] == ["cve-corpus"]
    assert res[0].ok
