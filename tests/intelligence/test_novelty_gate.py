"""Tests for the novelty gate (F1) — known-CVE re-detection vs candidate 0-day.

The corpus query is injected as a fake, so these are pure unit tests: no
ChromaDB, no network, no model.
"""

from __future__ import annotations

import pytest

from kryon.intelligence.novelty_gate import (
    NoveltyAssessment,
    annotate_novelty,
    assess_novelty,
    rank_by_novelty,
)
from kryon.intelligence.source_review import SourceFinding


def _finding(**kw) -> SourceFinding:
    base = dict(
        file="src/parser.c",
        line=42,
        cwe="CWE-120",
        severity="HIGH",
        title="stack buffer overflow",
        description="unbounded memcpy into fixed buffer",
        evidence="memcpy(buf, input, len);",
        sink="memcpy(",
        confidence=0.8,
    )
    base.update(kw)
    return SourceFinding(**base)


def _match(similarity, **kw):
    m = dict(
        cve_id="CVE-2018-1000",
        cwe_ids="CWE-120",
        severity="HIGH",
        repo="example/lib",
        files_changed="src/parser.c,src/other.c",
        similarity=similarity,
        pattern_excerpt="memcpy overflow fix",
    )
    m.update(kw)
    return m


# --- corpus states ----------------------------------------------------------


def test_empty_corpus_is_no_corpus():
    """An empty corpus returns [] — we must not claim novel or known."""
    a = assess_novelty(_finding(), lambda q, k: [])
    assert a.verdict == "no-corpus"
    assert a.nearest_cve is None
    assert a.nearest_similarity == 0.0
    assert "empty" in a.rationale.lower()


def test_corpus_query_raises_is_handled():
    """A corpus outage must not sink the finding."""
    def boom(q, k):
        raise RuntimeError("chroma down")

    a = assess_novelty(_finding(), boom)
    assert a.verdict == "no-corpus"
    assert "failed" in a.rationale.lower()


def test_finding_without_evidence_is_no_corpus():
    f = _finding(evidence="", sink="", title="", description="")
    a = assess_novelty(f, lambda q, k: [_match(0.99)])
    assert a.verdict == "no-corpus"
    assert "no code evidence" in a.rationale.lower()


# --- verdict bands ----------------------------------------------------------


def test_twin_match_is_likely_known():
    a = assess_novelty(_finding(), lambda q, k: [_match(0.95)])
    assert a.verdict == "likely-known"
    assert a.nearest_cve == "CVE-2018-1000"
    assert a.novelty_score == pytest.approx(0.05, abs=1e-3)
    # same file + same CWE should be called out
    assert "same file" in a.rationale
    assert "same CWE" in a.rationale


def test_twin_match_without_file_or_cwe_overlap_still_known():
    m = _match(0.92, files_changed="src/unrelated.c", cwe_ids="CWE-79")
    a = assess_novelty(_finding(), lambda q, k: [m])
    assert a.verdict == "likely-known"
    assert "same file" not in a.rationale
    assert "same CWE" not in a.rationale


def test_similar_match_is_uncertain():
    a = assess_novelty(_finding(), lambda q, k: [_match(0.80)])
    assert a.verdict == "uncertain"
    assert a.novelty_score == pytest.approx(0.20, abs=1e-3)


def test_weak_match_is_likely_novel():
    a = assess_novelty(_finding(), lambda q, k: [_match(0.40)])
    assert a.verdict == "likely-novel"
    assert a.novelty_score == pytest.approx(0.60, abs=1e-3)
    assert "moonshot" in a.rationale.lower()


def test_novelty_score_is_one_minus_similarity():
    a = assess_novelty(_finding(), lambda q, k: [_match(0.73)])
    assert a.novelty_score == pytest.approx(0.27, abs=1e-3)
    assert a.nearest_similarity == pytest.approx(0.73, abs=1e-3)


def test_similarity_clamped_and_none_handled():
    """A match with None similarity is ignored; out-of-range is clamped."""
    a = assess_novelty(_finding(), lambda q, k: [_match(None), _match(1.5)])
    assert a.nearest_similarity == 1.0
    assert a.novelty_score == 0.0


def test_best_match_wins_regardless_of_order():
    """We pick the highest-similarity match, not the first."""
    matches = [_match(0.30, cve_id="CVE-LOW"), _match(0.95, cve_id="CVE-HIGH")]
    a = assess_novelty(_finding(), lambda q, k: matches)
    assert a.nearest_cve == "CVE-HIGH"
    assert a.verdict == "likely-known"


def test_thresholds_are_tunable():
    """Custom thresholds shift the verdict bands."""
    a = assess_novelty(_finding(), lambda q, k: [_match(0.80)], twin_threshold=0.79)
    assert a.verdict == "likely-known"


# --- annotate + rank --------------------------------------------------------


def test_annotate_stamps_fields_onto_copies():
    findings = [_finding(), _finding(line=99, evidence="strcpy(a, b);", sink="strcpy(")]
    annotated = annotate_novelty(findings, lambda q, k: [_match(0.95)])
    assert len(annotated) == 2
    for f in annotated:
        assert f.novelty_verdict == "likely-known"
        assert f.nearest_cve == "CVE-2018-1000"
        assert f.novelty_score == pytest.approx(0.05, abs=1e-3)
    # originals are untouched (frozen dataclass, replace makes copies)
    assert findings[0].novelty_verdict == ""


def test_rank_by_novelty_floats_novel_to_top():
    known = _finding(line=1)
    novel = _finding(line=2)

    def q(query, k):
        # the "novel" finding (evidence has 'zzz') gets a weak match
        return [_match(0.95)] if "zzz" not in query else [_match(0.20)]

    novel = _finding(line=2, evidence="zzz custom sink", sink="zzz")
    annotated = annotate_novelty([known, novel], q)
    ranked = rank_by_novelty(annotated)
    assert ranked[0].line == 2  # novel first
    assert ranked[0].novelty_verdict == "likely-novel"
    assert ranked[1].novelty_verdict == "likely-known"


def test_rank_by_novelty_neutral_when_unannotated():
    """Findings without novelty scores don't crash the ranker."""
    findings = [_finding(line=3, severity="LOW"), _finding(line=4, severity="CRITICAL")]
    ranked = rank_by_novelty(findings)
    # both neutral novelty (0.5) → falls back to severity: CRITICAL first
    assert ranked[0].severity == "CRITICAL"


def test_assessment_is_frozen():
    a = NoveltyAssessment(0.5, "uncertain", None, 0.5, "x")
    with pytest.raises(Exception):
        a.verdict = "changed"  # type: ignore[misc]
