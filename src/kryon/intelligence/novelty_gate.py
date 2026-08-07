"""Novelty gate — separates re-detected known CVEs from candidate zero-days.

The source-review harness (``source_review.py``) is a strong *finder* but a
blind one: point it at zlib HEAD and it will happily "confirm" a bug that is
already CVE-2018-XXXX, patched three releases ago. Without a novelty check
there is no zero-day, only a CVE re-detector.

This module closes that gap by **inverting the CVE corpus**. Today
``cve_corpus.recall_similar_code_pattern`` is used as a *seed* ("this looks
like an old CVE → probably vulnerable, go look"). Here we use the exact same
index as a *filter* ("this looks IDENTICAL to CVE-2018-XXXX's patched code →
you re-found a known bug, not a novel one").

Honesty contract
----------------
Semantic similarity cannot *prove* novelty — a near-twin of an old CVE might
be a genuinely new variant, or the very same bug re-detected. So the gate
emits a graded **verdict + novelty_score**, never a hard boolean:

- ``likely-known``  — a near-identical prior CVE patch exists (high similarity,
  often same file/CWE). Treat as re-detection; deprioritise for the moonshot.
- ``uncertain``     — a similar-but-not-identical prior patch. Could be a novel
  variant OR a re-detection; a human (or the ASAN bridge) decides.
- ``likely-novel``  — the corpus holds prior art yet nothing close matches.
  The interesting bucket.
- ``no-corpus``     — the corpus is empty; we cannot assess. Never claim novel.

Design mirrors ``source_review``: the corpus query is injected behind the
``CorpusQuery`` callable so this whole module is pure and unit-testable with a
fake, never touching ChromaDB in tests.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Callable

from kryon.intelligence.source_review import SourceFinding

# A CorpusQuery takes (code_snippet, top_k) and returns the corpus matches as
# dicts shaped like cve_corpus._query_similar output: at least {similarity,
# cve_id, cwe_ids, files_changed}. The LLM/ChromaDB lives behind this; tests
# inject a fake list.
CorpusQuery = Callable[[str, int], list[dict]]

# Similarity thresholds over the corpus match (0 = unrelated, 1 = identical).
# A "twin" patch (≥0.90) is almost certainly the same bug; the mid band is
# genuinely ambiguous; below the floor we treat prior art as absent-enough.
TWIN_THRESHOLD = 0.90
SIMILAR_THRESHOLD = 0.75
DEFAULT_TOP_K = 5


@dataclass(frozen=True)
class NoveltyAssessment:
    """The gate's judgement for one finding."""

    novelty_score: float  # 0.0 = twin of a known CVE, 1.0 = no prior art at all
    verdict: str  # likely-known | uncertain | likely-novel | no-corpus
    nearest_cve: str | None
    nearest_similarity: float  # best corpus similarity seen (0.0 if none)
    rationale: str


def _finding_query_text(finding: SourceFinding) -> str:
    """Build the semantic query for a finding.

    The patched code in the corpus is indexed by its ``pattern`` (summary +
    diff), so we query with the finding's own code signal: the exact
    vulnerable line(s) first (highest overlap with a diff), then the sink and
    a short description for context.
    """
    parts = [finding.evidence, finding.sink, finding.title, finding.description]
    return "\n".join(p for p in parts if p and p.strip()).strip()


def _basename(path: str) -> str:
    """Last path component, POSIX-normalised (findings store rel paths with /)."""
    return PurePosixPath(path.replace("\\", "/")).name


def _same_file(finding: SourceFinding, match: dict) -> bool:
    """True if the finding's file appears in the CVE's changed files.

    A CVE patch lists ``files_changed`` (comma-joined paths). If the finding's
    basename is one of them, this is very likely the same code site — a strong
    signal that a high-similarity match is a re-detection, not a coincidence.
    """
    changed = str(match.get("files_changed", "") or "")
    if not changed:
        return False
    want = _basename(finding.file).lower()
    if not want:
        return False
    return any(_basename(c).lower() == want for c in changed.split(","))


def _same_cwe(finding: SourceFinding, match: dict) -> bool:
    cwes = str(match.get("cwe_ids", "") or "").upper()
    fc = finding.cwe.upper().strip()
    return bool(fc) and fc in cwes


def _best_match(matches: list[dict]) -> dict | None:
    """The highest-similarity match. Corpus already returns nearest-first, but
    we don't rely on order — pick the max defensively."""
    best: dict | None = None
    best_sim = -1.0
    for m in matches:
        sim = m.get("similarity")
        if sim is None:
            continue
        s = float(sim)
        if s > best_sim:
            best_sim = s
            best = m
    return best


def assess_novelty(
    finding: SourceFinding,
    corpus_query: CorpusQuery,
    *,
    twin_threshold: float = TWIN_THRESHOLD,
    similar_threshold: float = SIMILAR_THRESHOLD,
    top_k: int = DEFAULT_TOP_K,
) -> NoveltyAssessment:
    """Judge whether ``finding`` re-detects a known CVE or looks novel.

    Pure modulo ``corpus_query`` (the only impure dependency). Returns a
    graded ``NoveltyAssessment`` — never a hard boolean.
    """
    query = _finding_query_text(finding)
    if not query:
        return NoveltyAssessment(
            novelty_score=0.5,
            verdict="no-corpus",
            nearest_cve=None,
            nearest_similarity=0.0,
            rationale="finding has no code evidence to compare against the corpus",
        )

    try:
        matches = corpus_query(query, top_k) or []
    except Exception as e:  # noqa: BLE001 — a corpus outage must not sink the finding
        return NoveltyAssessment(
            novelty_score=0.5,
            verdict="no-corpus",
            nearest_cve=None,
            nearest_similarity=0.0,
            rationale=f"corpus query failed ({type(e).__name__}); novelty not assessed",
        )

    best = _best_match(matches)
    # Empty result == the corpus itself is empty (query returns [] only when
    # count==0; a populated corpus always returns top_k, however weak). So we
    # cannot claim novelty — say so honestly rather than guess.
    if best is None:
        return NoveltyAssessment(
            novelty_score=0.5,
            verdict="no-corpus",
            nearest_cve=None,
            nearest_similarity=0.0,
            rationale="CVE corpus is empty — cannot assess novelty (ingest it first)",
        )

    sim = max(0.0, min(1.0, float(best.get("similarity") or 0.0)))
    cve = (best.get("cve_id") or "").strip() or None
    novelty_score = round(1.0 - sim, 4)
    same_file = _same_file(finding, best)
    same_cwe = _same_cwe(finding, best)

    if sim >= twin_threshold:
        corr = []
        if same_file:
            corr.append("same file")
        if same_cwe:
            corr.append("same CWE")
        extra = f" ({', '.join(corr)})" if corr else ""
        verdict = "likely-known"
        rationale = (
            f"near-identical to {cve or 'a known CVE patch'} "
            f"(similarity {sim:.2f}){extra} — probable re-detection of a patched bug"
        )
    elif sim >= similar_threshold:
        verdict = "uncertain"
        rationale = (
            f"resembles {cve or 'a known CVE'} (similarity {sim:.2f}) but not identical — "
            "could be a novel variant or a re-detection; needs verification"
        )
    else:
        verdict = "likely-novel"
        rationale = (
            f"closest prior art is {cve or 'n/a'} at only {sim:.2f} similarity — "
            "no known CVE looks like this; candidate for the moonshot"
        )

    return NoveltyAssessment(
        novelty_score=novelty_score,
        verdict=verdict,
        nearest_cve=cve,
        nearest_similarity=round(sim, 4),
        rationale=rationale,
    )


def annotate_novelty(
    findings: list[SourceFinding],
    corpus_query: CorpusQuery,
    *,
    twin_threshold: float = TWIN_THRESHOLD,
    similar_threshold: float = SIMILAR_THRESHOLD,
    top_k: int = DEFAULT_TOP_K,
) -> list[SourceFinding]:
    """Return copies of ``findings`` with novelty fields filled in.

    Runs the gate over each finding and stamps ``novelty_score``,
    ``novelty_verdict`` and ``nearest_cve`` onto a copy (SourceFinding is
    frozen). Order is preserved.
    """
    out: list[SourceFinding] = []
    for f in findings:
        a = assess_novelty(
            f,
            corpus_query,
            twin_threshold=twin_threshold,
            similar_threshold=similar_threshold,
            top_k=top_k,
        )
        out.append(
            dataclasses.replace(
                f,
                novelty_score=a.novelty_score,
                novelty_verdict=a.verdict,
                nearest_cve=a.nearest_cve,
            )
        )
    return out


def rank_by_novelty(findings: list[SourceFinding]) -> list[SourceFinding]:
    """Re-order annotated findings so the moonshot bucket floats to the top.

    Sort key: novel-first (higher novelty_score first), then severity, then
    confidence. Findings without a novelty score sort as neutral (0.5) so a
    non-annotated run is unaffected.
    """

    def _nov(f: SourceFinding) -> float:
        return f.novelty_score if f.novelty_score is not None else 0.5

    return sorted(
        findings,
        key=lambda f: (-_nov(f), f.severity_rank(), -f.confidence, f.file, f.line),
    )
