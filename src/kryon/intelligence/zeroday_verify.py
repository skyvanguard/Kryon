"""Zero-day verification loop (F1+F2+F3) — the closed harness around the reasoner.

``source_review`` gives V4-Flash a Mythos-style *find*; this module wraps that
raw find in the loop that turns a hunch into a zero-day:

    reason (source_review)  →  VERIFY  →  FILTER-KNOWN  →  rank

- **VERIFY**: each finding goes to its oracle — memory bugs to ASAN (F2,
  ``verification_bridge``), everything else to the canary oracle (F3,
  ``dynamic_oracle``). A confirmed finding is ground truth.
- **FILTER-KNOWN**: the novelty gate (F1, ``novelty_gate``) stamps each finding
  known-vs-novel by inverting the CVE corpus.
- **rank**: confirmed-and-novel floats to the top — that's the moonshot bucket.

This is where "harness > modelo" is satisfied: the model only reasons; the
harness proves and dedups. All heavy deps are injected, so the orchestration is
pure and unit-testable; ``build_default_loop`` wires the real model + sandboxes
for production.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from kryon.intelligence.dynamic_oracle import (
    DynamicPocGenerator,
    DynamicRunner,
    is_dynamic_verifiable,
    verify_findings_dynamic,
)
from kryon.intelligence.novelty_gate import CorpusQuery, annotate_novelty
from kryon.intelligence.source_review import SourceFinding
from kryon.intelligence.verification_bridge import (
    PocGenerator,
    SandboxRunner,
    is_asan_verifiable,
    verify_findings,
)


@dataclass(frozen=True)
class LoopSummary:
    """One-glance status of a verification pass."""

    total: int
    confirmed: int
    likely_novel: int
    confirmed_and_novel: int  # the moonshot bucket
    unverifiable: int  # no oracle for this class/lang

    def as_line(self) -> str:
        return (
            f"{self.total} findings · {self.confirmed} confirmed · "
            f"{self.likely_novel} likely-novel · {self.confirmed_and_novel} CONFIRMED+NOVEL "
            f"· {self.unverifiable} no-oracle"
        )


def _verification_rank(f: SourceFinding) -> tuple:
    """Sort key: confirmed first, then novel, then severity, then confidence.

    Confirmed (``verified``) findings are ground truth → top. Within a tier,
    higher novelty (candidate zero-day) beats a re-detected known CVE.
    """
    nov = f.novelty_score if f.novelty_score is not None else 0.5
    return (0 if f.verified else 1, -nov, f.severity_rank(), -f.confidence, f.file, f.line)


def rank_verified_then_novel(findings: list[SourceFinding]) -> list[SourceFinding]:
    """Order for the moonshot: confirmed-and-novel at the very top."""
    return sorted(findings, key=_verification_rank)


def summarize(findings: list[SourceFinding]) -> LoopSummary:
    confirmed = [f for f in findings if f.verified]
    novel = [f for f in findings if f.novelty_verdict == "likely-novel"]
    both = [f for f in confirmed if f.novelty_verdict == "likely-novel"]
    unverifiable = [
        f for f in findings if not is_asan_verifiable(f) and not is_dynamic_verifiable(f)
    ]
    return LoopSummary(
        total=len(findings),
        confirmed=len(confirmed),
        likely_novel=len(novel),
        confirmed_and_novel=len(both),
        unverifiable=len(unverifiable),
    )


def close_verification_loop(
    findings: list[SourceFinding],
    *,
    # F2 — ASAN memory verification (both required to run it)
    poc_generator: PocGenerator | None = None,
    sandbox_runner: SandboxRunner | None = None,
    # F3 — canary non-memory verification (both required to run it)
    dyn_poc_generator: DynamicPocGenerator | None = None,
    dyn_runner: DynamicRunner | None = None,
    # F1 — novelty filter
    novelty_query: CorpusQuery | None = None,
    # shared: supplies the vulnerable file's source to the PoC generators
    context_reader: Callable[[SourceFinding], str] | None = None,
    max_verifications: int = 20,
) -> list[SourceFinding]:
    """Run the full F2→F3→F1 loop over ``findings`` and rank the result.

    Each stage is optional and only runs when its deps are supplied, so a
    caller with no compiler (F2), no interpreter (F3), or no corpus (F1) still
    gets whatever the available oracles can prove. Pure modulo the injected
    callables.
    """
    if poc_generator is not None and sandbox_runner is not None:
        findings = verify_findings(
            findings,
            poc_generator=poc_generator,
            sandbox_runner=sandbox_runner,
            context_reader=context_reader,
            max_verifications=max_verifications,
        )
    if dyn_poc_generator is not None and dyn_runner is not None:
        findings = verify_findings_dynamic(
            findings,
            poc_generator=dyn_poc_generator,
            runner=dyn_runner,
            context_reader=context_reader,
            max_verifications=max_verifications,
        )
    if novelty_query is not None:
        findings = annotate_novelty(findings, novelty_query)
    return rank_verified_then_novel(findings)


def build_default_loop(root: Path) -> Callable[[list[SourceFinding]], list[SourceFinding]]:
    """Wire the real model + sandboxes + corpus for production use.

    Returns a closure ``loop(findings) -> ranked findings`` that reads each
    finding's file under ``root`` for context, verifies via the live ASAN and
    canary oracles, and filters against the CVE corpus. Imports the heavy deps
    lazily so importing this module stays cheap.
    """
    from kryon.intelligence.dynamic_oracle import (
        LocalDynamicPocGenerator,
        default_dynamic_runner,
    )
    from kryon.intelligence.verification_bridge import (
        LocalPocGenerator,
        default_sandbox_runner,
    )

    root = Path(root)

    def _read_context(f: SourceFinding) -> str:
        try:
            return (root / f.file).read_text(encoding="utf-8", errors="replace")[:20000]
        except OSError:
            return ""

    def _novelty_query(snippet: str, top_k: int) -> list[dict]:
        # Lazy: the corpus pulls in ChromaDB. If it's unavailable/empty the
        # query returns [] and the gate reports no-corpus.
        try:
            from kryon.knowledge.cve_corpus import _query_similar

            return _query_similar(snippet, top_k=top_k)
        except Exception:  # noqa: BLE001 — a missing corpus must not break the loop
            return []

    def loop(findings: list[SourceFinding]) -> list[SourceFinding]:
        return close_verification_loop(
            findings,
            poc_generator=LocalPocGenerator(),
            sandbox_runner=default_sandbox_runner,
            dyn_poc_generator=LocalDynamicPocGenerator(),
            dyn_runner=default_dynamic_runner,
            novelty_query=_novelty_query,
            context_reader=_read_context,
        )

    return loop
