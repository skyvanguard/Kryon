"""T4-M8: SourceFinding.to_engage_finding() must carry the novelty + verification
verdicts (F1/F2/F3) into the Finding instead of discarding them — the 'likely-novel'
signal is the zero-day payoff and must survive the conversion boundary."""

from __future__ import annotations

import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

from kryon.intelligence.source_review import SourceFinding


def _sf(**kw):
    base = dict(file="app.c", line=42, cwe="CWE-89", severity="high", title="SQLi in query()")
    base.update(kw)
    return SourceFinding(**base)


def test_novelty_verdict_is_exposed():
    f = _sf(novelty_verdict="likely-novel", novelty_score=0.91, nearest_cve="CVE-2019-1234")
    fnd = f.to_engage_finding()
    assert "novelty=likely-novel" in fnd.evidence
    assert "CVE-2019-1234" in fnd.evidence
    assert "0.91" in fnd.evidence


def test_verification_verdict_and_crash_exposed():
    f = _sf(verified=True, verification_verdict="confirmed", crash_type="heap-buffer-overflow")
    fnd = f.to_engage_finding()
    assert "verification=confirmed" in fnd.evidence
    assert "heap-buffer-overflow" in fnd.evidence
    assert fnd.needs_verification is False
    assert fnd.confidence == 0.98


def test_original_evidence_is_preserved():
    f = _sf(evidence="sink: db.query(user_input)", novelty_verdict="likely-known")
    fnd = f.to_engage_finding()
    assert fnd.evidence.startswith("sink: db.query(user_input)")
    assert "novelty=likely-known" in fnd.evidence


def test_no_verdicts_leaves_evidence_untouched():
    f = _sf(evidence="just the sink")
    fnd = f.to_engage_finding()
    assert fnd.evidence == "just the sink"
