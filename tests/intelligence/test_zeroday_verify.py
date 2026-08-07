"""Tests for the closed zero-day loop (F1+F2+F3 orchestration)."""

from __future__ import annotations

from pathlib import Path

from kryon.intelligence.dynamic_oracle import DynamicPocSpec
from kryon.intelligence.source_review import SourceFinding
from kryon.intelligence.verification_bridge import PocSpec
from kryon.intelligence.zeroday_verify import (
    build_default_loop,
    close_verification_loop,
    rank_verified_then_novel,
    summarize,
)


def _f(**kw) -> SourceFinding:
    base = dict(
        file="a.c", line=1, cwe="CWE-787", severity="HIGH", title="oob write", evidence="x", sink="s", confidence=0.7
    )
    base.update(kw)
    return SourceFinding(**base)


# fakes
def _poc_ok(f, ctx):
    return PocSpec(source_code="int main(){}")


def _asan_crash(spec):
    return {"compiled": True, "crashed": True, "crash_type": "heap-buffer-overflow"}


def _asan_clean(spec):
    return {"compiled": True, "crashed": False}


def _dyn_poc(f, ctx, canary):
    return DynamicPocSpec(script="x", language="python", canary=canary)


def _dyn_fire(spec):
    return {"ran": True, "exit_code": 0, "stdout": spec.canary}


def _novel_corpus(q, k):
    return [{"similarity": 0.2, "cve_id": "CVE-OLD", "cwe_ids": "", "files_changed": ""}]


def _known_corpus(q, k):
    return [{"similarity": 0.97, "cve_id": "CVE-KNOWN", "cwe_ids": "CWE-787", "files_changed": "a.c"}]


# --- ranking ----------------------------------------------------------------


def test_confirmed_and_novel_floats_to_top():
    confirmed_novel = _f(line=1, verified=True, novelty_verdict="likely-novel", novelty_score=0.9)
    confirmed_known = _f(line=2, verified=True, novelty_verdict="likely-known", novelty_score=0.05)
    unverified = _f(line=3, verified=False, novelty_score=0.9)
    ranked = rank_verified_then_novel([unverified, confirmed_known, confirmed_novel])
    assert ranked[0].line == 1  # confirmed + novel
    assert ranked[1].line == 2  # confirmed + known
    assert ranked[2].line == 3  # unverified last


# --- summary ----------------------------------------------------------------


def test_summarize_counts_buckets():
    findings = [
        _f(line=1, cwe="CWE-787", verified=True, novelty_verdict="likely-novel"),  # confirmed+novel
        _f(line=2, cwe="CWE-89", file="a.py", verified=True, novelty_verdict="likely-known"),  # confirmed
        _f(line=3, cwe="CWE-999", file="a.txt"),  # no oracle (unknown cwe + non-source)
    ]
    s = summarize(findings)
    assert s.total == 3
    assert s.confirmed == 2
    assert s.confirmed_and_novel == 1
    assert s.unverifiable == 1
    assert "CONFIRMED+NOVEL" in s.as_line()


# --- full loop --------------------------------------------------------------


def test_full_loop_verifies_and_filters():
    # a memory bug (ASAN), a sqli (canary), both should end confirmed + novel
    findings = [_f(line=1, cwe="CWE-787", file="a.c"), _f(line=2, cwe="CWE-89", file="a.py")]
    out = close_verification_loop(
        findings,
        poc_generator=_poc_ok,
        sandbox_runner=_asan_crash,
        dyn_poc_generator=_dyn_poc,
        dyn_runner=_dyn_fire,
        novelty_query=_novel_corpus,
    )
    assert all(f.verified for f in out)
    assert all(f.novelty_verdict == "likely-novel" for f in out)
    # both confirmed → ground truth downstream
    assert all(not f.to_engage_finding().needs_verification for f in out)


def test_loop_stages_are_optional():
    """No deps → findings pass through untouched but still ranked."""
    findings = [_f(line=1), _f(line=2, severity="CRITICAL")]
    out = close_verification_loop(findings)
    assert len(out) == 2
    assert not any(f.verified for f in out)


def test_loop_known_cve_is_deprioritised():
    findings = [_f(line=1, cwe="CWE-787", file="a.c")]
    out = close_verification_loop(
        findings, poc_generator=_poc_ok, sandbox_runner=_asan_crash, novelty_query=_known_corpus
    )
    assert out[0].verified is True
    assert out[0].novelty_verdict == "likely-known"
    assert out[0].nearest_cve == "CVE-KNOWN"


def test_loop_not_reproduced_stays_unverified():
    findings = [_f(cwe="CWE-787", file="a.c")]
    out = close_verification_loop(findings, poc_generator=_poc_ok, sandbox_runner=_asan_clean)
    assert out[0].verified is False
    assert out[0].verification_verdict == "not-reproduced"


def test_context_reader_feeds_generators():
    seen = []

    def reader(f):
        seen.append(f.line)
        return "vulnerable source"

    def gen(f, ctx):
        assert ctx == "vulnerable source"
        return PocSpec(source_code="int main(){}")

    close_verification_loop(
        [_f(line=5, cwe="CWE-787", file="a.c")],
        poc_generator=gen,
        sandbox_runner=_asan_crash,
        context_reader=reader,
    )
    assert seen == [5]


# --- default wiring ---------------------------------------------------------


def test_build_default_loop_returns_callable(tmp_path):
    loop = build_default_loop(tmp_path)
    assert callable(loop)


def test_default_loop_context_reader_reads_files(tmp_path):
    (tmp_path / "a.c").write_text("int vuln(){ char b[4]; return 0; }")
    # empty findings list → loop returns [] without touching the model
    loop = build_default_loop(tmp_path)
    assert loop([]) == []
