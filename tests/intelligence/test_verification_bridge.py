"""Tests for the verification bridge (F2) — reasoned finding → ASAN oracle.

Both impure deps (PoC generator, sandbox runner) are injected as fakes, so
these are pure unit tests: no compiler, no model, no network.
"""

from __future__ import annotations

import pytest

from kryon.intelligence.source_review import SourceFinding
from kryon.intelligence.verification_bridge import (
    LocalPocGenerator,
    PocSpec,
    VerificationResult,
    apply_verification,
    default_sandbox_runner,
    is_asan_verifiable,
    verify_finding,
    verify_findings,
)


def _finding(**kw) -> SourceFinding:
    base = dict(
        file="src/parser.c",
        line=42,
        cwe="CWE-787",
        severity="HIGH",
        title="out-of-bounds write",
        evidence="buf[user_idx] = 0;",
        sink="buf[user_idx]",
        confidence=0.7,
    )
    base.update(kw)
    return SourceFinding(**base)


_GOOD_POC = PocSpec(source_code="int main(){char b[4]; b[9]=1; return 0;}", language="c")


def _gen_ok(finding, ctx):
    return _GOOD_POC


def _crash_runner(spec):
    return {"compiled": True, "crashed": True, "crash_type": "stack-buffer-overflow", "summary": "WRITE of size 1"}


def _clean_runner(spec):
    return {"compiled": True, "crashed": False}


# --- is_asan_verifiable -----------------------------------------------------


def test_memory_cwe_in_c_file_is_verifiable():
    assert is_asan_verifiable(_finding(cwe="CWE-120", file="a.c"))
    assert is_asan_verifiable(_finding(cwe="CWE-416", file="a.cpp"))


def test_non_memory_cwe_is_not_verifiable():
    assert not is_asan_verifiable(_finding(cwe="CWE-89", file="a.c"))
    assert not is_asan_verifiable(_finding(cwe="CWE-79", file="a.c"))


def test_memory_cwe_in_non_c_file_is_not_verifiable():
    assert not is_asan_verifiable(_finding(cwe="CWE-120", file="a.py"))
    assert not is_asan_verifiable(_finding(cwe="CWE-120", file="a.js"))


# --- verify_finding verdicts ------------------------------------------------


def test_crash_is_confirmed():
    r = verify_finding(_finding(), poc_generator=_gen_ok, sandbox_runner=_crash_runner)
    assert r.verdict == "confirmed"
    assert r.crash_type == "stack-buffer-overflow"
    assert "WRITE of size 1" in r.detail
    assert r.poc_source == _GOOD_POC.source_code


def test_clean_run_is_not_reproduced():
    r = verify_finding(_finding(), poc_generator=_gen_ok, sandbox_runner=_clean_runner)
    assert r.verdict == "not-reproduced"


def test_compile_failure_is_build_failed():
    def runner(spec):
        return {"compiled": False, "compile_stderr": "error: use of undeclared 'foo'"}

    r = verify_finding(_finding(), poc_generator=_gen_ok, sandbox_runner=runner)
    assert r.verdict == "poc-build-failed"
    assert "undeclared" in r.detail


def test_no_poc_when_generator_declines():
    r = verify_finding(_finding(), poc_generator=lambda f, c: None, sandbox_runner=_crash_runner)
    assert r.verdict == "no-poc"


def test_empty_poc_is_no_poc():
    r = verify_finding(
        _finding(), poc_generator=lambda f, c: PocSpec(source_code="   "), sandbox_runner=_crash_runner
    )
    assert r.verdict == "no-poc"


def test_unsupported_cwe_short_circuits():
    r = verify_finding(_finding(cwe="CWE-89"), poc_generator=_gen_ok, sandbox_runner=_crash_runner)
    assert r.verdict == "unsupported"
    assert "F3" in r.detail


def test_generator_exception_is_inconclusive():
    def boom(f, c):
        raise RuntimeError("model down")

    r = verify_finding(_finding(), poc_generator=boom, sandbox_runner=_crash_runner)
    assert r.verdict == "inconclusive"
    assert "model down" in r.detail


def test_sandbox_exception_is_inconclusive():
    def boom(spec):
        raise RuntimeError("no compiler")

    r = verify_finding(_finding(), poc_generator=_gen_ok, sandbox_runner=boom)
    assert r.verdict == "inconclusive"
    assert r.poc_source == _GOOD_POC.source_code


def test_sandbox_timeout_is_inconclusive():
    r = verify_finding(_finding(), poc_generator=_gen_ok, sandbox_runner=lambda s: {"timeout": True, "compiled": True})
    assert r.verdict == "inconclusive"
    assert "timed out" in r.detail


def test_sandbox_error_is_inconclusive():
    r = verify_finding(_finding(), poc_generator=_gen_ok, sandbox_runner=lambda s: {"error": "no compiler found"})
    assert r.verdict == "inconclusive"
    assert "no compiler" in r.detail


# --- apply_verification -----------------------------------------------------


def test_apply_confirmed_sets_verified():
    f = _finding()
    r = VerificationResult(verdict="confirmed", crash_type="heap-buffer-overflow", detail="x", poc_source="…")
    out = apply_verification(f, r)
    assert out.verified is True
    assert out.verification_verdict == "confirmed"
    assert out.crash_type == "heap-buffer-overflow"
    assert f.verified is False  # original untouched


def test_apply_not_reproduced_leaves_unverified():
    out = apply_verification(_finding(), VerificationResult("not-reproduced", "", "x", ""))
    assert out.verified is False
    assert out.verification_verdict == "not-reproduced"


def test_confirmed_finding_flips_needs_verification_downstream():
    confirmed = apply_verification(_finding(), VerificationResult("confirmed", "heap-buffer-overflow", "x", "…"))
    ef = confirmed.to_engage_finding()
    assert ef.needs_verification is False
    assert ef.confidence == pytest.approx(0.98)
    # an unverified finding stays needs_verification=True
    assert _finding().to_engage_finding().needs_verification is True


# --- verify_findings batch --------------------------------------------------


def test_batch_verifies_only_asan_classes_and_leaves_rest():
    findings = [_finding(line=1), _finding(line=2, cwe="CWE-89"), _finding(line=3, cwe="CWE-416")]
    out = verify_findings(findings, poc_generator=_gen_ok, sandbox_runner=_crash_runner)
    verdicts = {f.line: f.verification_verdict for f in out}
    assert verdicts[1] == "confirmed"
    assert verdicts[2] == ""  # CWE-89 skipped (only_verifiable), untouched → F3
    assert verdicts[3] == "confirmed"


def test_batch_respects_max_verifications():
    findings = [_finding(line=i) for i in range(5)]
    out = verify_findings(findings, poc_generator=_gen_ok, sandbox_runner=_crash_runner, max_verifications=2)
    confirmed = [f for f in out if f.verified]
    assert len(confirmed) == 2  # budget stopped the rest


def test_batch_context_reader_is_used():
    seen = {}

    def reader(f):
        seen[f.line] = True
        return "int vuln(){}"

    def gen(f, ctx):
        assert ctx == "int vuln(){}"
        return _GOOD_POC

    verify_findings([_finding(line=7)], poc_generator=gen, sandbox_runner=_crash_runner, context_reader=reader)
    assert seen == {7: True}


# --- LocalPocGenerator parsing (no network) ---------------------------------


def test_poc_parse_valid_json():
    raw = '{"language": "cpp", "source_code": "int main(){return 0;}", "stdin_bytes": "AAAA"}'
    spec = LocalPocGenerator._parse(raw)
    assert spec is not None
    assert spec.language == "cpp"
    assert spec.stdin_bytes == "AAAA"


def test_poc_parse_no_poc_token():
    assert LocalPocGenerator._parse("NO_POC") is None


def test_poc_parse_strips_think_and_finds_json():
    raw = "<think>hmm let me write it</think>\n{\"source_code\": \"int main(){}\"}"
    spec = LocalPocGenerator._parse(raw)
    assert spec is not None
    assert spec.language == "c"


def test_poc_parse_malformed_is_none():
    assert LocalPocGenerator._parse("not json at all") is None
    assert LocalPocGenerator._parse('{"source_code": ""}') is None


def test_default_sandbox_runner_handles_non_json(monkeypatch):
    import kryon.tools.code.sandbox as sb

    monkeypatch.setattr(sb, "_run_sandboxed_impl", lambda *a, **k: "not json")
    out = default_sandbox_runner(PocSpec(source_code="int main(){}"))
    assert "error" in out
