"""Tests for the dynamic oracle (F3) — non-memory bug verification by canary.

Fakes for the two impure deps keep most tests pure. A few integration tests
run the REAL default_dynamic_runner against the current Python interpreter
(always available) to prove the canary oracle end-to-end.
"""

from __future__ import annotations

import pytest

from kryon.intelligence.dynamic_oracle import (
    DynamicPocSpec,
    LocalDynamicPocGenerator,
    default_dynamic_runner,
    is_dynamic_verifiable,
    verify_dynamic,
    verify_findings_dynamic,
)
from kryon.intelligence.source_review import SourceFinding

CANARY = "KRYON_CANARY_test123"


def _finding(**kw) -> SourceFinding:
    base = dict(
        file="app/views.py",
        line=88,
        cwe="CWE-89",
        severity="CRITICAL",
        title="SQL injection in login",
        evidence='query = "SELECT * FROM users WHERE u=\'" + name + "\'"',
        sink="execute(query)",
        confidence=0.8,
    )
    base.update(kw)
    return SourceFinding(**base)


def _gen_print(finding, ctx, canary):
    return DynamicPocSpec(script=f'print("{canary}")', language="python", canary=canary)


def _canary_runner(spec):
    # simulate the harness firing the canary
    return {"ran": True, "exit_code": 0, "stdout": spec.canary + "\n", "stderr": ""}


# --- is_dynamic_verifiable --------------------------------------------------


def test_injection_in_dynamic_lang_is_verifiable():
    assert is_dynamic_verifiable(_finding(cwe="CWE-89", file="a.py"))
    assert is_dynamic_verifiable(_finding(cwe="CWE-78", file="a.php"))
    assert is_dynamic_verifiable(_finding(cwe="CWE-502", file="a.rb"))


def test_memory_cwe_is_not_dynamic():
    assert not is_dynamic_verifiable(_finding(cwe="CWE-120", file="a.py"))
    assert not is_dynamic_verifiable(_finding(cwe="CWE-787", file="a.c"))


def test_injection_in_c_file_is_not_dynamic():
    # .c isn't a dynamic-runnable language here
    assert not is_dynamic_verifiable(_finding(cwe="CWE-89", file="a.c"))


# --- verify_dynamic verdicts (fakes) ----------------------------------------


def test_canary_fires_is_confirmed():
    r = verify_dynamic(_finding(), poc_generator=_gen_print, runner=_canary_runner, canary=CANARY)
    assert r.verdict == "confirmed"
    assert "canary fired" in r.detail
    assert CANARY in r.poc_source or "print" in r.poc_source


def test_no_canary_clean_exit_is_not_reproduced():
    def runner(spec):
        return {"ran": True, "exit_code": 0, "stdout": "nothing here"}

    r = verify_dynamic(_finding(), poc_generator=_gen_print, runner=runner, canary=CANARY)
    assert r.verdict == "not-reproduced"


def test_harness_error_is_poc_error():
    def runner(spec):
        return {"ran": True, "exit_code": 1, "stdout": "", "stderr": "Traceback: NameError"}

    r = verify_dynamic(_finding(), poc_generator=_gen_print, runner=runner, canary=CANARY)
    assert r.verdict == "poc-error"
    assert "NameError" in r.detail


def test_unsupported_memory_cwe():
    r = verify_dynamic(_finding(cwe="CWE-120"), poc_generator=_gen_print, runner=_canary_runner)
    assert r.verdict == "unsupported"
    assert "F2" in r.detail


def test_no_poc_when_generator_declines():
    r = verify_dynamic(_finding(), poc_generator=lambda f, c, k: None, runner=_canary_runner)
    assert r.verdict == "no-poc"


def test_generator_exception_is_inconclusive():
    def boom(f, c, k):
        raise RuntimeError("model down")

    r = verify_dynamic(_finding(), poc_generator=boom, runner=_canary_runner)
    assert r.verdict == "inconclusive"


def test_runner_exception_is_inconclusive():
    def boom(spec):
        raise RuntimeError("interp missing")

    r = verify_dynamic(_finding(), poc_generator=_gen_print, runner=boom)
    assert r.verdict == "inconclusive"


def test_runner_timeout_is_inconclusive():
    r = verify_dynamic(_finding(), poc_generator=_gen_print, runner=lambda s: {"timeout": True, "ran": True}, canary=CANARY)
    assert r.verdict == "inconclusive"


def test_runner_error_is_inconclusive():
    r = verify_dynamic(_finding(), poc_generator=_gen_print, runner=lambda s: {"error": "no interpreter"})
    assert r.verdict == "inconclusive"


# --- verify_findings_dynamic batch ------------------------------------------


def test_batch_only_dynamic_classes():
    findings = [_finding(line=1, cwe="CWE-89"), _finding(line=2, cwe="CWE-120"), _finding(line=3, cwe="CWE-78")]
    out = verify_findings_dynamic(findings, poc_generator=_gen_print, runner=_canary_runner)
    v = {f.line: f.verification_verdict for f in out}
    assert v[1] == "confirmed"
    assert v[2] == ""  # memory bug left for F2
    assert v[3] == "confirmed"


def test_batch_confirmed_flips_needs_verification():
    out = verify_findings_dynamic([_finding()], poc_generator=_gen_print, runner=_canary_runner)
    assert out[0].verified is True
    ef = out[0].to_engage_finding()
    assert ef.needs_verification is False


def test_batch_budget_cap():
    findings = [_finding(line=i) for i in range(5)]
    out = verify_findings_dynamic(findings, poc_generator=_gen_print, runner=_canary_runner, max_verifications=2)
    assert len([f for f in out if f.verified]) == 2


# --- REAL runner integration (uses the live Python interpreter) -------------


def test_real_runner_fires_canary_end_to_end():
    """The full loop with the real subprocess runner: a harness that prints the
    canary must come back confirmed."""
    r = verify_dynamic(
        _finding(cwe="CWE-89", file="app.py"),
        poc_generator=_gen_print,
        runner=default_dynamic_runner,
        canary="KRYON_CANARY_realrun",
    )
    assert r.verdict == "confirmed"


def test_real_runner_clean_is_not_reproduced():
    def gen_silent(f, ctx, canary):
        return DynamicPocSpec(script='print("harmless output")', language="python", canary=canary)

    r = verify_dynamic(_finding(), poc_generator=gen_silent, runner=default_dynamic_runner, canary="KRYON_CANARY_x")
    assert r.verdict == "not-reproduced"


def test_real_runner_broken_script_is_poc_error():
    def gen_broken(f, ctx, canary):
        return DynamicPocSpec(script='raise SystemExit(2)', language="python", canary=canary)

    r = verify_dynamic(_finding(), poc_generator=gen_broken, runner=default_dynamic_runner, canary="KRYON_CANARY_y")
    assert r.verdict == "poc-error"


def test_real_runner_unknown_language():
    out = default_dynamic_runner(DynamicPocSpec(script="x", language="cobol", canary="c"))
    assert out["ran"] is False
    assert "no interpreter" in out["error"]


# --- LocalDynamicPocGenerator parsing (no network) --------------------------


def test_dyn_poc_parse_valid():
    raw = '{"language": "php", "script": "<?php echo \\"X\\"; ?>"}'
    spec = LocalDynamicPocGenerator._parse(raw, "X")
    assert spec is not None
    assert spec.language == "php"
    assert spec.canary == "X"


def test_dyn_poc_parse_js_alias():
    spec = LocalDynamicPocGenerator._parse('{"language": "javascript", "script": "console.log(1)"}', "c")
    assert spec is not None
    assert spec.language == "node"


def test_dyn_poc_parse_no_poc():
    assert LocalDynamicPocGenerator._parse("NO_POC", "c") is None


def test_dyn_poc_parse_malformed():
    assert LocalDynamicPocGenerator._parse("garbage", "c") is None
    assert LocalDynamicPocGenerator._parse('{"script": ""}', "c") is None
