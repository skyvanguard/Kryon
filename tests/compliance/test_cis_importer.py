"""Tests for the CIS framework importer (F33).

Coverage: YAML schema validation, pass_when evaluator (all leaves +
combinators), dynamic check factory, error propagation.

Tests never hit real SSH — ``run_cmd`` is monkey-patched to return a
scripted ``(stdout, stderr, rc)`` tuple so the check's execution path
can be exercised deterministically.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any

import pytest

try:
    _schema = importlib.import_module("kryon.compliance.cis.schema")
    _evaluator = importlib.import_module("kryon.compliance.cis.evaluator")
    _importer = importlib.import_module("kryon.compliance.cis.importer")
    PassWhen = _schema.PassWhen
    evaluate = _evaluator.evaluate
    PassWhenError = _evaluator.PassWhenError
    load_framework = _importer.load_framework
    build_check = _importer.build_check
    register_framework = _importer.register_framework
    FrameworkSchemaError = _importer.FrameworkSchemaError
    _parse_framework = _importer._parse_framework  # type: ignore[attr-defined]
    _parse_pass_when = _importer._parse_pass_when  # type: ignore[attr-defined]
except (ImportError, ModuleNotFoundError):
    pytest.skip("compliance/cis module not importable", allow_module_level=True)


_SAMPLE_PATH = (
    Path(__file__).resolve().parents[2] / "src" / "kryon" / "compliance" / "cis" / "frameworks" / "_sample.yaml"
)


# ---------------------------------------------------------------------------
# evaluator — leaves
# ---------------------------------------------------------------------------


def test_evaluate_stdout_contains_passes():
    pw = PassWhen(stdout_contains="PermitRootLogin no")
    assert evaluate(pw, stdout="permitrootlogin no", stderr="", exit_code=0) is False
    assert evaluate(pw, stdout="foo PermitRootLogin no bar", stderr="", exit_code=0) is True


def test_evaluate_stdout_not_contains():
    pw = PassWhen(stdout_not_contains="Protocol 1")
    assert evaluate(pw, stdout="Protocol 2", stderr="", exit_code=0) is True
    assert evaluate(pw, stdout="Protocol 1", stderr="", exit_code=0) is False


def test_evaluate_stdout_matches_regex_multiline():
    pw = PassWhen(stdout_matches=r"^permitrootlogin\s+no")
    out = "ciphers aes256\npermitrootlogin no\nport 22"
    assert evaluate(pw, stdout=out, stderr="", exit_code=0) is True


def test_evaluate_stdout_not_matches():
    pw = PassWhen(stdout_not_matches=r"^Protocol\s+1")
    assert evaluate(pw, stdout="Protocol 2", stderr="", exit_code=0) is True
    assert evaluate(pw, stdout="Protocol 1", stderr="", exit_code=0) is False


def test_evaluate_stdout_empty_true_and_false():
    assert evaluate(PassWhen(stdout_empty=True), stdout="", stderr="", exit_code=0) is True
    assert evaluate(PassWhen(stdout_empty=True), stdout="   \n", stderr="", exit_code=0) is True
    assert evaluate(PassWhen(stdout_empty=True), stdout="x", stderr="", exit_code=0) is False
    assert evaluate(PassWhen(stdout_empty=False), stdout="x", stderr="", exit_code=0) is True


def test_evaluate_exit_code_is():
    pw = PassWhen(exit_code_is=0)
    assert evaluate(pw, stdout="", stderr="", exit_code=0) is True
    assert evaluate(pw, stdout="", stderr="", exit_code=1) is False


def test_evaluate_empty_pass_when_raises():
    with pytest.raises(PassWhenError):
        evaluate(PassWhen(), stdout="", stderr="", exit_code=0)


# ---------------------------------------------------------------------------
# evaluator — combinators
# ---------------------------------------------------------------------------


def test_all_of_requires_every_subcondition():
    pw = PassWhen(
        all_of=(
            PassWhen(stdout_contains="foo"),
            PassWhen(stdout_contains="bar"),
        )
    )
    assert evaluate(pw, stdout="foo bar baz", stderr="", exit_code=0) is True
    assert evaluate(pw, stdout="foo", stderr="", exit_code=0) is False


def test_any_of_passes_if_any_subcondition_holds():
    pw = PassWhen(
        any_of=(
            PassWhen(stdout_contains="foo"),
            PassWhen(stdout_contains="bar"),
        )
    )
    assert evaluate(pw, stdout="only bar here", stderr="", exit_code=0) is True
    assert evaluate(pw, stdout="neither", stderr="", exit_code=0) is False


def test_not_inverts_subcondition():
    pw = PassWhen(not_=PassWhen(stdout_contains="danger"))
    assert evaluate(pw, stdout="safe", stderr="", exit_code=0) is True
    assert evaluate(pw, stdout="danger here", stderr="", exit_code=0) is False


def test_nested_combinators():
    pw = PassWhen(
        all_of=(
            PassWhen(stdout_contains="install /bin/true"),
            PassWhen(not_=PassWhen(stdout_matches=r"^cramfs\s")),
        )
    )
    out_pass = "install /bin/true\nfs info"
    out_fail = "install /bin/true\ncramfs enabled"
    assert evaluate(pw, stdout=out_pass, stderr="", exit_code=0) is True
    assert evaluate(pw, stdout=out_fail, stderr="", exit_code=0) is False


# ---------------------------------------------------------------------------
# _parse_pass_when
# ---------------------------------------------------------------------------


def test_parse_pass_when_rejects_unknown_key():
    with pytest.raises(FrameworkSchemaError):
        _parse_pass_when({"bogus": "x"}, "root")


def test_parse_pass_when_rejects_empty():
    with pytest.raises(FrameworkSchemaError):
        _parse_pass_when({}, "root")


def test_parse_pass_when_accepts_not_and_not_underscore():
    a = _parse_pass_when({"not": {"stdout_contains": "x"}}, "r")
    b = _parse_pass_when({"not_": {"stdout_contains": "x"}}, "r")
    assert a.not_ == b.not_


def test_parse_pass_when_all_of_requires_non_empty_list():
    with pytest.raises(FrameworkSchemaError):
        _parse_pass_when({"all_of": []}, "root")


# ---------------------------------------------------------------------------
# framework parser
# ---------------------------------------------------------------------------


def _valid_check_dict() -> dict[str, Any]:
    return {
        "id": "TEST-1.1",
        "title": "Sample",
        "section": "1",
        "severity": "HIGH",
        "remediation": "fix it",
        "command": "echo ok",
        "pass_when": {"stdout_contains": "ok"},
    }


def test_parse_framework_accepts_minimal_yaml():
    raw = {
        "framework": {"id": "fx", "title": "t", "version": "1"},
        "checks": [_valid_check_dict()],
    }
    fw = _parse_framework(raw)
    assert fw.metadata.id == "fx"
    assert len(fw.checks) == 1
    assert fw.checks[0].id == "TEST-1.1"
    assert fw.checks[0].severity == "HIGH"


def test_parse_framework_rejects_duplicate_check_ids():
    c = _valid_check_dict()
    raw = {
        "framework": {"id": "fx", "title": "t", "version": "1"},
        "checks": [c, c],
    }
    with pytest.raises(FrameworkSchemaError, match="duplicate"):
        _parse_framework(raw)


def test_parse_framework_rejects_bad_severity():
    c = _valid_check_dict()
    c["severity"] = "URGENT"
    raw = {"framework": {"id": "fx", "title": "t", "version": "1"}, "checks": [c]}
    with pytest.raises(FrameworkSchemaError, match="severity"):
        _parse_framework(raw)


def test_parse_framework_rejects_missing_top_level_keys():
    with pytest.raises(FrameworkSchemaError):
        _parse_framework({"framework": {"id": "x", "title": "t", "version": "1"}})
    with pytest.raises(FrameworkSchemaError):
        _parse_framework({"checks": []})


def test_parse_framework_rejects_empty_checks_list():
    raw = {"framework": {"id": "fx", "title": "t", "version": "1"}, "checks": []}
    with pytest.raises(FrameworkSchemaError):
        _parse_framework(raw)


# ---------------------------------------------------------------------------
# sample YAML integration
# ---------------------------------------------------------------------------


def test_sample_framework_loads_and_has_five_checks():
    fw = load_framework(_SAMPLE_PATH)
    assert fw.metadata.id == "cis-sample-ubuntu-l1"
    assert len(fw.checks) == 5
    ids = [c.id for c in fw.checks]
    assert ids == sorted(ids), "sample YAML check ids should be sorted for reproducibility"


def test_sample_framework_every_check_has_valid_schema():
    fw = load_framework(_SAMPLE_PATH)
    for spec in fw.checks:
        assert spec.id.startswith("CIS-")
        assert spec.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        assert spec.command, f"{spec.id}: empty command"
        assert spec.remediation, f"{spec.id}: empty remediation"


# ---------------------------------------------------------------------------
# _CISCheck runtime wrapper — mock run_cmd for deterministic tests
# ---------------------------------------------------------------------------


def _make_check_stub(pass_when: PassWhen) -> Any:
    from kryon.compliance.cis.schema import CheckSpec

    spec = CheckSpec(
        id="TEST-X",
        title="test",
        section="1",
        severity="HIGH",
        remediation="do it",
        command="echo hi",
        pass_when=pass_when,
    )
    return build_check(spec)


def test_check_returns_pass_when_predicate_true(monkeypatch):
    import kryon.compliance.cis.importer as imp

    monkeypatch.setattr(imp, "run_cmd", lambda *a, **kw: ("match", "", 0))
    from kryon.compliance.checks.base import CheckContext

    chk = _make_check_stub(PassWhen(stdout_contains="match"))
    result = chk.run(CheckContext())
    assert result.verdict == "PASS"
    assert result.control_id == "TEST-X"
    assert result.evidence_parsed["passed"] is True


def test_check_returns_fail_when_predicate_false(monkeypatch):
    import kryon.compliance.cis.importer as imp

    monkeypatch.setattr(imp, "run_cmd", lambda *a, **kw: ("nope", "", 0))
    from kryon.compliance.checks.base import CheckContext

    chk = _make_check_stub(PassWhen(stdout_contains="match"))
    result = chk.run(CheckContext())
    assert result.verdict == "FAIL"


def test_check_returns_error_on_transport_failure(monkeypatch):
    """Exit code 124 (timeout) / 127 (command not found) → ERROR, not FAIL."""
    import kryon.compliance.cis.importer as imp
    from kryon.compliance.checks.base import CheckContext

    monkeypatch.setattr(imp, "run_cmd", lambda *a, **kw: ("", "TIMEOUT", 124))
    chk = _make_check_stub(PassWhen(stdout_contains="match"))
    r = chk.run(CheckContext())
    assert r.verdict == "ERROR"
    assert "transport" in r.evidence_parsed["reason"]

    monkeypatch.setattr(imp, "run_cmd", lambda *a, **kw: ("", "not found", 127))
    chk = _make_check_stub(PassWhen(stdout_contains="match"))
    r = chk.run(CheckContext())
    assert r.verdict == "ERROR"


def test_register_framework_registers_all_checks_once(monkeypatch):
    """Every check in the sample YAML ends up in the runner registry."""
    from kryon.compliance import runner

    # Snapshot + restore so other tests see the original state.
    before_ids = {c.control_id for c in runner._REGISTERED_CHECKS}
    try:
        registered = register_framework(_SAMPLE_PATH)
        assert len(registered) == 5
        after_ids = {c.control_id for c in runner._REGISTERED_CHECKS}
        new_ids = after_ids - before_ids
        assert new_ids == {"CIS-1.1.1.1", "CIS-1.3.1", "CIS-5.2.4", "CIS-5.2.5", "CIS-6.2.1"}

        # register_check is idempotent by control_id.
        register_framework(_SAMPLE_PATH)
        assert after_ids == {c.control_id for c in runner._REGISTERED_CHECKS}
    finally:
        runner._REGISTERED_CHECKS[:] = [c for c in runner._REGISTERED_CHECKS if c.control_id in before_ids]


def test_load_framework_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        load_framework("/does/not/exist.yaml")


# ---------------------------------------------------------------------------
# end-to-end smoke: load, run against scripted run_cmd, check all 5 verdicts
# ---------------------------------------------------------------------------


def test_end_to_end_sample_yaml_against_scripted_outputs(monkeypatch):
    """Script run_cmd per check, verify expected verdict for each."""
    import kryon.compliance.cis.importer as imp
    from kryon.compliance.checks.base import CheckContext

    # Scripted (stdout, stderr, rc) keyed by the first 50 chars of the command.
    scripts: dict[str, tuple[str, str, int]] = {
        # CIS-1.1.1.1 cramfs disabled — PASS
        "modprobe -n -v cramfs": ("install /bin/true\n", "", 0),
        # CIS-5.2.4 PermitRootLogin no — PASS
        "sshd -T": ("permitrootlogin no\nport 22\n", "", 0),
        # CIS-5.2.5 Protocol 1 check — PASS (empty output)
        "grep -iE '^Protocol\\s+1'": ("", "", 0),
        # CIS-1.3.1 AIDE installed — FAIL
        "dpkg -s aide": ("", "package not found", 1),
        # CIS-6.2.1 empty password fields — FAIL (one user leaks)
        "awk -F:": ("hacker\n", "", 0),
    }

    def scripted_run(ctx, cmd, **kw):
        for prefix, triple in scripts.items():
            if prefix in cmd:
                return triple
        return ("", f"unscripted: {cmd[:60]}", 99)

    monkeypatch.setattr(imp, "run_cmd", scripted_run)

    fw = load_framework(_SAMPLE_PATH)
    checks = [build_check(spec) for spec in fw.checks]

    ctx = CheckContext()
    results = {chk.control_id: chk.run(ctx) for chk in checks}

    assert results["CIS-1.1.1.1"].verdict == "PASS"
    assert results["CIS-5.2.4"].verdict == "PASS"
    assert results["CIS-5.2.5"].verdict == "PASS"
    assert results["CIS-1.3.1"].verdict == "FAIL"
    assert results["CIS-6.2.1"].verdict == "FAIL"
