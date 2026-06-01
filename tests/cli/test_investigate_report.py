"""Tests for the investigate report builder (observability + anti-bluff)."""

from __future__ import annotations

from kryon.cli import investigate_report as ir
from kryon.cli.investigate_report import (
    _validations_from_chain,
    build_investigate_report,
)


class _Finding:
    def __init__(self, cwe, severity, host, message):
        self.cwe = cwe
        self.severity = severity
        self.host = host
        self.message = message


def test_validations_confirmed():
    chain = [{"tool": "validate_sqli", "output_preview": '{"validation_status":"confirmed"}'}]
    v = _validations_from_chain(chain)
    assert v and v[0]["status"] == "confirmed"


def test_validations_false_positive():
    chain = [{"tool": "validate_rce", "output_preview": "false_positive: no shell"}]
    assert _validations_from_chain(chain)[0]["status"] == "false_positive"


def test_validations_ignores_non_validation_tools():
    chain = [{"tool": "nmap", "output_preview": "confirmed open 80"}]
    assert _validations_from_chain(chain) == []


def test_negation_not_misread_as_confirmed():
    """Anti-bluff regression: 'not confirmed' / 'could not be confirmed'
    must NOT show as ✅ CONFIRMADO (the old `"confirmed" in pl` bug)."""
    for txt in (
        "could not be confirmed as exploitable",
        "the SQLi was not confirmed by sqlmap",
        "result: unconfirmed",
    ):
        chain = [{"tool": "validate_sqli", "output_preview": txt}]
        assert _validations_from_chain(chain)[0]["status"] == "false_positive", txt


def test_structured_verdict_is_authoritative_over_proof_text():
    """A false_positive verdict whose raw proof text happens to contain the
    word 'confirmed' must still classify as false_positive."""
    preview = (
        '{"validation_status": "false_positive", "exploit_proof": '
        '"target could be confirmed vulnerable under other conditions"}'
    )
    chain = [{"tool": "validate_sqli", "output_preview": preview}]
    assert _validations_from_chain(chain)[0]["status"] == "false_positive"


def test_potential_verdict_maps_to_ran_not_confirmed():
    preview = '{"validation_status": "potential", "exploit_proof": "is vulnerable maybe"}'
    chain = [{"tool": "validate_rce", "output_preview": preview}]
    assert _validations_from_chain(chain)[0]["status"] == "ran"


def test_sqlmap_not_injectable_is_false_positive():
    preview = '{"validation_status": "false_positive", "exploit_proof": "parameter does not appear to be injectable"}'
    chain = [{"tool": "validate_sqli", "output_preview": preview}]
    assert _validations_from_chain(chain)[0]["status"] == "false_positive"


def test_report_separates_verified_and_alleged():
    det = [_Finding("CWE-89", "HIGH", "10.0.0.1", "SQLi in login form")]
    chain = [
        {"tool": "validate_sqli", "args": "--url x", "output_preview": "confirmed"},
        {"tool": "nmap", "args": "-sV"},
    ]
    r = build_investigate_report(
        prompt="audit x", active=True, output="Maybe XSS on /search", deterministic_findings=det, chain=chain
    )
    # Verified block has the deterministic finding + the confirmed validator
    assert "Verificado" in r and "CWE-89" in r
    assert "CONFIRMADO" in r and "validate_sqli" in r
    # Alleged block has the LLM prose, clearly labelled
    assert "ALEGADO" in r and "Maybe XSS on /search" in r
    # Tool chain rendered
    assert "Cadena de herramientas" in r and "nmap" in r


def test_report_empty_run_is_honest():
    r = build_investigate_report(
        prompt="x", active=False, output="", deterministic_findings=[], chain=[]
    )
    assert "ninguno" in r  # no verified findings
    assert "no produjo salida" in r  # no LLM output


def test_persist_writes_stable_path(monkeypatch, tmp_path):
    monkeypatch.setattr(ir, "_REPORT_DIR", tmp_path)
    p = ir.persist_investigate_report("# report", when="20260101-000000")
    assert p.exists()
    assert p.read_text(encoding="utf-8") == "# report"
    assert p.name == "investigate-20260101-000000.md"
