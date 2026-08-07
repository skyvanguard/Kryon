"""Tests for audit_target — agentic network audit pipeline (gap #2).

run_target_orchestration is monkeypatched, so no nmap/network is needed.
"""

from __future__ import annotations

from types import SimpleNamespace

from kryon.tools.orchestration import audit as audit_mod
from kryon.tools.orchestration.audit import _audit_impl


def _result(**kw):
    base = dict(services=[], families=[], findings=[], ground_truth="", note="", discovery_ran=True)
    base.update(kw)
    return SimpleNamespace(**base)


def _patch(monkeypatch, result):
    import kryon.services.target_orchestrator as to

    monkeypatch.setattr(to, "run_target_orchestration", lambda *a, **k: result)


def test_empty_target():
    assert _audit_impl("").startswith("ERROR")
    assert _audit_impl("   ").startswith("ERROR")


def test_formats_ground_truth(monkeypatch):
    svc = [SimpleNamespace(port=80), SimpleNamespace(port=443)]
    fam = [SimpleNamespace(name="fortigate")]
    findings = [object(), object()]
    _patch(monkeypatch, _result(services=svc, families=fam, findings=findings, ground_truth="GROUND TRUTH BLOCK"))
    out = _audit_impl("10.0.0.5")
    assert "Auditoría de red" in out
    assert "Servicios**: 2" in out
    assert "fortigate" in out
    assert "Findings**: 2" in out
    assert "GROUND TRUTH BLOCK" in out


def test_cidr_note_passthrough(monkeypatch):
    _patch(monkeypatch, _result(note="'10.0.0.0/24' es un segmento (CIDR)."))
    out = _audit_impl("10.0.0.0/24")
    assert "CIDR" in out


def test_no_findings_message(monkeypatch):
    _patch(monkeypatch, _result(discovery_ran=True))
    out = _audit_impl("host")
    assert "Sin findings" in out


def test_orchestrator_exception_surfaced(monkeypatch):
    import kryon.services.target_orchestrator as to

    def boom(*a, **k):
        raise RuntimeError("nmap missing")

    monkeypatch.setattr(to, "run_target_orchestration", boom)
    out = _audit_impl("host")
    assert out.startswith("ERROR during audit")
    assert "nmap missing" in out


def test_discovery_skipped_note(monkeypatch):
    _patch(monkeypatch, _result(discovery_ran=False, ground_truth="x"))
    out = _audit_impl("host", discover=False)
    assert "discovery omitido" in out


# --- wiring -----------------------------------------------------------------


def test_registered_and_offered():
    from pathlib import Path

    import yaml

    from kryon.skills.tool_budget import build_tool_registry

    assert "audit_target" in build_tool_registry()
    assert audit_mod.audit_target.name == "audit_target"
    md = Path(__file__).resolve().parents[3] / "src/kryon/skills/playbooks/pentest.md"
    fm = yaml.safe_load(md.read_text(encoding="utf-8").split("---")[1])
    assert "audit_target" in fm["required_tools"]
