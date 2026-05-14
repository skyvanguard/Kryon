"""F159 — Deep reasoning preamble injection tests.

Verifies the orchestrator's ``_phase_preamble`` prepends ``/think``
when ``KRYON_DEEP_REASONING=true``. This is what activates Qwen3
dense's chain-of-thought on the kryon-14b base instruct model.
"""

from __future__ import annotations

import pytest

from kryon.cli.engage import _phase_preamble


@pytest.fixture(autouse=True)
def _no_deep_reasoning(monkeypatch):
    """Default for each test: KRYON_DEEP_REASONING off. Tests that
    need it on opt in explicitly."""
    monkeypatch.delenv("KRYON_DEEP_REASONING", raising=False)
    yield


def test_default_preamble_does_not_inject_think_token(monkeypatch):
    monkeypatch.delenv("KRYON_DEEP_REASONING", raising=False)
    text = _phase_preamble("recon", target="x", scope="x", families=[], findings=[])
    assert not text.startswith("/think")


def test_env_on_prepends_think_token(monkeypatch):
    monkeypatch.setenv("KRYON_DEEP_REASONING", "true")
    text = _phase_preamble("recon", target="x", scope="x", families=[], findings=[])
    assert text.startswith("/think\n\n")


def test_env_off_explicit_does_not_prepend(monkeypatch):
    monkeypatch.setenv("KRYON_DEEP_REASONING", "false")
    text = _phase_preamble("recon", target="x", scope="x", families=[], findings=[])
    assert not text.startswith("/think")


def test_think_token_for_every_phase_kind(monkeypatch):
    """The injection is global — applies to every phase the
    orchestrator runs, not just recon."""
    monkeypatch.setenv("KRYON_DEEP_REASONING", "true")
    for phase in ("recon", "vuln_scan", "web_vuln_scan", "compliance_audit", "reporting"):
        text = _phase_preamble(phase, target="x", scope="x", families=[], findings=[])
        assert text.startswith("/think\n\n"), f"phase {phase} missing /think"


def test_existing_preamble_body_preserved(monkeypatch):
    """The /think prefix doesn't strip the rest of the preamble."""
    monkeypatch.setenv("KRYON_DEEP_REASONING", "true")
    text = _phase_preamble("vuln_scan", target="britimp.com.py", scope="x", families=[], findings=[])
    assert "britimp.com.py" in text
    assert "Phase: vulnerability assessment" in text or "vuln_scan" in text.lower()


def test_think_appears_before_f150_contract(monkeypatch):
    """``/think`` must be the FIRST token so Qwen3 activates thinking;
    the F150 output contract appended later doesn't interfere."""
    monkeypatch.setenv("KRYON_DEEP_REASONING", "true")
    text = _phase_preamble("recon", target="x", scope="x", families=[], findings=[])
    think_idx = text.find("/think")
    contract_idx = text.find("IMPORTANT — after you finish reasoning")
    assert think_idx == 0
    assert contract_idx > think_idx
