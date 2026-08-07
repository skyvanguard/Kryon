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
    # F150 contract mentions ``<think>`` blocks in passing; what we care
    # about is the trailing ``/think`` token that activates Qwen3
    # thinking mode — that should be absent.
    assert not text.rstrip().endswith("/think")


def test_env_on_appends_think_token_at_end(monkeypatch):
    """F160 — Qwen3 chat template expects ``/think`` at the END of
    the last user message, not the start. F159's prepend approach
    made the model treat ``/think`` as text and never enter thinking
    mode (witnessed in F159.B Juice Shop stall)."""
    monkeypatch.setenv("KRYON_DEEP_REASONING", "true")
    text = _phase_preamble("recon", target="x", scope="x", families=[], findings=[])
    assert text.endswith(" /think")
    assert not text.startswith("/think")


def test_env_off_explicit_does_not_append(monkeypatch):
    monkeypatch.setenv("KRYON_DEEP_REASONING", "false")
    text = _phase_preamble("recon", target="x", scope="x", families=[], findings=[])
    assert not text.rstrip().endswith("/think")


def test_think_token_for_every_phase_kind(monkeypatch):
    """The injection is global — applies to every phase the
    orchestrator runs, not just recon."""
    monkeypatch.setenv("KRYON_DEEP_REASONING", "true")
    for phase in ("recon", "vuln_scan", "web_vuln_scan", "compliance_audit", "reporting"):
        text = _phase_preamble(phase, target="x", scope="x", families=[], findings=[])
        assert text.endswith(" /think"), f"phase {phase} missing trailing /think"


def test_existing_preamble_body_preserved(monkeypatch):
    """The /think suffix doesn't strip the rest of the preamble."""
    monkeypatch.setenv("KRYON_DEEP_REASONING", "true")
    text = _phase_preamble("vuln_scan", target="example.com", scope="x", families=[], findings=[])
    assert "example.com" in text
    assert "Phase: vulnerability assessment" in text or "vuln_scan" in text.lower()
    # The F150/F151/F152 contract section is preserved.
    assert "IMPORTANT" in text


def test_think_token_is_final_token(monkeypatch):
    """F160 — ``/think`` must be the LAST token so Qwen3 activates
    thinking. The F150 output contract sits before it."""
    monkeypatch.setenv("KRYON_DEEP_REASONING", "true")
    text = _phase_preamble("recon", target="x", scope="x", families=[], findings=[])
    think_idx = text.rfind("/think")
    contract_idx = text.find("IMPORTANT — after you finish reasoning")
    # /think is the LAST token; contract comes before it.
    assert think_idx > contract_idx
    # Nothing after /think other than the leading space.
    assert text[think_idx:].rstrip() == "/think"
