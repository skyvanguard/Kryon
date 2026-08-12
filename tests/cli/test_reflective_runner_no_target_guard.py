"""No-target guard: a fresh message naming no target runs ONE toolless turn so the
model answers in text and physically cannot fire spurious tools (the base offensive
prompt otherwise pushed even a capable model to run a command just to say "hola").
"""

from __future__ import annotations

import types

from kryon.cli.reflective_runner import (
    _answer_targetless,
    _fresh_user_text,
    _is_targetless_opening,
    _looks_targetless,
)

# --- _fresh_user_text ---


def test_fresh_user_text_bare_string():
    assert _fresh_user_text("hola") == "hola"


def test_fresh_user_text_strips():
    assert _fresh_user_text("  auditá algo  ") == "auditá algo"


def test_fresh_user_text_empty_is_none():
    assert _fresh_user_text("   ") is None


def test_fresh_user_text_single_user_message_list():
    assert _fresh_user_text([{"role": "user", "content": "hola"}]) == "hola"


def test_fresh_user_text_history_is_none():
    # More than one message = mid-engagement, not a fresh opening.
    hist = [
        {"role": "user", "content": "audita x"},
        {"role": "assistant", "content": "ok"},
        {"role": "user", "content": "seguí"},
    ]
    assert _fresh_user_text(hist) is None


def test_fresh_user_text_single_non_user_is_none():
    assert _fresh_user_text([{"role": "assistant", "content": "hi"}]) is None


# --- _looks_targetless (conservative address-token detector) ---


def test_looks_targetless_plain_greeting():
    assert _looks_targetless("decime hola, sin herramientas") is True


def test_looks_targetless_general_question():
    assert _looks_targetless("che, qué podés hacer?") is True


def test_url_scheme_is_a_target():
    # The exact case resolve_target missed: a dotless docker hostname + port.
    assert _looks_targetless("auditá https://juice_shop:3000") is False


def test_dotted_domain_is_a_target():
    assert _looks_targetless("pentest example.com por favor") is False


def test_ipv4_is_a_target():
    assert _looks_targetless("escaneá 192.168.1.1") is False


def test_cidr_is_a_target():
    assert _looks_targetless("barrer 10.0.0.0/24") is False


def test_host_port_is_a_target():
    assert _looks_targetless("mirá dvwa:8080") is False


# --- _is_targetless_opening ---


def test_targetless_greeting_fires(monkeypatch):
    monkeypatch.delenv("KRYON_NO_TARGET_GUARD", raising=False)
    assert _is_targetless_opening("decime hola, sin herramientas") is True


def test_with_target_does_not_fire():
    # A real engagement opening must NOT be treated as targetless.
    assert _is_targetless_opening("auditá https://juice_shop:3000") is False


def test_mid_engagement_does_not_fire():
    # Even with no target in the LAST message, prior history means it's not fresh.
    hist = [
        {"role": "user", "content": "audita x"},
        {"role": "assistant", "content": "ok"},
        {"role": "user", "content": "seguí"},
    ]
    assert _is_targetless_opening(hist) is False


def test_env_disable_turns_it_off(monkeypatch):
    monkeypatch.setenv("KRYON_NO_TARGET_GUARD", "false")
    assert _is_targetless_opening("hola") is False


# --- _answer_targetless (the toolless run) ---


async def test_answer_targetless_runs_one_toolless_turn(monkeypatch):
    calls: dict = {}

    class _FakeAgent:
        def clone(self, **kw):
            calls["clone_kw"] = kw
            return self

    async def _fake_run(agent, *, input, max_turns, run_config):
        calls["max_turns"] = max_turns
        ms = getattr(run_config, "model_settings", None)
        calls["tool_choice"] = getattr(ms, "tool_choice", None)
        calls["max_tokens"] = getattr(ms, "max_tokens", None)
        return types.SimpleNamespace(final_output="hola")

    monkeypatch.setattr("kryon.sdk.agents.run.Runner.run", _fake_run)

    result = await _answer_targetless(_FakeAgent(), "decime hola", None)

    assert result.final_output == "hola"
    assert calls["clone_kw"] == {"tools": []}  # cloned WITHOUT tools
    assert calls["max_turns"] == 1  # a single turn, no chaining
    assert calls["tool_choice"] == "none"  # belt-and-suspenders over the toolless clone
    assert calls["max_tokens"] == 512  # bounded — no multi-minute reasoning dump for a greeting


async def test_run_with_reflection_short_circuits_on_targetless(monkeypatch):
    """The guard wires into run_with_reflection: a targetless opening returns the
    toolless answer without ever entering the reflective loop."""
    from kryon.cli import reflective_runner as rr

    monkeypatch.setattr(rr, "_is_targetless_opening", lambda _inp: True)

    async def _fake_answer(agent, initial_input, run_config):
        return types.SimpleNamespace(final_output="respondido en texto")

    monkeypatch.setattr(rr, "_answer_targetless", _fake_answer)

    # If the short-circuit fails, Runner.run would be hit — make that a loud failure.
    async def _boom(*a, **k):
        raise AssertionError("reflective loop ran despite the no-target short-circuit")

    monkeypatch.setattr("kryon.sdk.agents.run.Runner.run", _boom)

    out = await rr.run_with_reflection(object(), "hola")
    assert out.final_output == "respondido en texto"
