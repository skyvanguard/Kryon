"""El harness no estrangula al modelo capable — gates A/B1/C/E.

Estos fixes degradan de IMPONER a SUGERIR bajo is_capable_model():
- A : tool_choice="required" forzado por directiva del planner (SDK-level)
- B1: temperatura greedy (engage preflight pre-emptaba el 0.4 capable)
- C : turn budgets levantados en capable (run.py fallback + investigate default)
- E : stance de parada del prompt de investigate (parar-al-cubrir vs encadenar-a-impacto)

Contrato: el downgrade SOLO bajo is_capable_model(); el 4B conserva el régimen duro.
"""

from __future__ import annotations

import argparse
import importlib
import os

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

# ---------------------------------------------------------------------------
# A — directive tool_choice="required" no se fuerza al capable
# ---------------------------------------------------------------------------


class TestDirectiveForceGate:
    def test_capable_never_forced_even_with_env_on(self, monkeypatch):
        from kryon.sdk.agents.models.openai_chatcompletions import (
            _should_force_directive_tool_choice,
        )

        monkeypatch.setenv("KRYON_FORCE_DIRECTIVE_TOOL_CHOICE", "true")
        monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
        # Gated OFF for capable regardless of any pending high-conf directive.
        assert _should_force_directive_tool_choice(True, None) is False

    def test_no_tools_short_circuits(self, monkeypatch):
        from kryon.sdk.agents.models.openai_chatcompletions import (
            _should_force_directive_tool_choice,
        )

        monkeypatch.setenv("KRYON_FORCE_DIRECTIVE_TOOL_CHOICE", "true")
        monkeypatch.setenv("KRYON_CAPABLE_MODEL", "false")
        assert _should_force_directive_tool_choice(False, None) is False

    def test_env_off_short_circuits_for_4b(self, monkeypatch):
        from kryon.sdk.agents.models.openai_chatcompletions import (
            _should_force_directive_tool_choice,
        )

        monkeypatch.setenv("KRYON_FORCE_DIRECTIVE_TOOL_CHOICE", "false")
        monkeypatch.setenv("KRYON_CAPABLE_MODEL", "false")
        assert _should_force_directive_tool_choice(True, None) is False


# ---------------------------------------------------------------------------
# B1 — engage preflight temp: capable recibe 0.4, no greedy 0.0
# ---------------------------------------------------------------------------


class TestPreflightTemperature:
    def _resolve(self, monkeypatch, *, capable: bool):
        monkeypatch.delenv("KRYON_LLM_TEMPERATURE", raising=False)
        monkeypatch.delenv("KRYON_DEEP_REASONING", raising=False)
        monkeypatch.setenv("KRYON_MODEL", "deepseek-chat")  # non-reasoning
        monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true" if capable else "false")
        from kryon.policy import preflight

        return preflight.resolve_policy().temperature

    def test_capable_non_reasoning_gets_0_4(self, monkeypatch):
        assert self._resolve(monkeypatch, capable=True) == pytest.approx(0.4)

    def test_4b_non_reasoning_stays_greedy(self, monkeypatch):
        assert self._resolve(monkeypatch, capable=False) == pytest.approx(0.0)

    def test_explicit_env_temp_wins(self, monkeypatch):
        monkeypatch.delenv("KRYON_DEEP_REASONING", raising=False)
        monkeypatch.setenv("KRYON_MODEL", "deepseek-chat")
        monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
        monkeypatch.setenv("KRYON_LLM_TEMPERATURE", "0.15")
        from kryon.policy import preflight

        assert preflight.resolve_policy().temperature == pytest.approx(0.15)


# ---------------------------------------------------------------------------
# C — turn budgets levantados en capable
# ---------------------------------------------------------------------------


class TestTurnBudgets:
    def test_run_default_max_turns_raised_for_capable(self, monkeypatch):
        monkeypatch.delenv("KRYON_MAX_TURNS", raising=False)
        monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
        import kryon.sdk.agents.run as run_mod

        importlib.reload(run_mod)
        assert run_mod.DEFAULT_MAX_TURNS == 100

    def test_run_default_max_turns_4b(self, monkeypatch):
        monkeypatch.delenv("KRYON_MAX_TURNS", raising=False)
        monkeypatch.setenv("KRYON_CAPABLE_MODEL", "false")
        import kryon.sdk.agents.run as run_mod

        importlib.reload(run_mod)
        assert run_mod.DEFAULT_MAX_TURNS == 40

    def test_run_explicit_env_wins(self, monkeypatch):
        monkeypatch.setenv("KRYON_MAX_TURNS", "25")
        monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
        import kryon.sdk.agents.run as run_mod

        importlib.reload(run_mod)
        assert run_mod.DEFAULT_MAX_TURNS == 25
        # restore module state for the rest of the suite
        monkeypatch.delenv("KRYON_MAX_TURNS", raising=False)
        importlib.reload(run_mod)

    def _investigate_max_turns_default(self, monkeypatch, *, capable: bool):
        monkeypatch.delenv("KRYON_MAX_TURNS", raising=False)
        monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true" if capable else "false")
        from kryon.cli.investigate import add_investigate_subparser

        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers()
        p = add_investigate_subparser(sub)
        action = next(a for a in p._actions if "--max-turns" in a.option_strings)
        return action.default

    def test_investigate_default_raised_for_capable(self, monkeypatch):
        assert self._investigate_max_turns_default(monkeypatch, capable=True) == 60

    def test_investigate_default_4b(self, monkeypatch):
        assert self._investigate_max_turns_default(monkeypatch, capable=False) == 30


# ---------------------------------------------------------------------------
# E — stance de parada del prompt de investigate
# ---------------------------------------------------------------------------


class TestInvestigateStopStance:
    def _prompt(self, monkeypatch, *, capable: bool):
        monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true" if capable else "false")
        from kryon.cli.investigate import _build_investigate_prompt

        return _build_investigate_prompt("audita https://x", {}, True)

    def test_capable_chains_to_impact(self, monkeypatch):
        p = self._prompt(monkeypatch, capable=True)
        assert "encadená hacia impacto" in p
        assert "alcanzaste impacto real" in p

    def test_4b_gets_conservative_stop(self, monkeypatch):
        p = self._prompt(monkeypatch, capable=False)
        assert "el objetivo del operador está cubierto" in p
        assert "encadená hacia impacto" not in p
