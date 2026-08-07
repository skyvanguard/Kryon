"""Eje 8: el auto-compact (LLM summary + history.clear) no estrangula al capable.

`_auto_compact_if_needed` (openai_chatcompletions.py) comprime el HISTORIAL
acumulado cuando cruza el threshold. Para el 4B destruye el historial turn-by-turn
(summary LLM lossy + message_history.clear()) — aceptable, su historial es ruido.
Para el capable eso BORRA la evidencia que encadena (hashes/tickets/cookies exactos,
aristas del attack-graph). El fix: capable nunca cae al summary destructivo — se
queda con el historial intacto (over-threshold pero completo > destruido).

Distinto del eje 4 (caps POR-OUTPUT). Este es el historial COMPLETO.
"""

from __future__ import annotations

import pytest

from kryon.sdk.agents.models.openai_chatcompletions import OpenAIChatCompletionsModel


class _StubModel:
    """Mínimo para ejercitar _auto_compact_if_needed sin instanciar el modelo real."""

    def __init__(self, history: list) -> None:
        self.message_history = history
        self.model = "qwen-unc"
        self.agent_name = "kryon"

    def _get_model_max_tokens(self, _model: str) -> int:
        return 1000  # ventana chica → threshold 800 fácil de cruzar en el test


def _big_history() -> list:
    # varios turnos con evidencia que el capable encadenaría
    return [
        {"role": "user", "content": "pentest"},
        {"role": "assistant", "content": "found NTLM hash aad3b435:31d6cfe0 for admin"},
        {"role": "user", "content": "continue"},
        {"role": "assistant", "content": "pivoted to 10.0.0.5, JWT eyJ... captured"},
    ]


async def test_capable_over_threshold_keeps_full_history(monkeypatch):
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
    monkeypatch.setenv("KRYON_MICRO_COMPACT", "false")  # salta el trim → va al skip/summary
    monkeypatch.setenv("KRYON_AUTO_COMPACT", "true")

    hist = _big_history()
    stub = _StubModel(hist)
    # estimated 900 > threshold 800 → compactaría
    new_input, new_sys, compacted = await OpenAIChatCompletionsModel._auto_compact_if_needed(
        stub, 900, "latest", "sys"
    )

    assert compacted is False  # no destruyó el historial
    assert stub.message_history == hist  # intacto, no se vació
    assert new_input == "latest"
    assert new_sys == "sys"


async def test_4b_over_threshold_falls_to_destructive_summary(monkeypatch):
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "false")
    monkeypatch.setenv("KRYON_MICRO_COMPACT", "false")
    monkeypatch.setenv("KRYON_AUTO_COMPACT", "true")

    # el 4B SÍ llama al summarizer destructivo — lo mockeamos para no pegarle a un LLM
    called = {"summarize": False}

    async def _fake_summarize(_agent_name):
        called["summarize"] = True
        return "RESUMEN LOSSY"

    from kryon.repl.commands.memory import MEMORY_COMMAND_INSTANCE

    monkeypatch.setattr(MEMORY_COMMAND_INSTANCE, "_ai_summarize_history", _fake_summarize)

    hist = _big_history()
    stub = _StubModel(hist)
    _new_input, new_sys, compacted = await OpenAIChatCompletionsModel._auto_compact_if_needed(
        stub, 900, "latest", "sys"
    )

    # el contraste con el capable: el 4B SÍ toma el path destructivo — resume y vacía
    # el historial (lo posterior — reconstruir el input desde el converter — es infra
    # ajena a este eje y no la stubeamos).
    assert called["summarize"] is True  # el 4B SÍ resume
    assert stub.message_history == []  # el 4B SÍ vacía el historial
    _ = (compacted, new_sys)


async def test_disabled_short_circuits_for_both(monkeypatch):
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
    monkeypatch.setenv("KRYON_AUTO_COMPACT", "false")

    hist = _big_history()
    stub = _StubModel(hist)
    _i, _s, compacted = await OpenAIChatCompletionsModel._auto_compact_if_needed(stub, 5000, "x", "y")
    assert compacted is False
    assert stub.message_history == hist


async def test_under_threshold_no_compaction(monkeypatch):
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
    monkeypatch.setenv("KRYON_AUTO_COMPACT", "true")

    hist = _big_history()
    stub = _StubModel(hist)
    _i, _s, compacted = await OpenAIChatCompletionsModel._auto_compact_if_needed(stub, 100, "x", "y")
    assert compacted is False
    assert stub.message_history == hist
