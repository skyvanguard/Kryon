"""Tests for session-history sanitization before persistence (#1 continuity)."""

from kryon.cli.reflective_runner import _FINAL_SYNTHESIS_PROMPT
from kryon.services.history_sanitize import ensure_final_assistant, sanitize_history_for_persist


def test_drops_forced_synthesis_prompt_real_case():
    """The observed live case: [user, synth_user, assistant] → [user, assistant].

    The forced-synthesis prompt was injected as a second consecutive 'user' message,
    leaving user/user/assistant that stalled the resumed turn's chat template.
    """
    history = [
        {"role": "user", "content": "Recorda esta palabra clave: TIBURON42"},
        {"role": "user", "content": _FINAL_SYNTHESIS_PROMPT},
        {"role": "assistant", "content": "## Veredicto\nLIMPIO"},
    ]

    clean = sanitize_history_for_persist(history)

    assert [m["role"] for m in clean] == ["user", "assistant"]
    assert clean[0]["content"] == "Recorda esta palabra clave: TIBURON42"
    assert _FINAL_SYNTHESIS_PROMPT not in clean[0]["content"]


def test_keeps_clean_conversation_untouched():
    history = [
        {"role": "user", "content": "audita https://x"},
        {"role": "assistant", "content": "reporte"},
        {"role": "user", "content": "y el puerto 22?"},
        {"role": "assistant", "content": "ssh ok"},
    ]

    assert sanitize_history_for_persist(history) == history


def test_drops_every_internal_directive_marker():
    directives = [
        "El presupuesto de exploración se agotó, producí el reporte",
        "\n---\n## 🪞 Reflection forced (chunk budget exhausted)\n\n...",
        "⚠️ Tu último tool_call fue RECHAZADO por el servidor: JSON inválido",
        "🛑 ABANDONÁ por completo ese enfoque — se rechazó por JSON",
        "Tu turno anterior no produjo NINGUNA acción ni respuesta",
        "🛑🛑🛑 **PREMATURE FINAL_OUTPUT REJECTED** (intento 1/3)",
    ]
    for d in directives:
        history = [
            {"role": "user", "content": "objetivo real"},
            {"role": "user", "content": d},
            {"role": "assistant", "content": "salida"},
        ]
        clean = sanitize_history_for_persist(history)
        assert [m["role"] for m in clean] == ["user", "assistant"], f"no filtró: {d[:40]}"
        assert clean[0]["content"] == "objetivo real"


def test_collapses_consecutive_assistants_after_directive_removal():
    """Longer run: dropping the synth 'user' leaves two adjacent assistants — they
    must merge so the persisted history stays role-alternating."""
    history = [
        {"role": "user", "content": "audita x"},
        {"role": "assistant", "content": "hallazgo parcial"},
        {"role": "user", "content": _FINAL_SYNTHESIS_PROMPT},
        {"role": "assistant", "content": "reporte final"},
    ]

    clean = sanitize_history_for_persist(history)

    assert [m["role"] for m in clean] == ["user", "assistant"]
    assert clean[1]["content"] == "hallazgo parcial\n\nreporte final"


def test_never_merges_tool_turns():
    """Structured tool turns (tool_calls / tool_call_id) must not be merged even if
    adjacent and same-role."""
    history = [
        {"role": "assistant", "content": "", "tool_calls": [{"id": "1"}]},
        {"role": "assistant", "content": "", "tool_calls": [{"id": "2"}]},
    ]

    clean = sanitize_history_for_persist(history)

    assert len(clean) == 2  # not merged


def test_handles_list_shaped_content():
    """Content as list-of-parts (some adapters) is flattened for marker matching."""
    history = [
        {"role": "user", "content": [{"type": "text", "text": "target real"}]},
        {"role": "user", "content": [{"type": "text", "text": _FINAL_SYNTHESIS_PROMPT}]},
        {"role": "assistant", "content": "ok"},
    ]

    clean = sanitize_history_for_persist(history)

    assert [m["role"] for m in clean] == ["user", "assistant"]


def test_non_list_input_returns_empty():
    assert sanitize_history_for_persist(None) == []
    assert sanitize_history_for_persist("nope") == []


def test_preserves_non_dict_items():
    history = ["raw string", {"role": "user", "content": "hola"}]
    assert sanitize_history_for_persist(history) == history


# --- ensure_final_assistant (reasoning-only continuity gap) ---


def test_ensure_final_appends_when_reasoning_only():
    """The observed gap: model answered in reasoning_content, content was empty, so
    the assistant never landed in message_history — history is [user] only."""
    history = [{"role": "user", "content": "decime un color"}]

    out = ensure_final_assistant(history, "azul")

    assert [m["role"] for m in out] == ["user", "assistant"]
    assert out[-1]["content"] == "azul"


def test_ensure_final_no_duplicate_when_already_present():
    """Normal case: content was non-empty so the assistant is already in history —
    ensure must NOT append a duplicate."""
    history = [
        {"role": "user", "content": "decime un color"},
        {"role": "assistant", "content": "azul"},
    ]

    out = ensure_final_assistant(history, "azul")

    assert out == history  # unchanged


def test_ensure_final_no_duplicate_when_final_is_substring():
    """final_output is derived from the last assistant, so containment (either way)
    counts as already-captured."""
    history = [
        {"role": "user", "content": "audita x"},
        {"role": "assistant", "content": "## Veredicto\nLIMPIO\n\n## Hallazgos (0)"},
    ]

    out = ensure_final_assistant(history, "## Veredicto\nLIMPIO")

    assert out == history


def test_ensure_final_appends_after_tool_turn():
    """If the newest assistant is a tool-call turn (no text), the reasoning-only
    final answer still needs appending."""
    history = [
        {"role": "user", "content": "audita x"},
        {"role": "assistant", "content": "", "tool_calls": [{"id": "1"}]},
        {"role": "tool", "tool_call_id": "1", "content": "nmap output"},
    ]

    out = ensure_final_assistant(history, "reporte final")

    assert out[-1] == {"role": "assistant", "content": "reporte final"}


def test_ensure_final_empty_output_is_noop():
    history = [{"role": "user", "content": "hola"}]
    assert ensure_final_assistant(history, "") == history
    assert ensure_final_assistant(history, "   ") == history
    assert ensure_final_assistant(history, None) == history


def test_ensure_final_non_list_history():
    assert ensure_final_assistant(None, "x") == [{"role": "assistant", "content": "x"}]
