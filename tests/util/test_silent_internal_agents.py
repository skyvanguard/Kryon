"""Internal guardrail agents must never render to the user's console.

Regression: the prompt-injection guardrail runs as a sub-agent and its output
was printed via cli_print_agent_messages, dumping a raw JSON panel
("[1] Agent: Prompt Injection Detector … {contains_injection:…}") on top of the
real run output. cli_print_agent_messages must early-return for such agents.
"""

from __future__ import annotations

import contextlib
import io

from kryon.util.message_utils import _SILENT_INTERNAL_AGENTS, cli_print_agent_messages


def _capture(agent_name: str) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cli_print_agent_messages(
            agent_name,
            {"content": '{"contains_injection": false, "confidence": 0.95}'},
            1,
            "kryon-local",
            False,
        )
    return buf.getvalue()


def test_injection_detector_is_silenced() -> None:
    assert "Prompt Injection Detector" in _SILENT_INTERNAL_AGENTS
    assert _capture("Prompt Injection Detector") == ""


def test_normal_agent_still_renders() -> None:
    # A non-internal agent must NOT be silenced (guards against over-broad match).
    out = _capture("Kryon")
    assert out != ""
