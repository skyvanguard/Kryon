"""F203.C — Tests for reflective_runner.

Cubre:
- Stuck pattern detection (identical tool+args repetidos)
- Reflection prompt builder (incluye contexto, instrucciones, stuck warning)
- _hash_args estabilidad (mismo dict → mismo hash; otro orden → mismo hash)
- _extract_tool_calls duck-typing tolerante
- run_with_reflection loop (mockeando Runner.run)
- reflect_every=0 passthrough (sin injection)
- Stuck termina con warning incluido en prompt
"""

from __future__ import annotations

import asyncio
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.reflective_runner import (
    _build_reflection_prompt,
    _extract_tool_calls,
    _has_pending_tool_calls,
    _hash_args,
    _is_stuck,
    _ToolCallRecord,
    run_with_reflection,
)

# ---------------------------------------------------------------------------
# _hash_args
# ---------------------------------------------------------------------------


class TestHashArgs:
    def test_stable_for_same_dict(self):
        a = {"url": "https://x", "timeout": 5}
        b = {"url": "https://x", "timeout": 5}
        assert _hash_args(a) == _hash_args(b)

    def test_key_order_invariant(self):
        a = {"url": "https://x", "timeout": 5}
        b = {"timeout": 5, "url": "https://x"}
        assert _hash_args(a) == _hash_args(b)

    def test_different_args_differ(self):
        a = {"url": "https://x"}
        b = {"url": "https://y"}
        assert _hash_args(a) != _hash_args(b)

    def test_handles_unserializable(self):
        # Should not raise — falls back to repr().
        class Custom:
            def __repr__(self) -> str:
                return "<custom>"

        h = _hash_args({"obj": Custom()})
        assert isinstance(h, str)
        assert len(h) == 12


# ---------------------------------------------------------------------------
# _is_stuck
# ---------------------------------------------------------------------------


def _rec(name: str, args_hash: str) -> _ToolCallRecord:
    return _ToolCallRecord(tool_name=name, args_hash=args_hash, args_preview="x")


class TestIsStuck:
    def test_empty_history_not_stuck(self):
        assert _is_stuck([], threshold=2) is None

    def test_single_call_not_stuck(self):
        assert _is_stuck([_rec("nmap", "aaa")], threshold=2) is None

    def test_two_identical_consecutive_is_stuck(self):
        hist = [_rec("nmap", "aaa"), _rec("nmap", "aaa")]
        stuck = _is_stuck(hist, threshold=2)
        assert stuck is not None
        assert stuck.tool_name == "nmap"

    def test_two_different_calls_not_stuck(self):
        hist = [_rec("nmap", "aaa"), _rec("nmap", "bbb")]
        assert _is_stuck(hist, threshold=2) is None

    def test_three_identical_at_tail_triggers(self):
        hist = [
            _rec("curl", "x"),
            _rec("nmap", "aaa"),
            _rec("nmap", "aaa"),
            _rec("nmap", "aaa"),
        ]
        stuck = _is_stuck(hist, threshold=3)
        assert stuck is not None

    def test_higher_threshold_respected(self):
        hist = [_rec("nmap", "aaa"), _rec("nmap", "aaa")]
        # threshold 3 with only 2 calls → not stuck
        assert _is_stuck(hist, threshold=3) is None


# ---------------------------------------------------------------------------
# _build_reflection_prompt
# ---------------------------------------------------------------------------


class TestReflectionPrompt:
    def test_includes_turn_counter(self):
        p = _build_reflection_prompt(
            turns_used=8,
            total_turns_cap=30,
            tool_history=[],
            last_output_summary="",
            stuck_record=None,
        )
        assert "turn 8/30" in p

    def test_includes_5_reflection_questions(self):
        p = _build_reflection_prompt(
            turns_used=4,
            total_turns_cap=30,
            tool_history=[],
            last_output_summary="",
            stuck_record=None,
        )
        for marker in ("aprendí", "hipótesis", "progresando", "skill", "PARAR"):
            assert marker in p

    def test_includes_recent_tools(self):
        hist = [_rec("nmap", "x"), _rec("curl", "y"), _rec("web_fetch_smart", "z")]
        p = _build_reflection_prompt(
            turns_used=3,
            total_turns_cap=10,
            tool_history=hist,
            last_output_summary="",
            stuck_record=None,
        )
        assert "nmap" in p or "curl" in p or "web_fetch_smart" in p

    def test_includes_last_output_preview(self):
        p = _build_reflection_prompt(
            turns_used=4,
            total_turns_cap=30,
            tool_history=[],
            last_output_summary="found a critical SQL injection in /login",
            stuck_record=None,
        )
        assert "SQL injection" in p

    def test_stuck_warning_present_when_stuck(self):
        stuck = _rec("nmap", "samehash")
        p = _build_reflection_prompt(
            turns_used=4,
            total_turns_cap=30,
            tool_history=[stuck, stuck],
            last_output_summary="",
            stuck_record=stuck,
        )
        assert "STUCK PATTERN DETECTED" in p
        assert "nmap" in p

    def test_no_stuck_warning_when_not_stuck(self):
        p = _build_reflection_prompt(
            turns_used=4,
            total_turns_cap=30,
            tool_history=[_rec("curl", "x")],
            last_output_summary="",
            stuck_record=None,
        )
        assert "STUCK PATTERN DETECTED" not in p


# ---------------------------------------------------------------------------
# _extract_tool_calls (duck-typed)
# ---------------------------------------------------------------------------


class TestExtractToolCalls:
    def test_extracts_from_simplenamespace_with_name_arguments(self):
        # Simulate an SDK item with raw_item exposing name + arguments
        raw = SimpleNamespace(name="web_fetch_smart", arguments={"url": "http://x"})
        item = SimpleNamespace(raw_item=raw)
        records = _extract_tool_calls([item])
        assert len(records) == 1
        assert records[0].tool_name == "web_fetch_smart"

    def test_skips_items_without_name(self):
        item = SimpleNamespace(raw_item=SimpleNamespace(other="x"))
        records = _extract_tool_calls([item])
        assert records == []

    def test_handles_empty_list(self):
        assert _extract_tool_calls([]) == []


# ---------------------------------------------------------------------------
# _has_pending_tool_calls
# ---------------------------------------------------------------------------


class TestHasPendingToolCalls:
    def test_no_new_items_returns_false(self):
        r = SimpleNamespace(new_items=[], final_output=None)
        assert _has_pending_tool_calls(r) is False

    def test_final_output_set_returns_false(self):
        r = SimpleNamespace(new_items=[object()], final_output="done!")
        assert _has_pending_tool_calls(r) is False

    def test_new_items_no_final_output_returns_true(self):
        r = SimpleNamespace(new_items=[object()], final_output=None)
        assert _has_pending_tool_calls(r) is True


# ---------------------------------------------------------------------------
# run_with_reflection (integration with mocked Runner)
# ---------------------------------------------------------------------------


def _fake_result(turn_count: int = 1, final_output: str | None = None, items=None):
    """Build a fake RunResult-shaped object."""
    raw = [object() for _ in range(turn_count)]
    return SimpleNamespace(
        raw_responses=raw,
        new_items=items or [],
        final_output=final_output,
        to_input_list=lambda: [{"role": "user", "content": "(history snapshot)"}],
    )


class TestRunWithReflection:
    def test_reflect_every_0_passthrough(self):
        """reflect_every=0 must skip injection entirely (one Runner.run call)."""
        fake = _fake_result(turn_count=5, final_output="all done")
        with patch.object(
            __import__("kryon.sdk.agents.run", fromlist=["Runner"]).Runner,
            "run",
            new=AsyncMock(return_value=fake),
        ) as mock_run:
            result = asyncio.run(
                run_with_reflection(
                    agent=object(),
                    initial_input="hi",
                    reflect_every=0,
                    max_total_turns=10,
                )
            )
        assert mock_run.call_count == 1
        assert result is fake

    def test_finishes_early_when_final_output_set(self):
        """If first chunk emits final_output, no further chunks run."""
        fake = _fake_result(turn_count=2, final_output="finished early")
        with patch.object(
            __import__("kryon.sdk.agents.run", fromlist=["Runner"]).Runner,
            "run",
            new=AsyncMock(return_value=fake),
        ) as mock_run:
            asyncio.run(
                run_with_reflection(
                    agent=object(),
                    initial_input="hi",
                    reflect_every=4,
                    max_total_turns=20,
                )
            )
        # Should only call Runner.run once because agent finished.
        assert mock_run.call_count == 1

    def test_multiple_chunks_when_agent_keeps_calling_tools(self):
        """If final_output stays None, the wrapper keeps cycling until cap."""
        # Non-empty new_items so _has_pending_tool_calls keeps the loop alive.
        tool_item = SimpleNamespace(raw_item=SimpleNamespace(name="curl", arguments={}))
        ongoing = _fake_result(turn_count=4, final_output=None, items=[tool_item])
        with patch.object(
            __import__("kryon.sdk.agents.run", fromlist=["Runner"]).Runner,
            "run",
            new=AsyncMock(return_value=ongoing),
        ) as mock_run:
            asyncio.run(
                run_with_reflection(
                    agent=object(),
                    initial_input="hi",
                    reflect_every=4,
                    max_total_turns=10,
                )
            )
        assert mock_run.call_count >= 2

    def test_input_evolves_after_reflection_injected(self):
        """Second call to Runner.run gets the reflection-augmented history."""
        tool_item = SimpleNamespace(raw_item=SimpleNamespace(name="curl", arguments={}))
        ongoing = _fake_result(turn_count=4, final_output=None, items=[tool_item])
        calls = []

        async def _capture(*args, **kwargs):
            calls.append(kwargs.get("input", args[1] if len(args) > 1 else None))
            return ongoing

        with patch.object(
            __import__("kryon.sdk.agents.run", fromlist=["Runner"]).Runner,
            "run",
            new=AsyncMock(side_effect=_capture),
        ):
            asyncio.run(
                run_with_reflection(
                    agent=object(),
                    initial_input="initial prompt",
                    reflect_every=4,
                    max_total_turns=12,
                )
            )
        # First call: plain string. Subsequent: history list with reflection msg.
        assert calls[0] == "initial prompt"
        assert isinstance(calls[1], list)
        # Last message in the history must include reflection markers
        last_msg = calls[1][-1]
        assert "Reflection turn" in last_msg.get("content", "")
