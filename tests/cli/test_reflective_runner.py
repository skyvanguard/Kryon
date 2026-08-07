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
    ItemCaptureHooks,
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

    # --- Fase 1: Adviser escalation on stall/stuck + anti-repeat block ---

    def test_low_conf_next_action_stays_below_when_not_stuck(self):
        """Baseline: a low-confidence recommendation without a stall goes in the
        lower (soft) slot, NOT escalated to the imperative top."""
        from kryon.intelligence.exploit_chain_planner import NextActionRecommendation

        rec = NextActionRecommendation(
            tool="run_command",
            args="GetNPUsers.py -no-pass corp.local/",
            rationale="users + domain known",
            confidence=0.6,
        )
        p = _build_reflection_prompt(
            turns_used=4,
            total_turns_cap=30,
            tool_history=[_rec("nmap", "x")],
            last_output_summary="",
            stuck_record=None,
            next_action=rec,
            stall_detected=False,
        )
        assert "ESTÁS REPITIENDO SIN PROGRESO" not in p
        assert "GetNPUsers.py" in p  # still present, just not escalated

    def test_low_conf_next_action_escalated_to_imperative_on_stall(self):
        """PentAGI Mentor: when the loop stalls, promote the concrete low-conf
        recommendation to the imperative top slot — the model choosing freely
        has failed, so give it a concrete next step up front."""
        from kryon.intelligence.exploit_chain_planner import NextActionRecommendation

        rec = NextActionRecommendation(
            tool="run_command",
            args="GetNPUsers.py -no-pass corp.local/",
            rationale="users + domain known",
            confidence=0.6,
        )
        p = _build_reflection_prompt(
            turns_used=8,
            total_turns_cap=30,
            tool_history=[_rec("nmap", "x")],
            last_output_summary="",
            stuck_record=None,
            next_action=rec,
            stall_detected=True,
        )
        assert "ESTÁS REPITIENDO SIN PROGRESO" in p
        # escalation renders ABOVE the reflection questions (top slot)
        assert p.index("ESTÁS REPITIENDO SIN PROGRESO") < p.index("aprendí")

    def test_low_conf_next_action_escalated_on_stuck_record(self):
        """A stuck_record (identical tool+args) also escalates the recommendation,
        not just the facts-signature stall."""
        from kryon.intelligence.exploit_chain_planner import NextActionRecommendation

        stuck = _rec("nmap", "samehash")
        rec = NextActionRecommendation(
            tool="run_command",
            args="ldapsearch -x -b dc=corp,dc=local",
            rationale="anon LDAP not yet tried",
            confidence=0.5,
        )
        p = _build_reflection_prompt(
            turns_used=6,
            total_turns_cap=30,
            tool_history=[stuck, stuck],
            last_output_summary="",
            stuck_record=stuck,
            next_action=rec,
        )
        assert "ESTÁS REPITIENDO SIN PROGRESO" in p
        assert "ldapsearch" in p

    def test_capable_model_gets_softer_escalation_tone(self):
        """Gating: for a capable model the escalation is a strong nudge it can
        override; for the 4B regime it's an order."""
        from kryon.intelligence.exploit_chain_planner import NextActionRecommendation

        rec = NextActionRecommendation(
            tool="run_command",
            args="GetNPUsers.py -no-pass corp.local/",
            rationale="users + domain known",
            confidence=0.6,
        )

        def _build():
            return _build_reflection_prompt(
                turns_used=8,
                total_turns_cap=30,
                tool_history=[_rec("nmap", "x")],
                last_output_summary="",
                stuck_record=None,
                next_action=rec,
                stall_detected=True,
            )

        with patch("kryon.util.env.is_capable_model", return_value=True):
            capable = _build()
        with patch("kryon.util.env.is_capable_model", return_value=False):
            regime4b = _build()

        assert "Considerá" in capable  # nudge
        assert "EJECUTÁ ESTA ACCIÓN AHORA" in regime4b  # order

    def test_high_conf_next_action_not_double_escalated(self):
        """A high-confidence rec is already in the top slot; a concurrent stall
        must NOT wrap it in the 'repitiendo' escalation (avoid double-imperative)."""
        from kryon.intelligence.exploit_chain_planner import NextActionRecommendation

        rec = NextActionRecommendation(
            tool="run_command",
            args="GetNPUsers.py -no-pass corp.local/",
            rationale="high confidence",
            confidence=0.95,
        )
        p = _build_reflection_prompt(
            turns_used=8,
            total_turns_cap=30,
            tool_history=[_rec("nmap", "x")],
            last_output_summary="",
            stuck_record=None,
            next_action=rec,
            stall_detected=True,
        )
        assert "ESTÁS REPITIENDO SIN PROGRESO" not in p
        assert "GetNPUsers.py" in p

    def test_anti_repeat_block_lists_executed_commands(self):
        """hackingBuddyGPT: the prompt names the ACTUAL executed (tool, args) with
        a 'do not repeat' directive — dynamic, not hardcoded examples."""
        hist = [
            _ToolCallRecord(tool_name="nmap", args_hash="a", args_preview="-sV 10.0.0.5"),
            _ToolCallRecord(tool_name="smbclient", args_hash="b", args_preview="-L //10.0.0.5 -N"),
        ]
        p = _build_reflection_prompt(
            turns_used=5,
            total_turns_cap=30,
            tool_history=hist,
            last_output_summary="",
            stuck_record=None,
        )
        assert "Ya ejecutado" in p
        assert "NO repitas" in p
        assert "-L //10.0.0.5 -N" in p
        assert "-sV 10.0.0.5" in p

    def test_anti_repeat_block_absent_when_no_history(self):
        p = _build_reflection_prompt(
            turns_used=1,
            total_turns_cap=30,
            tool_history=[],
            last_output_summary="",
            stuck_record=None,
        )
        assert "Ya ejecutado" not in p

    def test_anti_repeat_block_dedupes_identical_calls(self):
        """Repeated identical invocations collapse to one line (readability)."""
        rec = _ToolCallRecord(tool_name="nmap", args_hash="a", args_preview="-sV 10.0.0.5")
        p = _build_reflection_prompt(
            turns_used=5,
            total_turns_cap=30,
            tool_history=[rec, rec, rec],
            last_output_summary="",
            stuck_record=None,
        )
        assert p.count("-sV 10.0.0.5") == 1


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

    def test_empty_final_output_does_not_end_run_immediately(self):
        """Empty final_output (thinking-model reasoning-only dud) must NOT end the run at the
        first chunk — the runner falls back (autoexec/nudge) and continues, bounded so it still
        terminates. Regression: Qwen3.5 died at turn 2/12 emitting an empty output."""
        empty = _fake_result(turn_count=2, final_output="")  # the dud
        with patch.object(
            __import__("kryon.sdk.agents.run", fromlist=["Runner"]).Runner,
            "run",
            new=AsyncMock(return_value=empty),
        ) as mock_run:
            asyncio.run(
                run_with_reflection(
                    agent=object(),
                    initial_input="hi",
                    reflect_every=4,
                    max_total_turns=20,
                )
            )
        # Empty output is converted to continuations (vs the 1 call a real final_output gets),
        # and the run still terminates (the fallback is bounded — no infinite loop).
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


# ---------------------------------------------------------------------------
# F203.K — ItemCaptureHooks
# ---------------------------------------------------------------------------


class TestItemCaptureHooks:
    def test_initial_state_empty(self):
        h = ItemCaptureHooks()
        assert h.captured_items == []
        assert h.to_chain() == []

    def test_on_tool_start_appends_entry(self):
        h = ItemCaptureHooks()
        tool = SimpleNamespace(name="web_fetch_smart")

        async def _run():
            await h.on_tool_start(None, None, tool)

        asyncio.run(_run())
        assert len(h.captured_items) == 1
        assert h.captured_items[0]["tool"] == "web_fetch_smart"
        assert h.captured_items[0]["type"] == "tool_call"
        assert h.captured_items[0]["output_preview"] == ""

    def test_on_tool_end_attaches_output(self):
        h = ItemCaptureHooks()
        tool = SimpleNamespace(name="curl_command")

        async def _run():
            await h.on_tool_start(None, None, tool)
            await h.on_tool_end(None, None, tool, "HTTP 200 OK")

        asyncio.run(_run())
        assert h.captured_items[0]["output_preview"] == "HTTP 200 OK"

    def test_multiple_tool_calls(self):
        h = ItemCaptureHooks()
        t1 = SimpleNamespace(name="web_fetch_smart")
        t2 = SimpleNamespace(name="duckduckgo_search")

        async def _run():
            await h.on_tool_start(None, None, t1)
            await h.on_tool_end(None, None, t1, "page content")
            await h.on_tool_start(None, None, t2)
            await h.on_tool_end(None, None, t2, "search results")

        asyncio.run(_run())
        chain = h.to_chain()
        assert len(chain) == 2
        assert chain[0]["tool"] == "web_fetch_smart"
        assert chain[0]["output_preview"] == "page content"
        assert chain[1]["tool"] == "duckduckgo_search"
        assert chain[1]["output_preview"] == "search results"

    def test_on_agent_end_recorded_separately(self):
        h = ItemCaptureHooks()
        tool = SimpleNamespace(name="x")

        async def _run():
            await h.on_tool_start(None, None, tool)
            await h.on_tool_end(None, None, tool, "out")
            await h.on_agent_end(None, None, "final summary")

        asyncio.run(_run())
        # captured_items has both tool_call and agent_end
        assert len(h.captured_items) == 2
        # to_chain() only returns tool_call entries
        chain = h.to_chain()
        assert len(chain) == 1
        assert chain[0]["tool"] == "x"

    def test_output_truncated_at_500_chars(self):
        h = ItemCaptureHooks()
        tool = SimpleNamespace(name="big_tool")

        async def _run():
            await h.on_tool_start(None, None, tool)
            await h.on_tool_end(None, None, tool, "x" * 1000)

        asyncio.run(_run())
        assert len(h.captured_items[0]["output_preview"]) == 500


class TestHooksIntegrationWithReflectiveRunner:
    """Verify that capture_hooks attached on the final result so write-back
    has access via _captured_chain attr."""

    def test_captured_chain_attached_on_early_finish(self):
        # Simulate one chunk that finishes naturally
        tool_item = SimpleNamespace(raw_item=SimpleNamespace(name="x", arguments={}))
        ongoing = _fake_result(turn_count=2, final_output="done", items=[tool_item])

        async def _capture(*args, **kwargs):
            # Verify hooks were passed
            assert "hooks" in kwargs
            hooks = kwargs["hooks"]
            # Simulate the hooks being invoked during the run (we can't
            # actually run agents in unit tests, just check wiring).
            await hooks.on_tool_start(None, None, SimpleNamespace(name="fake_tool"))
            await hooks.on_tool_end(None, None, SimpleNamespace(name="fake_tool"), "out")
            return ongoing

        with patch.object(
            __import__("kryon.sdk.agents.run", fromlist=["Runner"]).Runner,
            "run",
            new=AsyncMock(side_effect=_capture),
        ):
            result = asyncio.run(
                run_with_reflection(
                    agent=object(),
                    initial_input="hi",
                    reflect_every=4,
                    max_total_turns=10,
                )
            )
        # _captured_chain attached on result
        chain = getattr(result, "_captured_chain", None)
        assert chain is not None
        assert len(chain) == 1
        assert chain[0]["tool"] == "fake_tool"
        assert chain[0]["output_preview"] == "out"


# ---------------------------------------------------------------------------
# Scaffolding hardening: facts_signature breadth + chunk-text from .output
# ---------------------------------------------------------------------------


def test_facts_signature_moves_on_host_service_path_progress():
    from kryon.cli.reflective_runner import _facts_signature
    from kryon.intelligence.fact_extractor import ExtractedFacts

    base = ExtractedFacts()
    # Progress ONLY in hosts/services/paths/versions (not the original 5 fields).
    grew_hosts = ExtractedFacts(hosts=("10.0.0.5",))
    grew_services = ExtractedFacts(services=((22, "ssh"),))
    grew_paths = ExtractedFacts(paths=("/admin",))
    grew_versions = ExtractedFacts(versions=(("nginx", "1.18"),))
    for f in (grew_hosts, grew_services, grew_paths, grew_versions):
        assert _facts_signature(f) != _facts_signature(base), f


def test_extract_chunk_text_reads_model_response_output():
    from kryon.cli.reflective_runner import _extract_chunk_text

    # ModelResponse shape: text lives in .output message items, .message is absent,
    # final_output is empty (a tool-calling turn). The old code returned "".
    msg_item = SimpleNamespace(content=[SimpleNamespace(text="thinking thinking thinking")])
    resp = SimpleNamespace(output=[msg_item])
    result = SimpleNamespace(raw_responses=[resp], final_output="")
    assert "thinking thinking thinking" in _extract_chunk_text(result)


def test_extract_chunk_text_falls_back_to_final_output():
    from kryon.cli.reflective_runner import _extract_chunk_text

    result = SimpleNamespace(raw_responses=[], final_output="just the summary")
    assert _extract_chunk_text(result) == "just the summary"


# ---------------------------------------------------------------------------
# Attack-path chaining — harness no longer strangles the capable model
# (Fixes ①/②/③: rich graph state reaches the driving model; the distilled
#  rec + stall block stop being 4B-style imperatives under a capable model.)
# ---------------------------------------------------------------------------


def _facts(**kw):
    """ExtractedFacts-shaped stub for the attack-graph builder (duck-typed)."""
    base = dict(hosts=("10.0.0.5",), users=(), creds=(), domains=(), hashes=(), hints=())
    base.update(kw)
    return SimpleNamespace(
        render_for_prompt=lambda: "FACTS_MARKER",
        is_empty=lambda: False,
        **base,
    )


class TestRenderGraphState:
    """Fix ① helper — the proven attack-graph state handed to the driving model."""

    def test_renders_proven_chain_when_impact_reached(self):
        from kryon.cli.reflective_runner import _render_graph_state

        out = _render_graph_state(None, _facts(hints=("privesc: sudo -l NOPASSWD",)), [])
        assert "Attack-graph" in out
        assert "Demonstrated attack paths" in out
        assert "root" in out  # access —[privesc]→ root

    def test_renders_pursuit_when_impact_not_reached(self):
        from kryon.cli.reflective_runner import _render_graph_state

        out = _render_graph_state(None, _facts(), [])
        assert "Path-pursuit" in out
        assert "NEXT LINK to prove" in out

    def test_never_raises_on_none_inputs(self):
        from kryon.cli.reflective_runner import _render_graph_state

        # Must not blow up the run even with no graph and no facts.
        assert isinstance(_render_graph_state(None, None, None), str)


class TestGraphBlockInjection:
    """Fix ① wiring — graph_block lands ABOVE facts in the reflection prompt."""

    def test_graph_block_present_and_above_facts(self):
        p = _build_reflection_prompt(
            turns_used=4,
            total_turns_cap=30,
            tool_history=[_rec("nmap", "x")],
            last_output_summary="",
            stuck_record=None,
            extracted_facts=_facts(),
            graph_block="\n## 🕸️ Attack-graph — proven state\nGRAPH_MARKER\n",
        )
        assert "GRAPH_MARKER" in p
        assert "FACTS_MARKER" in p
        # the proven state must read before the raw facts dump
        assert p.index("GRAPH_MARKER") < p.index("FACTS_MARKER")


class TestCapableModelNotStrangled:
    """Fixes ②/③ — under a capable model the distilled rec is not top-slotted
    and the stall block is a decision, not a verbatim-copy order."""

    def _high_conf_rec(self):
        from kryon.intelligence.exploit_chain_planner import NextActionRecommendation

        return NextActionRecommendation(
            tool="run_command",
            args="GetNPUsers.py -no-pass corp.local/",
            rationale="users + domain known",
            confidence=0.95,
        )

    def test_capable_high_conf_rec_drops_below_facts(self):
        """Fix ②: a capable model reads facts first; its high-conf distilled rec
        is NOT hoisted to the imperative top slot (it sits below facts)."""
        rec = self._high_conf_rec()

        def _build():
            return _build_reflection_prompt(
                turns_used=4,
                total_turns_cap=30,
                tool_history=[_rec("nmap", "x")],
                last_output_summary="",
                stuck_record=None,
                extracted_facts=_facts(),
                next_action=rec,
                stall_detected=False,
            )

        with patch("kryon.util.env.is_capable_model", return_value=True):
            capable = _build()
        with patch("kryon.util.env.is_capable_model", return_value=False):
            regime4b = _build()

        # capable: rec renders AFTER the facts dump (lower slot)
        assert capable.index("GetNPUsers.py") > capable.index("FACTS_MARKER")
        # 4B: rec is top-slotted, BEFORE the facts dump
        assert regime4b.index("GetNPUsers.py") < regime4b.index("FACTS_MARKER")

    def test_capable_stall_block_is_a_decision_not_verbatim_copy(self):
        """Fix ③: the stall block for a capable model does not order a
        letter-for-letter copy of the directive."""

        def _build():
            return _build_reflection_prompt(
                turns_used=8,
                total_turns_cap=30,
                tool_history=[_rec("nmap", "x")],
                last_output_summary="",
                stuck_record=None,
                extracted_facts=_facts(),
                stall_detected=True,
            )

        with patch("kryon.util.env.is_capable_model", return_value=True):
            capable = _build()
        with patch("kryon.util.env.is_capable_model", return_value=False):
            regime4b = _build()

        assert "planner repeating, facts flat" in capable
        assert "Letter-for-letter" not in capable
        assert "verbatim" not in capable
        # 4B keeps the hard verbatim-copy order
        assert "Letter-for-letter" in regime4b

    def test_capable_premature_summary_offers_justified_exit(self):
        """Fix (extra): the premature-summary block for a capable model keeps the
        brake but offers a justified-exit path instead of an absolute NO TERMINES."""

        def _build():
            return _build_reflection_prompt(
                turns_used=3,
                total_turns_cap=30,
                tool_history=[_rec("nmap", "x")],
                last_output_summary="",
                stuck_record=None,
                extracted_facts=_facts(),
                premature_summary_detected=True,
            )

        with patch("kryon.util.env.is_capable_model", return_value=True):
            capable = _build()
        with patch("kryon.util.env.is_capable_model", return_value=False):
            regime4b = _build()

        # capable keeps a brake but offers the justified-exit path
        assert "POSIBLEMENTE PREMATURO" in capable
        assert "justificá" in capable
        assert "3 hipótesis" not in capable  # no mandatory 3-hypothesis demand
        # 4B keeps the hard NO TERMINES + mandatory 3-hypothesis
        assert "NO TERMINES AÚN" in regime4b
        assert "3 hipótesis" in regime4b
