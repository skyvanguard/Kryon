"""FASE 6 — execute_planner_directive function_tool unit tests.

The tool delegates execution to ``run_command_async`` via the
``kryon.tools.common`` dispatcher; tests stub that out to keep this
file pure-logic (no subprocess spawns). What we pin:

1. ``[NO RUNTIME]`` when the ContextVar is unset (tool called
   outside ``run_with_reflection``).
2. ``[NO DIRECTIVE]`` when the planner returns None.
3. ``[LOW CONFIDENCE]`` when below the floor (default 0.85).
4. The successful path: ``# PLANNER EXECUTED`` header + the underlying
   tool output, with ``<target>`` substituted from the host argument
   OR from ExtractedFacts.hosts.
5. Subprocess failures are caught and surfaced as ``(FAILED)`` rather
   than propagating an exception out of the tool.
"""

from __future__ import annotations

import pytest

from kryon.intelligence.exploit_chain_planner import NextActionRecommendation
from kryon.intelligence.fact_extractor import EMPTY, ExtractedFacts
from kryon.intelligence.planner_runtime import (
    clear_current_state,
    set_current_state,
)
from kryon.tools.intelligence.planner_executor import (
    _SQLMAP_ENUM_TIMEOUT_S,
    _resolve_directive_timeout,
    execute_planner_directive,
    execute_recommendation,
)


def _raw_fn(tool):
    """Resolve the underlying coroutine from the @function_tool wrapper.

    ``function_tool`` keeps the original callable under one of a few
    attribute names depending on SDK version. Walk the candidates and
    fall back to the wrapper itself if none match — at least the
    on_invoke_tool path is exercised in that case.
    """
    for attr in ("_raw_fn", "raw_fn", "fn", "__wrapped__"):
        candidate = getattr(tool, attr, None)
        if callable(candidate):
            return candidate
    return tool


@pytest.fixture(autouse=True)
def _reset_planner_runtime() -> None:
    """Each test starts with a clean ContextVar so previous tests
    don't bleed state."""
    clear_current_state()
    yield
    clear_current_state()


@pytest.mark.asyncio
async def test_returns_no_runtime_marker_when_state_unset() -> None:
    fn = _raw_fn(execute_planner_directive)
    out = await fn()
    assert "[NO RUNTIME]" in out


@pytest.mark.asyncio
async def test_returns_no_directive_when_planner_abstains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty facts → no rule fires → planner returns None → tool
    surfaces ``[NO DIRECTIVE]`` instead of executing anything."""
    set_current_state(EMPTY, ())
    fn = _raw_fn(execute_planner_directive)
    out = await fn()
    assert "[NO DIRECTIVE]" in out


@pytest.mark.asyncio
async def test_low_confidence_recommendation_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the planner's rec is below the floor, tool returns
    LOW CONFIDENCE without executing."""

    def _stub_plan(_facts, prior_tool_args=None, intent=""):
        return NextActionRecommendation(
            tool="run_command",
            args="nmap -sV target",
            rationale="example",
            confidence=0.6,  # below default 0.85
        )

    monkeypatch.setattr(
        "kryon.intelligence.exploit_chain_planner.plan_next_action",
        _stub_plan,
    )
    # set_current_state requires non-default facts so the planner
    # would have something to look at if it did fire.
    set_current_state(ExtractedFacts(users=("alice",)), ())
    fn = _raw_fn(execute_planner_directive)
    out = await fn()
    assert "[LOW CONFIDENCE]" in out
    # The rec should be echoed for transparency.
    assert "nmap" in out


@pytest.mark.asyncio
async def test_high_confidence_recommendation_executes_via_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path: planner returns a high-confidence rec, target
    placeholder gets substituted, subprocess returns stdout, tool
    prefixes ``# PLANNER EXECUTED:`` and surfaces the output."""

    def _stub_plan(_facts, prior_tool_args=None, intent=""):
        return NextActionRecommendation(
            tool="run_command",
            args="nc -q 1 -w 5 <target> 8000",
            rationale="basic connection hint resolved",
            confidence=0.92,
        )

    captured_command: dict[str, str] = {}

    async def _stub_subprocess(command, **_kwargs):
        captured_command["command"] = command
        return "OK — connected and closed"

    monkeypatch.setattr(
        "kryon.intelligence.exploit_chain_planner.plan_next_action",
        _stub_plan,
    )
    monkeypatch.setattr(
        "kryon.tools.common.run_command_async",
        _stub_subprocess,
    )

    set_current_state(
        ExtractedFacts(hosts=("10.0.0.42",), services=((8000, "http"),)),
        (),
    )

    fn = _raw_fn(execute_planner_directive)
    out = await fn()
    assert "PLANNER EXECUTED SUCCESSFULLY" in out
    assert "OK — connected and closed" in out
    # The host substitution must have replaced ``<target>`` with the
    # value from ExtractedFacts.hosts.
    assert "10.0.0.42" in captured_command["command"]
    assert "<target>" not in captured_command["command"]


@pytest.mark.asyncio
async def test_target_host_argument_overrides_facts_hosts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the caller passes target_host, that takes precedence over
    ExtractedFacts.hosts."""

    def _stub_plan(_facts, prior_tool_args=None, intent=""):
        return NextActionRecommendation(
            tool="run_command",
            args="nc -q 1 -w 5 <target> 8000",
            rationale="example",
            confidence=0.92,
        )

    captured_command: dict[str, str] = {}

    async def _stub_subprocess(command, **_kwargs):
        captured_command["command"] = command
        return ""

    monkeypatch.setattr(
        "kryon.intelligence.exploit_chain_planner.plan_next_action",
        _stub_plan,
    )
    monkeypatch.setattr(
        "kryon.tools.common.run_command_async",
        _stub_subprocess,
    )

    set_current_state(ExtractedFacts(hosts=("10.0.0.42",)), ())
    fn = _raw_fn(execute_planner_directive)
    await fn(target_host="172.16.5.10")
    # The override host wins.
    assert "172.16.5.10" in captured_command["command"]
    assert "10.0.0.42" not in captured_command["command"]


@pytest.mark.asyncio
async def test_subprocess_failure_is_caught_and_surfaced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If ``run_command_async`` raises, the tool must NOT propagate —
    it surfaces a ``(FAILED)`` marker so the model can react instead
    of seeing a 500."""

    def _stub_plan(_facts, prior_tool_args=None, intent=""):
        return NextActionRecommendation(
            tool="run_command",
            args="nc -q 1 -w 5 <target> 8000",
            rationale="example",
            confidence=0.92,
        )

    async def _stub_subprocess(_command, **_kwargs):
        raise RuntimeError("subprocess died")

    monkeypatch.setattr(
        "kryon.intelligence.exploit_chain_planner.plan_next_action",
        _stub_plan,
    )
    monkeypatch.setattr(
        "kryon.tools.common.run_command_async",
        _stub_subprocess,
    )

    set_current_state(ExtractedFacts(hosts=("1.2.3.4",)), ())
    fn = _raw_fn(execute_planner_directive)
    out = await fn()
    assert "(FAILED)" in out
    assert "subprocess died" in out


@pytest.mark.asyncio
async def test_lower_floor_argument_allows_softer_recommendations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Caller can pass ``confidence_floor=0.5`` to opt into low-
    confidence recommendations."""

    def _stub_plan(_facts, prior_tool_args=None, intent=""):
        return NextActionRecommendation(
            tool="run_command",
            args="nmap -sV <target>",
            rationale="example",
            confidence=0.6,
        )

    async def _stub_subprocess(_command, **_kwargs):
        return "executed"

    monkeypatch.setattr(
        "kryon.intelligence.exploit_chain_planner.plan_next_action",
        _stub_plan,
    )
    monkeypatch.setattr(
        "kryon.tools.common.run_command_async",
        _stub_subprocess,
    )

    set_current_state(ExtractedFacts(hosts=("1.2.3.4",)), ())
    fn = _raw_fn(execute_planner_directive)
    out = await fn(confidence_floor=0.5)
    assert "PLANNER EXECUTED SUCCESSFULLY" in out
    assert "executed" in out


class TestResolveDirectiveTimeout:
    """The sqlmap-aware timeout floor — a boolean/error-based dump of a creds
    table needs far more than the 120s default, and the reasoning-planner's own
    sqlmap recs never carry an explicit ``timeout_s`` (only rules do)."""

    def test_explicit_timeout_always_wins(self) -> None:
        # A rule that knows its cost set timeout_s — never override it, even for sqlmap.
        assert _resolve_directive_timeout(300, 'sqlmap -u "http://x/?q=1" --dump') == 300

    def test_explicit_timeout_wins_even_below_floor(self) -> None:
        assert _resolve_directive_timeout(45, "sqlmap --dump") == 45

    def test_sqlmap_dump_gets_generous_floor(self) -> None:
        out = _resolve_directive_timeout(None, 'sqlmap -u "http://x/?q=1" -T Users --dump')
        assert out == _SQLMAP_ENUM_TIMEOUT_S

    def test_sqlmap_enumeration_flags_all_get_floor(self) -> None:
        for flag in ("--dump", "--dbs", "--tables", "--columns", "--dump-all"):
            assert _resolve_directive_timeout(None, f"sqlmap -u x {flag}") == _SQLMAP_ENUM_TIMEOUT_S

    def test_sqlmap_detect_only_keeps_default(self) -> None:
        # A plain detection run (no enumeration/dump flag) is not the slow case.
        assert _resolve_directive_timeout(None, 'sqlmap -u "http://x/?q=1" --batch') == 120

    def test_non_sqlmap_command_keeps_default(self) -> None:
        assert _resolve_directive_timeout(None, "nmap -sV 10.0.0.1") == 120
        assert _resolve_directive_timeout(None, "curl -s http://x/?q=1 --dump-header -") == 120

    def test_case_insensitive(self) -> None:
        assert _resolve_directive_timeout(None, "SQLMAP -u X --DUMP") == _SQLMAP_ENUM_TIMEOUT_S


@pytest.mark.asyncio
async def test_sqlmap_dump_directive_passes_raised_timeout_to_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: a model-driven sqlmap ``--dump`` rec (no timeout_s) must reach
    the subprocess with the raised budget, not the 120s default that killed the
    live Juice Shop dump mid-extraction."""
    captured: dict[str, object] = {}

    async def _stub_subprocess(command, **kwargs):
        captured["command"] = command
        captured["timeout"] = kwargs.get("timeout")
        return "database dumped"

    monkeypatch.setattr("kryon.tools.common.run_command_async", _stub_subprocess)

    rec = NextActionRecommendation(
        tool="run_command",
        args='sqlmap -u "http://<target>:3000/rest/products/search?q=apple" -T Users -C email,password --dump --batch',
        rationale="confirmed SQLi → scoped creds dump",
        confidence=0.95,
    )
    out = await execute_recommendation(rec, target_host="juice_shop")
    assert "PLANNER EXECUTED SUCCESSFULLY" in out
    assert captured["timeout"] == _SQLMAP_ENUM_TIMEOUT_S
    assert "<target>" not in captured["command"]
    assert "juice_shop" in captured["command"]
