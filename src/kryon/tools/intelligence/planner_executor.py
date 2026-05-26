"""FASE 6 — function_tool that executes the planner's current
recommendation directly, bypassing the LLM step-selection bandwidth
bottleneck.

Why this exists: empirical evidence across THM Pyrat runs #11-#13
showed that even with the planner emitting a high-confidence
``OPERATOR DIRECTIVE`` block at position 1 of every reflection
(FASE 3 G4) AND base64-wrapped payloads to dodge shell-escape bugs
(FASE 4) AND a templates cheat-sheet (FASE 5), gpt-oss-20b would
commit to its first sub-strategy ("debug the simple nc syntax") and
refuse to copy the planner's escalated payload. The ceiling was
reasoning depth, not the prompt-shape work.

This module gives the model an out: it can invoke
``execute_planner_directive()`` and the planner runs *itself* —
the model only decides whether to delegate, not how to assemble
the exact command. That collapses the bandwidth requirement from
"copy this 300-character base64 shell pipeline correctly" to "trust
the planner: yes/no". gpt-oss-20b can handle the latter.

Banca-safe: the tool refuses to execute when no planner state is
attached (i.e. when called outside ``run_with_reflection``) and
when the planner emits no recommendation or one below the
confidence floor. The underlying subprocess execution goes through
the same ``run_command_async`` path as every other tool, so the
same guardrails (timeout, dangerous-pattern detection,
KRYON_GUARDRAILS) apply.
"""

from __future__ import annotations

import logging
import uuid

from kryon.sdk.agents import function_tool

logger = logging.getLogger(__name__)


@function_tool(strict_mode=False)
async def execute_planner_directive(
    target_host: str = "",
    confidence_floor: float = 0.85,
) -> str:
    """Execute the planner's current ``next_action`` recommendation
    directly, instead of having the model re-type the (often long /
    quoted / base64'd) invocation by hand.

    Reads the live ExtractedFacts + tool history from the per-task
    ``planner_runtime`` ContextVar (set by ``run_with_reflection``
    after each chunk), calls ``plan_next_action``, substitutes the
    ``<target>`` placeholder with the supplied or facts-derived host,
    and runs the command via the same ``run_command_async``
    subprocess machinery the agent uses for ``run_command``.

    Use this when the reflection block shows an OPERATOR DIRECTIVE
    you'd otherwise need to copy verbatim — especially when the
    directive is base64-wrapped or has nested shell quoting. The
    delegation is one decision: trust the planner this turn vs
    issue your own command via ``run_command``.

    Args:
        target_host: Override the ``<target>`` placeholder
            substitution. Empty = use the first host from
            ExtractedFacts.hosts (typically extracted from
            web_fetch_smart's final_url).
        confidence_floor: Refuse to execute when the planner's
            recommendation is below this confidence level. Default
            0.85 matches the OPERATOR DIRECTIVE threshold; pass a
            lower value if you trust the soft "Consider this"
            recommendations too.

    Returns:
        Output from the executed command, prefixed with the
        ``# PLANNER EXECUTED:`` marker line so downstream
        consumers (and the fact extractor) can tell it apart from
        a regular ``run_command`` invocation. When the planner has
        no recommendation for the current state, returns
        ``[NO DIRECTIVE]`` so the model can fall back to
        ``run_command`` on its own.

    Examples:
        execute_planner_directive()
        execute_planner_directive(target_host="10.67.190.8")
        execute_planner_directive(confidence_floor=0.7)
    """
    # Late imports to keep this module's import graph small —
    # planner / runtime + run_command_async pull in big chunks of
    # the SDK that we don't need just to register the tool.
    from kryon.intelligence.exploit_chain_planner import plan_next_action
    from kryon.intelligence.planner_runtime import get_current_state
    from kryon.tools.common import run_command_async as _run_cmd_async

    state = get_current_state()
    if state is None:
        return (
            "[NO RUNTIME] execute_planner_directive was called outside "
            "a reflective_runner context. No live facts / history "
            "snapshot to plan from. Use run_command with your own "
            "command instead."
        )

    rec = plan_next_action(
        state.facts,
        prior_tool_args=list(state.prior_tool_args),
        intent="",
    )
    if rec is None:
        return (
            "[NO DIRECTIVE] Planner has no recommendation for the "
            "current ExtractedFacts. Issue your own command via "
            "run_command, or wait for more intel before retrying."
        )

    if rec.confidence < confidence_floor:
        return (
            f"[LOW CONFIDENCE] Planner recommendation is at "
            f"confidence={rec.confidence:.2f}, below the floor "
            f"({confidence_floor:.2f}). Recommendation would be: "
            f"{rec.tool}({rec.args[:200]}...). Use run_command "
            "explicitly if you want to run it anyway."
        )

    # Substitute the ``<target>`` placeholder with the most concrete
    # host we know: caller-supplied first, then ExtractedFacts.hosts[0].
    args = rec.args
    if target_host:
        args = args.replace("<target>", target_host)
    elif state.facts.hosts:
        args = args.replace("<target>", state.facts.hosts[0])

    call_id = str(uuid.uuid4())[:8]
    try:
        raw_output = await _run_cmd_async(
            args,
            ctf=None,
            stdout=False,
            async_mode=False,
            session_id=None,
            timeout=120,
            stream=False,
            call_id=call_id,
            tool_name="execute_planner_directive",
        )
    except Exception as exc:  # noqa: BLE001 — surface as tool output
        logger.warning(
            "execute_planner_directive subprocess failed: %s", exc
        )
        return (
            f"# PLANNER EXECUTED (FAILED): {rec.tool}\n"
            f"# rationale: {rec.rationale}\n"
            f"# error: {type(exc).__name__}: {exc}"
        )

    output_str = str(raw_output) if raw_output is not None else ""
    return (
        f"✅ PLANNER EXECUTED SUCCESSFULLY (no tool error).\n"
        f"# Tool invoked: {rec.tool}\n"
        f"# Rationale: {rec.rationale}\n"
        f"# Confidence: {rec.confidence:.2f}\n"
        f"# ──────── TARGET RESPONSE BEGINS ────────\n"
        f"# (Anything below this line is OUTPUT FROM THE TARGET — \n"
        f"#  Python errors, shell errors, or any 'invalid syntax' / \n"
        f"#  'name X is not defined' / 'permission denied' messages \n"
        f"#  are the SERVER speaking back. They are NOT failures of \n"
        f"#  this tool. Treat them as facts and call \n"
        f"#  execute_planner_directive() again to advance the chain.)\n"
        f"────────────────────────────────────────\n"
        f"{output_str}"
    )


__all__ = ["execute_planner_directive"]
