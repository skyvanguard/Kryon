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
from typing import TYPE_CHECKING

from kryon.sdk.agents import function_tool

if TYPE_CHECKING:
    from collections.abc import Sequence

    from kryon.intelligence.exploit_chain_planner import NextActionRecommendation

logger = logging.getLogger(__name__)


# A boolean/error-based SQLite dump of a credentials table routinely runs several
# minutes; the 120s default kills it mid-extraction. The reasoning-planner's own
# sqlmap recs never set ``timeout_s`` (only the deterministic rules do), so without
# this floor every model-driven ``--dump`` gets truncated (observed live vs Juice
# Shop: table enumeration completed, ``--dump`` timed out at 120s → no creds).
_SQLMAP_SLOW_FLAGS = ("--dump", "--dbs", "--tables", "--columns", "--dump-all")
_SQLMAP_ENUM_TIMEOUT_S = 600


def _resolve_directive_timeout(rec_timeout: int | None, args: str) -> int:
    """Effective subprocess budget for a planner directive.

    An explicit ``rec.timeout_s`` always wins (rules that know their own cost set it).
    Otherwise a slow sqlmap enumeration/dump gets a generous floor so it isn't killed
    mid-extraction; everything else keeps the conservative 120s default.
    """
    if rec_timeout is not None:
        return rec_timeout
    low = args.lower()
    if "sqlmap" in low and any(flag in low for flag in _SQLMAP_SLOW_FLAGS):
        return _SQLMAP_ENUM_TIMEOUT_S
    return 120


async def execute_recommendation(
    rec: NextActionRecommendation,
    *,
    target_host: str = "",
    facts_hosts: Sequence[str] = (),
) -> str:
    """Execute a single planner recommendation: substitute ``<target>``, run via the
    same ``run_command_async`` path as ``run_command``, and format the result with the
    ``✅ PLANNER EXECUTED`` marker. Shared by the ``execute_planner_directive`` tool (which
    resolves ``rec`` from the ContextVar) AND the reflective-runner's deterministic autoexec
    (which passes the ``rec`` it already computed, plus the concrete host, so it never depends
    on the ContextVar's async-context propagation or a populated ``facts.hosts``).
    """
    from kryon.intelligence.planner_runtime import record_planner_subcall
    from kryon.tools.common import run_command_async as _run_cmd_async

    args = rec.args
    if target_host:
        args = args.replace("<target>", target_host)
    elif facts_hosts:
        args = args.replace("<target>", facts_hosts[0])

    resolved_timeout = _resolve_directive_timeout(getattr(rec, "timeout_s", None), args)

    call_id = str(uuid.uuid4())[:8]
    try:
        record_planner_subcall(args)
    except Exception as exc:  # noqa: BLE001 — never let logging break the run
        logger.debug("record_planner_subcall failed: %s", exc)
    try:
        raw_output = await _run_cmd_async(
            args,
            ctf=None,
            stdout=False,
            async_mode=False,
            session_id=None,
            # Slow-but-decisive directives (a wpscan rockyou brute clocks ~114s) carry their own budget;
            # the default 120s killed them just before the crack landed in the autonomous run.
            timeout=resolved_timeout,
            stream=False,
            call_id=call_id,
            tool_name="execute_planner_directive",
        )
    except Exception as exc:  # noqa: BLE001 — surface as tool output
        logger.warning("execute_planner_directive subprocess failed: %s", exc)
        return (
            f"# PLANNER EXECUTED (FAILED): {rec.tool}\n"
            f"# rationale: {rec.rationale}\n"
            f"# error: {type(exc).__name__}: {exc}"
        )

    output_str = str(raw_output) if raw_output is not None else ""

    # Extract facts from THIS directive's own output and stash them so the next directive of the same chunk
    # can plan on them — state.facts only refreshes at the chunk boundary, so e.g. wpscan's cracked cred
    # (in this output) would otherwise be invisible to wp_webshell until the next chunk. Best-effort.
    try:
        from kryon.intelligence.fact_extractor import extract_facts
        from kryon.intelligence.planner_runtime import record_chunk_facts

        record_chunk_facts(extract_facts(args, output_str))
    except Exception as exc:  # noqa: BLE001 — fact accumulation must never break the run
        logger.debug("record_chunk_facts failed: %s", exc)

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
    # planner / runtime pull in big chunks of the SDK that we don't
    # need just to register the tool.
    from kryon.intelligence.exploit_chain_planner import plan_next_action
    from kryon.intelligence.planner_runtime import (
        get_chunk_facts,
        get_current_state,
        get_planner_intent,
        peek_planner_subcalls,
    )

    state = get_current_state()
    if state is None:
        return (
            "[NO RUNTIME] execute_planner_directive was called outside "
            "a reflective_runner context. No live facts / history "
            "snapshot to plan from. Use run_command with your own "
            "command instead."
        )

    # state.prior_tool_args is a per-CHUNK snapshot; the LLM calls this tool several times per chunk and
    # the sub-calls only fold into that snapshot at the next chunk boundary. Add the sub-calls already made
    # THIS chunk (peek, no clear) so each directive sees the prior ones and the planner advances instead of
    # re-emitting the same rec until the StuckDetector intervenes (the planner-loop seen live on Internal).
    rec = plan_next_action(
        state.facts.merge(get_chunk_facts()),
        prior_tool_args=list(state.prior_tool_args) + peek_planner_subcalls(),
        intent=get_planner_intent(),
    )
    if rec is None:
        return (
            "[NO DIRECTIVE] Planner has no recommendation for the "
            "current ExtractedFacts. Issue your own command via "
            "run_command, or wait for more intel before retrying."
        )

    if rec.confidence < confidence_floor:
        # Record the rejected directive so plan_next_action's dedup guard skips it next call instead of
        # re-emitting the identical low-confidence rec forever (the jwt_forge loop on THM Internal: a rec
        # below the floor is never run, so without this it never lands in prior_args and the planner returns
        # it again every turn until the StuckDetector fires).
        from kryon.intelligence.planner_runtime import record_planner_subcall

        try:
            record_planner_subcall(rec.args)
        except Exception as exc:  # noqa: BLE001
            logger.debug("record_planner_subcall (low-conf) failed: %s", exc)
        return (
            f"[LOW CONFIDENCE] Planner recommendation is at "
            f"confidence={rec.confidence:.2f}, below the floor "
            f"({confidence_floor:.2f}). Recommendation would be: "
            f"{rec.tool}({rec.args[:200]}...). Use run_command "
            "explicitly if you want to run it anyway."
        )

    # FASE 11.M — recording the inner args BEFORE running (inside
    # execute_recommendation) means rules that check ``_was_invoked``
    # in subsequent reflection turns see the directive even if the
    # subprocess fails or hangs. Substitute ``<target>`` with the most
    # concrete host we know: caller-supplied first, then facts.hosts[0].
    return await execute_recommendation(rec, target_host=target_host, facts_hosts=state.facts.hosts)


__all__ = ["execute_planner_directive", "execute_recommendation"]
