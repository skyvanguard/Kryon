"""FASE 11.B — Anti-premature-summary detector tests.

Pyrat bench B (kryon-qwen3-8b vs kryon-gpt-oss, 2026-05-26) showed
qwen3-8b emitting "📌 Resumen Ejecutivo" after only 3 tool calls and
without ever confirming foothold (no creds, no hashes, no shell prompt).
This is the failure mode that `_detect_premature_summary` is built to
catch: the model gives up too early on ambiguous tool outputs.

The detector + the corresponding reflection block (PREMATURE SUMMARY
DETECTED) work the same way the FASE 4 stall detector does: pure
function over (chunk_text, tool_calls_in_chunk, has_foothold) → bool,
integration in run_with_reflection injects an imperative
"NO termines aún" block into the next reflection turn.

Foothold definition (intentionally narrow):
  - creds: at least one (user, password) pair confirmed
  - hashes: at least one extracted hash (NTLM, krb5, etc.)
  - hints contain shell-prompt evidence: ``uid=`` ``gid=`` ``root@``
    ``$ `` (bash prompt) ``# `` (root prompt) ``C:\\`` (Windows shell)

Knowing usernames or services alone is NOT foothold — that's recon.
The whole point of the active-pentest profile is that recon doesn't
justify ending the run.
"""

from __future__ import annotations

import pytest

from kryon.cli.reflective_runner import (
    _build_reflection_prompt,
    _detect_premature_summary,
    _has_foothold,
)
from kryon.intelligence.fact_extractor import ExtractedFacts

# ---------------------------------------------------------------------------
# _detect_premature_summary — core detection
# ---------------------------------------------------------------------------


def test_detects_resumen_ejecutivo_exact_pattern_from_bench_b() -> None:
    """The exact phrase qwen3-8b emitted in Pyrat bench B."""
    chunk = (
        "Wait, maybe the server is configured to only accept...\n"
        "# 📌 Resumen Ejecutivo\n"
        "1. CWE-319 (HIGH): Servicio HTTP sin TLS\n"
        "2. CWE-200 (MEDIUM): Information disclosure\n"
    )
    assert (
        _detect_premature_summary(
            chunk,
            tool_calls_in_chunk=2,
            has_foothold=False,
        )
        is True
    )


def test_detects_resumen_de_la_investigacion() -> None:
    """Another shape observed in older runs."""
    chunk = "═══ Resumen de la investigación ═══\nFindings: ..."
    assert (
        _detect_premature_summary(
            chunk,
            tool_calls_in_chunk=2,
            has_foothold=False,
        )
        is True
    )


def test_detects_executive_summary_english() -> None:
    """English-mode runs (some skills are EN-only) — must catch both
    Spanish and English markers."""
    chunk = "## Executive Summary\n\nIdentified 2 medium findings..."
    assert (
        _detect_premature_summary(
            chunk,
            tool_calls_in_chunk=2,
            has_foothold=False,
        )
        is True
    )


def test_detects_hallazgos_marker() -> None:
    chunk = "📋 Hallazgos\n- CWE-200..."
    assert (
        _detect_premature_summary(
            chunk,
            tool_calls_in_chunk=2,
            has_foothold=False,
        )
        is True
    )


def test_detects_conclusion_marker() -> None:
    chunk = "## Conclusión\n\nEl target no presenta vulnerabilidades..."
    assert (
        _detect_premature_summary(
            chunk,
            tool_calls_in_chunk=2,
            has_foothold=False,
        )
        is True
    )


def test_no_summary_in_text_returns_false() -> None:
    """Plain reasoning text with no summary markers → not premature."""
    chunk = "We're still enumerating the target. Let me try a different endpoint to see if there's a path traversal."
    assert (
        _detect_premature_summary(
            chunk,
            tool_calls_in_chunk=2,
            has_foothold=False,
        )
        is False
    )


def test_empty_chunk_returns_false() -> None:
    assert (
        _detect_premature_summary(
            "",
            tool_calls_in_chunk=0,
            has_foothold=False,
        )
        is False
    )


def test_high_tool_call_count_is_legitimate_summary() -> None:
    """Even with the summary marker, ≥3 tool calls in the chunk means
    the model genuinely explored before summarizing. Not premature."""
    chunk = "📌 Resumen Ejecutivo\n1. CWE-200..."
    assert (
        _detect_premature_summary(
            chunk,
            tool_calls_in_chunk=5,
            has_foothold=False,
        )
        is False
    )


def test_foothold_confirmed_makes_summary_legitimate() -> None:
    """If we DO have creds/hashes/shell evidence, the summary is the
    correct outcome — don't false-positive."""
    chunk = "📌 Resumen Ejecutivo\n1. RCE confirmed via..."
    assert (
        _detect_premature_summary(
            chunk,
            tool_calls_in_chunk=2,
            has_foothold=True,
        )
        is False
    )


def test_custom_threshold_overrides_default() -> None:
    """Operator can tighten or loosen the threshold for specific
    skills (e.g. recon-only skills want a lower threshold)."""
    chunk = "📌 Resumen Ejecutivo\nFindings..."
    # Default threshold=3 → would fire at 2 calls
    assert (
        _detect_premature_summary(
            chunk,
            tool_calls_in_chunk=2,
            has_foothold=False,
        )
        is True
    )
    # Bump threshold to 1 → 2 calls now legitimate
    assert (
        _detect_premature_summary(
            chunk,
            tool_calls_in_chunk=2,
            has_foothold=False,
            threshold_tool_calls=1,
        )
        is False
    )


def test_summary_marker_in_thinking_block_still_counts() -> None:
    """Some models emit the summary inside their <think> reasoning
    before it lands in the final channel. The detector operates on the
    full chunk text so it catches both placements."""
    chunk = "<think>\nMaybe I should just wrap this up — # 📌 Resumen Ejecutivo\n</think>\nOK let me think more..."
    assert (
        _detect_premature_summary(
            chunk,
            tool_calls_in_chunk=1,
            has_foothold=False,
        )
        is True
    )


def test_summary_threshold_boundary_at_exactly_threshold() -> None:
    """Exactly equal to threshold (3 tool calls) → legitimate.
    Below (2) → premature. Boundary test."""
    chunk = "📌 Resumen Ejecutivo"
    assert (
        _detect_premature_summary(
            chunk,
            tool_calls_in_chunk=3,
            has_foothold=False,
        )
        is False
    )
    assert (
        _detect_premature_summary(
            chunk,
            tool_calls_in_chunk=2,
            has_foothold=False,
        )
        is True
    )


# ---------------------------------------------------------------------------
# _has_foothold — foothold confirmation
# ---------------------------------------------------------------------------


def test_has_foothold_creds_present() -> None:
    facts = ExtractedFacts(creds=(("alice", "hunter2"),))
    assert _has_foothold(facts) is True


def test_has_foothold_hashes_present() -> None:
    facts = ExtractedFacts(hashes=("$krb5asrep$23$alice@CORP:abc...",))
    assert _has_foothold(facts) is True


def test_has_foothold_uid_in_hints() -> None:
    """The classic ``uid=33(www-data) gid=33`` from a confirmed RCE."""
    facts = ExtractedFacts(hints=("uid=33(www-data) gid=33(www-data)",))
    assert _has_foothold(facts) is True


def test_has_foothold_root_uid_in_hints() -> None:
    facts = ExtractedFacts(hints=("uid=0(root) gid=0(root) groups=0(root)",))
    assert _has_foothold(facts) is True


def test_has_foothold_root_at_host_prompt() -> None:
    facts = ExtractedFacts(hints=("root@ubuntu:/# ",))
    assert _has_foothold(facts) is True


def test_has_foothold_admin_in_windows_prompt() -> None:
    facts = ExtractedFacts(hints=("administrator@TARGET-PC C:\\Windows>",))
    assert _has_foothold(facts) is True


def test_has_foothold_kryon_probe_echo_marker() -> None:
    """FASE 11.J — when the planner's foothold-confirm directive
    succeeds, the server echoes ``kryon-probe`` back through the
    socket. That IS foothold (remote end executes our code) — same
    class of control as a shell prompt. Pyrat bench 7 (2026-05-26)
    proved the model goes on to invoke ``os.system("id")`` over the
    same socket immediately after."""
    facts = ExtractedFacts(hints=("kryon-probe",))
    assert _has_foothold(facts) is True


def test_has_foothold_kryon_probe_in_longer_hint() -> None:
    """The marker must be detected even when wrapped in surrounding
    text from the model's narration."""
    facts = ExtractedFacts(
        hints=("the server echoed kryon-probe back, confirming repl",),
    )
    assert _has_foothold(facts) is True


def test_no_foothold_when_only_users_known() -> None:
    """Knowing usernames is recon, not foothold."""
    facts = ExtractedFacts(users=("alice", "bob"))
    assert _has_foothold(facts) is False


def test_no_foothold_when_only_services_known() -> None:
    """Port enumeration alone is recon."""
    facts = ExtractedFacts(services=((22, "ssh"), (80, "http")))
    assert _has_foothold(facts) is False


def test_no_foothold_when_only_domains_known() -> None:
    facts = ExtractedFacts(domains=("corp.local",))
    assert _has_foothold(facts) is False


def test_no_foothold_with_unrelated_hints() -> None:
    """Hints like 'try a basic connection' or 'invalid syntax' are
    classifier signals, not foothold evidence."""
    facts = ExtractedFacts(
        hints=("invalid syntax", "try a more basic connection"),
    )
    assert _has_foothold(facts) is False


def test_has_foothold_empty_facts() -> None:
    assert _has_foothold(ExtractedFacts()) is False


# ---------------------------------------------------------------------------
# _build_reflection_prompt integration
# ---------------------------------------------------------------------------


def test_reflection_prompt_includes_premature_summary_block_when_detected() -> None:
    """When the detector fires, the reflection prompt MUST include a
    hard imperative block that instructs the model to abandon the
    summary and try 3 hypotheses instead."""
    prompt = _build_reflection_prompt(
        turns_used=3,
        total_turns_cap=30,
        tool_history=[],
        last_output_summary="",
        stuck_record=None,
        degen_pattern=None,
        extracted_facts=None,
        next_action=None,
        premature_summary_detected=True,
    )
    assert "PREMATURE SUMMARY" in prompt
    assert "NO termines" in prompt or "NO TERMINES" in prompt


def test_reflection_prompt_omits_premature_block_when_not_detected() -> None:
    """Default path: no detector firing → no premature block in the
    reflection prompt (don't pollute with irrelevant headers)."""
    prompt = _build_reflection_prompt(
        turns_used=4,
        total_turns_cap=30,
        tool_history=[],
        last_output_summary="",
        stuck_record=None,
        degen_pattern=None,
        extracted_facts=None,
        next_action=None,
        premature_summary_detected=False,
    )
    assert "PREMATURE SUMMARY" not in prompt


def test_premature_block_demands_three_hypotheses() -> None:
    """The block must require the model to generate 3 hypotheses
    before considering ending the run — this is the structural fix
    that turns 'give up' into 'explore alternatives'."""
    prompt = _build_reflection_prompt(
        turns_used=3,
        total_turns_cap=30,
        tool_history=[],
        last_output_summary="",
        stuck_record=None,
        degen_pattern=None,
        extracted_facts=None,
        next_action=None,
        premature_summary_detected=True,
    )
    # The block must reference "3 hipótesis" or "tres hipótesis" so
    # the model has explicit structural guidance, not just "try
    # harder".
    assert "3 hipótesis" in prompt.lower() or "tres hipótesis" in prompt.lower()


def test_premature_block_appears_above_facts_block() -> None:
    """Ordering invariant: premature-summary directive must be high
    in the prompt (above facts) because it's the controlling signal
    — if the model just summarized prematurely, it's NOT reading the
    facts at the bottom of the prompt anyway."""
    facts = ExtractedFacts(users=("alice",))
    prompt = _build_reflection_prompt(
        turns_used=3,
        total_turns_cap=30,
        tool_history=[],
        last_output_summary="",
        stuck_record=None,
        degen_pattern=None,
        extracted_facts=facts,
        next_action=None,
        premature_summary_detected=True,
    )
    premature_idx = prompt.index("PREMATURE SUMMARY")
    facts_idx = prompt.index("Facts extracted so far")
    assert premature_idx < facts_idx


# ---------------------------------------------------------------------------
# FASE 11.E — evaluate_final_for_premature
# ---------------------------------------------------------------------------
#
# Gap discovered in Pyrat bench (2026-05-26): the FASE 11.B detector fires
# only during reflection cadence (between chunks). When the agent emits a
# summary as ``final_output`` (agent finished), the existing code path
# returns the result immediately — the detector never runs. The model can
# therefore bypass the safeguard by labeling its premature summary as the
# final answer instead of intermediate reasoning.
#
# Fix: ``_evaluate_final_for_premature(text, ...)`` is the gate that runs
# in the agent-finished path. Same predicate logic as the intermediate
# detector, plus a ``rejection_count`` parameter so the runner doesn't
# loop forever on a genuinely-stuck model.


def test_evaluate_final_premature_rejects_first_time() -> None:
    """A first-attempt premature final must be rejected so the runner
    can inject reflection + continue the loop instead of returning."""
    from kryon.cli.reflective_runner import _evaluate_final_for_premature

    should_reject, msg = _evaluate_final_for_premature(
        "📌 Resumen Ejecutivo\n1. CWE-200 (HIGH)...",
        tool_calls_in_chunk=1,
        has_foothold=False,
        rejection_count=0,
    )
    assert should_reject is True
    assert msg  # non-empty rejection message
    assert "PREMATURE FINAL" in msg.upper()


def test_evaluate_final_allows_when_legitimate() -> None:
    """No summary marker → not premature → don't reject."""
    from kryon.cli.reflective_runner import _evaluate_final_for_premature

    should_reject, msg = _evaluate_final_for_premature(
        "The target is unreachable. All probes timed out.",
        tool_calls_in_chunk=1,
        has_foothold=False,
        rejection_count=0,
    )
    assert should_reject is False
    assert msg == ""


def test_evaluate_final_allows_when_foothold_present() -> None:
    """Summary AFTER foothold (creds/uid=/hash) is legitimate."""
    from kryon.cli.reflective_runner import _evaluate_final_for_premature

    should_reject, _ = _evaluate_final_for_premature(
        "📌 Resumen Ejecutivo\n1. RCE confirmed via cmd injection...",
        tool_calls_in_chunk=2,
        has_foothold=True,
        rejection_count=0,
    )
    assert should_reject is False


def test_evaluate_final_allows_when_enough_tool_calls() -> None:
    """≥3 tool calls in the final chunk means the model genuinely
    explored → summary legitimate even without foothold."""
    from kryon.cli.reflective_runner import _evaluate_final_for_premature

    should_reject, _ = _evaluate_final_for_premature(
        "📌 Resumen Ejecutivo\n1. Findings...",
        tool_calls_in_chunk=5,
        has_foothold=False,
        rejection_count=0,
    )
    assert should_reject is False


def test_evaluate_final_lets_through_after_max_rejections() -> None:
    """After max_rejections (default 2), the runner must let the
    summary through to avoid an infinite reject→retry→reject loop.
    A genuinely-stuck model would keep emitting summary; eventually
    the operator needs to see SOMETHING."""
    from kryon.cli.reflective_runner import _evaluate_final_for_premature

    # rejection_count == max → allow through
    should_reject, _ = _evaluate_final_for_premature(
        "📌 Resumen Ejecutivo\nFindings...",
        tool_calls_in_chunk=1,
        has_foothold=False,
        rejection_count=2,
        max_rejections=2,
    )
    assert should_reject is False


def test_evaluate_final_lets_through_after_custom_max() -> None:
    """Operator can tighten max_rejections for high-budget runs."""
    from kryon.cli.reflective_runner import _evaluate_final_for_premature

    should_reject, _ = _evaluate_final_for_premature(
        "📌 Resumen Ejecutivo\nFindings...",
        tool_calls_in_chunk=1,
        has_foothold=False,
        rejection_count=1,
        max_rejections=1,  # tighter cap
    )
    assert should_reject is False


def test_evaluate_final_rejects_until_max() -> None:
    """At rejection_count < max, keep rejecting. Boundary check."""
    from kryon.cli.reflective_runner import _evaluate_final_for_premature

    # rejection_count == 1, max == 2 → still reject
    should_reject, _ = _evaluate_final_for_premature(
        "📌 Resumen Ejecutivo\nFindings...",
        tool_calls_in_chunk=1,
        has_foothold=False,
        rejection_count=1,
        max_rejections=2,
    )
    assert should_reject is True


def test_evaluate_final_rejection_msg_includes_attempt_counter() -> None:
    """The rejection message must show ``intento N/MAX`` so the model
    sees how many chances are left — anchors the urgency."""
    from kryon.cli.reflective_runner import _evaluate_final_for_premature

    _, msg = _evaluate_final_for_premature(
        "📌 Resumen Ejecutivo\nFindings...",
        tool_calls_in_chunk=1,
        has_foothold=False,
        rejection_count=0,
        max_rejections=2,
    )
    assert "1/2" in msg or "intento 1" in msg.lower()


def test_evaluate_final_rejection_msg_demands_three_hypotheses() -> None:
    """Same structural demand as the intermediate FASE 11.B block —
    forces the model to generate alternatives, not just retry."""
    from kryon.cli.reflective_runner import _evaluate_final_for_premature

    _, msg = _evaluate_final_for_premature(
        "📌 Resumen Ejecutivo\nFindings...",
        tool_calls_in_chunk=1,
        has_foothold=False,
        rejection_count=0,
    )
    assert "3 hipótesis" in msg.lower() or "tres hipótesis" in msg.lower()


def test_count_real_tool_calls_excludes_planner_subcall() -> None:
    """FASE 11.N — planner_subcall synthetic records (created by the
    reflective runner from the executor's sub-call log) shouldn't
    count toward the ``tool_calls_in_chunk`` threshold. They represent
    work the planner did INSIDE the executor, not new model-issued
    exploration. Counting them inflates the count and lets the model
    emit summaries after fewer real probes than the operator
    intended."""
    from kryon.cli.reflective_runner import (
        _count_real_tool_calls,
        _ToolCallRecord,
    )

    records = [
        _ToolCallRecord(tool_name="web_fetch_smart", args_hash="a", args_preview="..."),
        _ToolCallRecord(tool_name="execute_planner_directive", args_hash="b", args_preview=""),
        _ToolCallRecord(tool_name="planner_subcall", args_hash="c", args_preview="gobuster ..."),
        _ToolCallRecord(tool_name="planner_subcall", args_hash="d", args_preview="gobuster ..."),
        _ToolCallRecord(tool_name="run_command", args_hash="e", args_preview="curl ..."),
    ]
    # 5 total records, 3 real (web_fetch + execute_planner_directive + run_command)
    assert _count_real_tool_calls(records) == 3


def test_count_real_tool_calls_empty_list() -> None:
    from kryon.cli.reflective_runner import _count_real_tool_calls

    assert _count_real_tool_calls([]) == 0


def test_count_real_tool_calls_all_synthetic() -> None:
    """Edge case: chunk where ONLY planner_subcall records exist
    (model invoked execute_planner_directive but no other tools).
    Real count should be 0 — those subcalls came from the planner,
    not from the model's own probes."""
    from kryon.cli.reflective_runner import (
        _count_real_tool_calls,
        _ToolCallRecord,
    )

    records = [
        _ToolCallRecord(tool_name="planner_subcall", args_hash="a", args_preview="x"),
        _ToolCallRecord(tool_name="planner_subcall", args_hash="b", args_preview="y"),
    ]
    assert _count_real_tool_calls(records) == 0


def test_resolve_threshold_recon_class_with_disallow_hints() -> None:
    """FASE 11.N — recon-class CTFs (web bruteforce / disallow path
    chain) need more tool calls than eval-class to chain through to
    foothold (gobuster → cascade → cred discovery → hydra → ssh).
    With ``disallow:`` hints present, the threshold goes from 3 to
    5 so cascade rules have room to land before a legit summary."""
    from kryon.cli.reflective_runner import _resolve_threshold_for_class

    facts = ExtractedFacts(hints=("disallow:/admin",))
    assert _resolve_threshold_for_class(facts) == 5


def test_resolve_threshold_eval_class_default() -> None:
    """No disallow hints (e.g. Pyrat REPL eval target) → keep the
    default threshold of 3."""
    from kryon.cli.reflective_runner import _resolve_threshold_for_class

    facts = ExtractedFacts(hints=("invalid syntax",))
    assert _resolve_threshold_for_class(facts) == 3


def test_resolve_threshold_empty_facts_keeps_default() -> None:
    from kryon.cli.reflective_runner import _resolve_threshold_for_class

    assert _resolve_threshold_for_class(ExtractedFacts()) == 3


def test_resolve_threshold_multiple_disallow_hints_recon_class() -> None:
    """Multiple disallow hints — still recon-class, threshold 5."""
    from kryon.cli.reflective_runner import _resolve_threshold_for_class

    facts = ExtractedFacts(
        hints=("disallow:/admin", "disallow:/secret", "invalid syntax"),
    )
    # Even with a mix of hints, the presence of disallow signals
    # recon-class behavior.
    assert _resolve_threshold_for_class(facts) == 5


def test_evaluate_final_empty_text_does_not_crash() -> None:
    """Defensive: empty / None final_output should return (False, '')
    without raising."""
    from kryon.cli.reflective_runner import _evaluate_final_for_premature

    should_reject, msg = _evaluate_final_for_premature(
        "",
        tool_calls_in_chunk=0,
        has_foothold=False,
        rejection_count=0,
    )
    assert should_reject is False
    assert msg == ""
