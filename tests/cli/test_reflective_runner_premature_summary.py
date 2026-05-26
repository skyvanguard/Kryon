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
    assert _detect_premature_summary(
        chunk,
        tool_calls_in_chunk=2,
        has_foothold=False,
    ) is True


def test_detects_resumen_de_la_investigacion() -> None:
    """Another shape observed in older runs."""
    chunk = "═══ Resumen de la investigación ═══\nFindings: ..."
    assert _detect_premature_summary(
        chunk,
        tool_calls_in_chunk=2,
        has_foothold=False,
    ) is True


def test_detects_executive_summary_english() -> None:
    """English-mode runs (some skills are EN-only) — must catch both
    Spanish and English markers."""
    chunk = "## Executive Summary\n\nIdentified 2 medium findings..."
    assert _detect_premature_summary(
        chunk,
        tool_calls_in_chunk=2,
        has_foothold=False,
    ) is True


def test_detects_hallazgos_marker() -> None:
    chunk = "📋 Hallazgos\n- CWE-200..."
    assert _detect_premature_summary(
        chunk,
        tool_calls_in_chunk=2,
        has_foothold=False,
    ) is True


def test_detects_conclusion_marker() -> None:
    chunk = "## Conclusión\n\nEl target no presenta vulnerabilidades..."
    assert _detect_premature_summary(
        chunk,
        tool_calls_in_chunk=2,
        has_foothold=False,
    ) is True


def test_no_summary_in_text_returns_false() -> None:
    """Plain reasoning text with no summary markers → not premature."""
    chunk = (
        "We're still enumerating the target. Let me try a different "
        "endpoint to see if there's a path traversal."
    )
    assert _detect_premature_summary(
        chunk,
        tool_calls_in_chunk=2,
        has_foothold=False,
    ) is False


def test_empty_chunk_returns_false() -> None:
    assert _detect_premature_summary(
        "",
        tool_calls_in_chunk=0,
        has_foothold=False,
    ) is False


def test_high_tool_call_count_is_legitimate_summary() -> None:
    """Even with the summary marker, ≥3 tool calls in the chunk means
    the model genuinely explored before summarizing. Not premature."""
    chunk = "📌 Resumen Ejecutivo\n1. CWE-200..."
    assert _detect_premature_summary(
        chunk,
        tool_calls_in_chunk=5,
        has_foothold=False,
    ) is False


def test_foothold_confirmed_makes_summary_legitimate() -> None:
    """If we DO have creds/hashes/shell evidence, the summary is the
    correct outcome — don't false-positive."""
    chunk = "📌 Resumen Ejecutivo\n1. RCE confirmed via..."
    assert _detect_premature_summary(
        chunk,
        tool_calls_in_chunk=2,
        has_foothold=True,
    ) is False


def test_custom_threshold_overrides_default() -> None:
    """Operator can tighten or loosen the threshold for specific
    skills (e.g. recon-only skills want a lower threshold)."""
    chunk = "📌 Resumen Ejecutivo\nFindings..."
    # Default threshold=3 → would fire at 2 calls
    assert _detect_premature_summary(
        chunk,
        tool_calls_in_chunk=2,
        has_foothold=False,
    ) is True
    # Bump threshold to 1 → 2 calls now legitimate
    assert _detect_premature_summary(
        chunk,
        tool_calls_in_chunk=2,
        has_foothold=False,
        threshold_tool_calls=1,
    ) is False


def test_summary_marker_in_thinking_block_still_counts() -> None:
    """Some models emit the summary inside their <think> reasoning
    before it lands in the final channel. The detector operates on the
    full chunk text so it catches both placements."""
    chunk = (
        "<think>\n"
        "Maybe I should just wrap this up — # 📌 Resumen Ejecutivo\n"
        "</think>\n"
        "OK let me think more..."
    )
    assert _detect_premature_summary(
        chunk,
        tool_calls_in_chunk=1,
        has_foothold=False,
    ) is True


def test_summary_threshold_boundary_at_exactly_threshold() -> None:
    """Exactly equal to threshold (3 tool calls) → legitimate.
    Below (2) → premature. Boundary test."""
    chunk = "📌 Resumen Ejecutivo"
    assert _detect_premature_summary(
        chunk,
        tool_calls_in_chunk=3,
        has_foothold=False,
    ) is False
    assert _detect_premature_summary(
        chunk,
        tool_calls_in_chunk=2,
        has_foothold=False,
    ) is True


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
