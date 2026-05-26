"""F203.AX — Intra-turn degeneracy detector tests.

The turn-level ``_is_stuck`` only detects when consecutive ``tool_call``
records have identical (name, args_hash). gpt-oss-20b can degenerate
INSIDE a single reasoning block, repeating a 32+ word line 100+ times
without ever emitting another tool_call. ``_is_stuck`` never fires, the
chunk hits max_tokens, thousands of tokens wasted.

``_detect_intra_turn_degeneracy`` is the post-chunk safety net that
catches this. These tests pin its behavior against:

* a real degeneracy sample observed in the THM Operation Endgame run
  (the smbclient "-L? Already / Not" loop that motivated the fix),
* legitimate pentest narration that must NOT false-positive,
* legitimate enumeration output ("Found user X. Found user Y. ...")
  that also must NOT false-positive (each line shares a verb prefix
  but the n-gram changes per line),
* short inputs that don't have enough words for the window to apply.
"""

from __future__ import annotations

from collections import deque

from kryon.cli.reflective_runner import (
    _build_reflection_prompt,
    _chunk_text_from_capture,
    _detect_intra_turn_degeneracy,
    _extract_chunk_text,
    _extract_facts_from_chunk,
    _facts_signature,
    _is_stall,
    _recommendation_signature,
)
from kryon.intelligence.fact_extractor import ExtractedFacts


def test_detects_real_degeneracy_sample_from_endgame_run() -> None:
    """The smbclient loop observed in run #2 — should fire."""
    degen = (
        'Maybe use smbclient -L 10.64.151.155 -U "" -N -L? Not.\n'
        'Maybe use smbclient -L 10.64.151.155 -U "" -N -L? Already.\n'
        "Let us try smbclient -L 10.64.151.155 -U \"\" -N -L? Already.\n"
        'Maybe use smbclient -L 10.64.151.155 -U "" -N -L? Not.\n'
        "Let us try smbclient -L 10.64.151.155 -U \"\" -N -L? Already.\n"
        'Maybe use smbclient -L 10.64.151.155 -U "" -N -L? Not.\n'
        'Ok maybe use smbclient -L 10.64.151.155 -U "" -N -L? Already.\n'
        'Ok maybe use smbclient -L 10.64.151.155 -U "" -N -L? Not.\n'
    )
    pattern = _detect_intra_turn_degeneracy(degen)
    assert pattern is not None
    assert "smbclient" in pattern


def test_normal_pentest_narration_does_not_false_positive() -> None:
    """Free-form planning text with no tight repetition — must stay quiet."""
    narration = (
        "We need to perform blackbox pentest. We must use tools: nmap, "
        "smbclient, nxc, ldapsearch. First, check authorization. Assume "
        "we have it. Next step: enumerate SMB shares anonymously. We can "
        "use smbclient with -L flag and empty username for NULL session. "
        "After that, try ldapsearch with -x for simple bind, then RID "
        "brute via nxc. If we find users without preauth, asreproast with "
        "GetNPUsers. If we have creds, kerberoast with GetUserSPNs. "
        "Bloodhound for attack paths. Secretsdump if DA."
    )
    assert _detect_intra_turn_degeneracy(narration) is None


def test_legitimate_enumeration_output_does_not_false_positive() -> None:
    """Tool output that lists many similar entries — must stay quiet.

    Each line shares the "Found user X." prefix but the n-gram window
    (size 8) spans across lines and the username differs every time, so
    no 8-word window repeats min_repeats times.
    """
    enum = (
        "Found user Alice. Found user Bob. Found user Carol. Found user "
        "Dave. Found user Eve. Found user Frank. Found user Grace. Found "
        "user Henry. Found user Ian. Found user Jane. Found user Kate. "
        "Found user Liam."
    )
    assert _detect_intra_turn_degeneracy(enum) is None


def test_text_shorter_than_window_returns_none() -> None:
    """ngram_size * min_repeats = 32 words minimum; under that → None
    without scanning, by design."""
    assert _detect_intra_turn_degeneracy("only a handful of words here") is None


def test_empty_input_returns_none() -> None:
    assert _detect_intra_turn_degeneracy("") is None
    assert _detect_intra_turn_degeneracy(None) is None  # type: ignore[arg-type]


def test_threshold_just_below_min_repeats_does_not_fire() -> None:
    """Exactly 3 repeats of an 8-gram should NOT fire (default min=4)."""
    block = "the same exact phrase repeated three times here yes " * 3
    assert _detect_intra_turn_degeneracy(block) is None


def test_threshold_at_min_repeats_fires() -> None:
    """Exactly 4 repeats of an 8-gram SHOULD fire (default min=4)."""
    block = "the same exact phrase repeated four times here yes " * 4
    pattern = _detect_intra_turn_degeneracy(block)
    assert pattern is not None
    assert "same exact phrase" in pattern


def test_custom_threshold_overrides_default() -> None:
    """Caller can demand higher confidence with a stricter min_repeats."""
    block = "the same exact phrase repeated four times here yes " * 4
    # Default fires at 4 — bump min_repeats to 10 and it should go quiet.
    assert _detect_intra_turn_degeneracy(block, min_repeats=10) is None


def test_extract_chunk_text_handles_string_content() -> None:
    """raw_responses with simple string .message.content — common shape."""

    class _Msg:
        def __init__(self, content: str) -> None:
            self.content = content

    class _Resp:
        def __init__(self, content: str) -> None:
            self.message = _Msg(content)

    class _Result:
        raw_responses = [_Resp("first chunk"), _Resp("second chunk")]
        final_output = None

    out = _extract_chunk_text(_Result())
    assert "first chunk" in out
    assert "second chunk" in out


def test_extract_chunk_text_falls_back_to_final_output() -> None:
    """When raw_responses is empty/opaque, prefer final_output."""

    class _Result:
        raw_responses = []
        final_output = "summary text"

    assert "summary text" in _extract_chunk_text(_Result())


def test_extract_chunk_text_handles_structured_content() -> None:
    """Some SDK versions emit content as list[dict] with 'text' keys."""

    class _Msg:
        def __init__(self) -> None:
            self.content = [
                {"text": "structured part one"},
                {"text": "structured part two"},
            ]

    class _Resp:
        def __init__(self) -> None:
            self.message = _Msg()

    class _Result:
        raw_responses = [_Resp()]
        final_output = None

    out = _extract_chunk_text(_Result())
    assert "structured part one" in out
    assert "structured part two" in out


# ---------------------------------------------------------------------------
# FASE 1 (G1+G2) — _extract_facts_from_chunk + reflection prompt rendering
# ---------------------------------------------------------------------------


def test_extract_facts_from_chunk_handles_empty_string() -> None:
    facts = _extract_facts_from_chunk("")
    assert facts.is_empty()


def test_extract_facts_from_chunk_parses_ldapsearch_block() -> None:
    """A chunk with a real-shaped ldapsearch invocation marker should
    route the LDIF block to the ldapsearch parser and surface users +
    domain."""
    chunk = """\
We need to enumerate users now.

▸ run_command  ldapsearch -x -H ldap://10.64.170.128 -b dc=thm,dc=local
dn: CN=Administrator,CN=Users,DC=thm,DC=local
sAMAccountName: Administrator
userPrincipalName: administrator@thm.local

dn: CN=alice,CN=Users,DC=thm,DC=local
sAMAccountName: alice

dn:
defaultNamingContext: DC=thm,DC=local
"""
    facts = _extract_facts_from_chunk(chunk)
    assert "Administrator" in facts.users
    assert "alice" in facts.users
    assert "thm.local" in facts.domains


def test_extract_facts_from_chunk_merges_multiple_tool_blocks() -> None:
    """Multiple ▸-marked blocks in the same chunk should merge: nmap
    services + smbclient shares both visible after extraction."""
    chunk = """\
▸ nmap 10.0.0.1
PORT      STATE SERVICE
22/tcp    open  ssh
445/tcp   open  microsoft-ds

▸ run_command  smbclient -L //10.0.0.1 -N
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        IPC$            IPC       Remote IPC
"""
    facts = _extract_facts_from_chunk(chunk)
    ports = {p for p, _ in facts.services}
    assert {22, 445}.issubset(ports)
    assert "ADMIN$" in facts.shares
    assert "IPC$" in facts.shares


def test_extract_facts_from_chunk_picks_up_hint_phrases_from_reasoning() -> None:
    """CTF-style hint phrases that appear in the model's reasoning
    (not in a tool output block) should still surface via the
    whole-chunk generic pass."""
    chunk = (
        "The server keeps saying 'Try a more basic connection' on every "
        "endpoint we hit. Maybe try netcat raw?"
    )
    facts = _extract_facts_from_chunk(chunk)
    assert "try a more basic connection" in facts.hints


def test_reflection_prompt_includes_extracted_facts_block_when_present() -> None:
    facts = ExtractedFacts(
        users=("alice", "bob"),
        domains=("thm.local",),
        services=((445, "smb"),),
    )
    prompt = _build_reflection_prompt(
        turns_used=4,
        total_turns_cap=30,
        tool_history=[],
        last_output_summary="",
        stuck_record=None,
        degen_pattern=None,
        extracted_facts=facts,
    )
    assert "Facts extracted so far" in prompt
    assert "alice, bob" in prompt
    assert "thm.local" in prompt
    assert "445/smb" in prompt


def test_reflection_prompt_omits_facts_block_when_empty() -> None:
    """Empty / None ExtractedFacts → no facts block (don't pollute the
    prompt with empty headers)."""
    prompt = _build_reflection_prompt(
        turns_used=4,
        total_turns_cap=30,
        tool_history=[],
        last_output_summary="",
        stuck_record=None,
        degen_pattern=None,
        extracted_facts=ExtractedFacts(),
    )
    assert "Facts extracted so far" not in prompt


def test_reflection_prompt_facts_block_appears_above_recent_tools() -> None:
    """Ordering invariant: facts block must come BEFORE the 'Tools
    recientes usadas' line, so the model reads the structured intel
    before any reasoning about tool history."""
    facts = ExtractedFacts(users=("alice",))
    prompt = _build_reflection_prompt(
        turns_used=4,
        total_turns_cap=30,
        tool_history=[],
        last_output_summary="",
        stuck_record=None,
        degen_pattern=None,
        extracted_facts=facts,
    )
    facts_idx = prompt.index("Facts extracted so far")
    tools_idx = prompt.index("Tools recientes usadas")
    assert facts_idx < tools_idx


# ---------------------------------------------------------------------------
# FASE 2 (G3) — exploit_chain_planner integration in reflection prompt
# ---------------------------------------------------------------------------


def test_reflection_prompt_includes_high_confidence_directive_block() -> None:
    """A high-confidence NextActionRecommendation surfaces as an
    ``OPERATOR DIRECTIVE`` block (G4 rephrasing). The exact tool
    invocation must be present so the model can copy it."""
    from kryon.intelligence.exploit_chain_planner import NextActionRecommendation

    rec = NextActionRecommendation(
        tool="run_command",
        args="hashcat -m 18200 hashes.txt rockyou.txt",
        rationale="hashes present, no creds yet",
        confidence=0.9,
    )
    prompt = _build_reflection_prompt(
        turns_used=4,
        total_turns_cap=30,
        tool_history=[],
        last_output_summary="",
        stuck_record=None,
        degen_pattern=None,
        extracted_facts=None,
        next_action=rec,
    )
    assert "OPERATOR DIRECTIVE" in prompt
    assert "hashcat -m 18200" in prompt


def test_reflection_prompt_includes_low_confidence_soft_block() -> None:
    """Low-confidence NextActionRecommendation surfaces with softer
    ``Next action recommendation`` phrasing — not as a hard directive."""
    from kryon.intelligence.exploit_chain_planner import NextActionRecommendation

    rec = NextActionRecommendation(
        tool="run_command",
        args="nmap -A target",
        rationale="example",
        confidence=0.6,
    )
    prompt = _build_reflection_prompt(
        turns_used=4,
        total_turns_cap=30,
        tool_history=[],
        last_output_summary="",
        stuck_record=None,
        degen_pattern=None,
        extracted_facts=None,
        next_action=rec,
    )
    assert "Next action recommendation" in prompt
    assert "OPERATOR DIRECTIVE" not in prompt
    assert "nmap -A target" in prompt


def test_reflection_prompt_omits_next_action_when_planner_returned_none() -> None:
    prompt = _build_reflection_prompt(
        turns_used=4,
        total_turns_cap=30,
        tool_history=[],
        last_output_summary="",
        stuck_record=None,
        degen_pattern=None,
        extracted_facts=None,
        next_action=None,
    )
    assert "Next action recommendation" not in prompt


# ---------------------------------------------------------------------------
# B9 (FASE 2) — MaxTurns-path also extracts facts + plans next action
# ---------------------------------------------------------------------------


def test_chunk_text_from_capture_reconstructs_text_from_hooks() -> None:
    """The capture-based reconstruction must produce text that the same
    ``_extract_facts_from_chunk`` splitter can parse — same ``▸`` marker
    shape that the normal renderer uses."""

    class _StubHooks:
        captured_items = [
            {
                "type": "tool_call",
                "tool": "run_command",
                "output_preview": (
                    "dn: CN=alice,CN=Users,DC=corp,DC=local\n"
                    "sAMAccountName: alice\n"
                    "defaultNamingContext: DC=corp,DC=local"
                ),
            },
            {
                "type": "tool_call",
                "tool": "run_command",
                "output_preview": (
                    "        Sharename       Type      Comment\n"
                    "        ---------       ----      -------\n"
                    "        ADMIN$          Disk      Remote Admin"
                ),
            },
            {"type": "agent_end", "output_preview": "summary"},  # filtered out
        ]

    reconstructed = _chunk_text_from_capture(_StubHooks())
    # Must contain the ▸ marker shape so the splitter routes blocks.
    assert "▸ run_command" in reconstructed
    # And the same splitter must extract the user + share from the
    # reconstructed text.
    facts = _extract_facts_from_chunk(reconstructed)
    assert "alice" in facts.users
    assert "corp.local" in facts.domains
    assert "ADMIN$" in facts.shares


def test_chunk_text_from_capture_handles_empty_hooks() -> None:
    class _Empty:
        captured_items = []

    assert _chunk_text_from_capture(_Empty()) == ""


def test_chunk_text_from_capture_skips_items_without_output() -> None:
    """tool_start with no output yet → don't emit empty ▸ blocks that
    would dilute the dispatch."""

    class _Hooks:
        captured_items = [
            {"type": "tool_call", "tool": "run_command", "output_preview": ""},
            {
                "type": "tool_call",
                "tool": "run_command",
                "output_preview": "actual output here",
            },
        ]

    reconstructed = _chunk_text_from_capture(_Hooks())
    # Exactly one ▸ marker (the one with output).
    assert reconstructed.count("▸ run_command") == 1
    assert "actual output here" in reconstructed


def test_reflection_prompt_low_confidence_next_action_appears_below_facts() -> None:
    """Ordering invariant for LOW-confidence: facts (justification)
    above recommendation (softer suggestion). Lets the model weigh
    evidence before considering the soft suggestion."""
    from kryon.intelligence.exploit_chain_planner import NextActionRecommendation

    facts = ExtractedFacts(users=("alice",), domains=("thm.local",))
    rec = NextActionRecommendation(
        tool="run_command",
        args="GetNPUsers.py -no-pass thm.local/",
        rationale="users and domain present",
        confidence=0.6,  # LOW
    )
    prompt = _build_reflection_prompt(
        turns_used=4,
        total_turns_cap=30,
        tool_history=[],
        last_output_summary="",
        stuck_record=None,
        degen_pattern=None,
        extracted_facts=facts,
        next_action=rec,
    )
    facts_idx = prompt.index("Facts extracted so far")
    rec_idx = prompt.index("Next action recommendation")
    assert facts_idx < rec_idx


# ---------------------------------------------------------------------------
# G4 (FASE 3) — high-confidence planner directive goes to position 1
# ---------------------------------------------------------------------------


def test_reflection_prompt_high_confidence_directive_appears_above_everything() -> None:
    """G4 ordering fix: HIGH-confidence (>=0.85) ``OPERATOR DIRECTIVE``
    block must precede every other section — facts, degen, stuck, the
    reflection title. Buried below other content the model ignored it
    in the Pyrat run #10 transcript."""
    from kryon.intelligence.exploit_chain_planner import NextActionRecommendation

    facts = ExtractedFacts(users=("alice",), domains=("thm.local",))
    rec = NextActionRecommendation(
        tool="run_command",
        args="GetNPUsers.py -no-pass thm.local/",
        rationale="users + domain",
        confidence=0.9,  # HIGH
    )
    prompt = _build_reflection_prompt(
        turns_used=4,
        total_turns_cap=30,
        tool_history=[],
        last_output_summary="",
        stuck_record=None,
        degen_pattern=None,
        extracted_facts=facts,
        next_action=rec,
    )
    directive_idx = prompt.index("OPERATOR DIRECTIVE")
    facts_idx = prompt.index("Facts extracted so far")
    tools_idx = prompt.index("Tools recientes usadas")
    # The directive must be ABOVE facts AND above the recent-tools line.
    assert directive_idx < facts_idx
    assert directive_idx < tools_idx


# ---------------------------------------------------------------------------
# G7 (FASE 4) — stall detector
# ---------------------------------------------------------------------------


def test_facts_signature_changes_when_users_grow() -> None:
    a = ExtractedFacts(users=("alice",))
    b = ExtractedFacts(users=("alice", "bob"))
    assert _facts_signature(a) != _facts_signature(b)


def test_facts_signature_unchanged_when_only_hints_added() -> None:
    """Hints/versions don't count as progress — the signature pins on
    high-value fields only (users, hashes, creds, shares, domains)."""
    a = ExtractedFacts(users=("alice",))
    b = ExtractedFacts(users=("alice",), hints=("new hint",))
    assert _facts_signature(a) == _facts_signature(b)


def test_facts_signature_none_is_empty_string() -> None:
    assert _facts_signature(None) == ""


def test_recommendation_signature_truncates_long_args() -> None:
    from kryon.intelligence.exploit_chain_planner import NextActionRecommendation

    rec_a = NextActionRecommendation(
        tool="run_command", args="x" * 1000, rationale="r"
    )
    rec_b = NextActionRecommendation(
        tool="run_command", args="x" * 1000 + "different", rationale="r"
    )
    # First 200 chars identical → signatures match (benign drift in
    # tail doesn't count as a new recommendation).
    assert _recommendation_signature(rec_a) == _recommendation_signature(rec_b)


def test_recommendation_signature_none_is_empty_string() -> None:
    assert _recommendation_signature(None) == ""


def test_is_stall_fires_on_3_identical_recommendations_no_facts_change() -> None:
    """Canonical stall: three reflection turns in a row, same
    recommendation, no facts progress between them."""
    window = deque(maxlen=3)
    rec_sig = "run_command|GetNPUsers.py -no-pass thm.local/"
    for _ in range(3):
        window.append(rec_sig)
    assert _is_stall(window, "u=2_h=0_c=0_s=0_d=1", "u=2_h=0_c=0_s=0_d=1") is True


def test_is_stall_clears_when_facts_progress() -> None:
    """Even with 3 identical recommendations, if facts moved we ARE
    progressing — don't flag a stall."""
    window = deque(maxlen=3)
    rec_sig = "run_command|GetNPUsers.py -no-pass thm.local/"
    for _ in range(3):
        window.append(rec_sig)
    assert _is_stall(
        window,
        "u=2_h=0_c=0_s=0_d=1",  # before
        "u=2_h=1_c=0_s=0_d=1",  # after — hashes grew
    ) is False


def test_is_stall_requires_window_to_be_full() -> None:
    """Only one entry in the window — can't conclude anything about
    repetition. Stall should be False."""
    window = deque(maxlen=3)
    window.append("run_command|GetNPUsers ...")
    assert _is_stall(window, "u=1", "u=1") is False


def test_is_stall_empty_recommendations_dont_count() -> None:
    """If the planner emitted no recommendation (all empty strings),
    we have nothing to stall on. False."""
    window = deque(maxlen=3)
    for _ in range(3):
        window.append("")
    assert _is_stall(window, "u=0", "u=0") is False


def test_is_stall_requires_all_window_entries_identical() -> None:
    """Two of three identical, one different → no stall."""
    window = deque(maxlen=3)
    window.append("run_command|A")
    window.append("run_command|B")
    window.append("run_command|A")
    assert _is_stall(window, "u=0", "u=0") is False


def test_reflection_prompt_includes_stall_block_when_detected() -> None:
    """The stall block surfaces explicit (A)/(B) directive: copy the
    operator directive verbatim, or emit final summary."""
    prompt = _build_reflection_prompt(
        turns_used=8,
        total_turns_cap=30,
        tool_history=[],
        last_output_summary="",
        stuck_record=None,
        degen_pattern=None,
        extracted_facts=None,
        next_action=None,
        stall_detected=True,
    )
    assert "STALL DETECTED" in prompt
    assert "Copy the OPERATOR DIRECTIVE verbatim" in prompt
    assert "emit the final summary" in prompt.lower()


def test_reflection_prompt_omits_stall_block_when_not_detected() -> None:
    prompt = _build_reflection_prompt(
        turns_used=4,
        total_turns_cap=30,
        tool_history=[],
        last_output_summary="",
        stuck_record=None,
        degen_pattern=None,
        extracted_facts=None,
        next_action=None,
        stall_detected=False,
    )
    assert "STALL DETECTED" not in prompt


def test_reflection_prompt_substitutes_target_host_from_facts() -> None:
    """G4 placeholder substitution: when ExtractedFacts.hosts is
    populated, the ``<target>`` placeholder in the planner's args
    must be replaced with the first known host in the rendered prompt."""
    from kryon.intelligence.exploit_chain_planner import NextActionRecommendation

    facts = ExtractedFacts(hosts=("10.67.190.8",))
    rec = NextActionRecommendation(
        tool="run_command",
        args="nc -q 1 -w 5 <target> 8000",
        rationale="basic connection hint",
        confidence=0.9,
    )
    prompt = _build_reflection_prompt(
        turns_used=4,
        total_turns_cap=30,
        tool_history=[],
        last_output_summary="",
        stuck_record=None,
        degen_pattern=None,
        extracted_facts=facts,
        next_action=rec,
    )
    assert "10.67.190.8" in prompt
    # No literal ``<target>`` should survive when a host is known.
    assert "<target>" not in prompt
