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

from kryon.cli.reflective_runner import (
    _detect_intra_turn_degeneracy,
    _extract_chunk_text,
)


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
