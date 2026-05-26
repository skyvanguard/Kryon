"""FASE 5 — tool_templates unit tests.

The templates module is pure data + string formatting, so the tests
pin the contract: which tool names get matched against an
``args_preview`` string, how the rendered block looks, ordering /
deduplication / cap behavior, and that callers never crash on empty
input.

Why these tests exist: the rendered block lands in every reflection
turn's prompt. If the formatter drifts (e.g. starts emitting tools
that aren't in recent history, or duplicates entries) the prompt
bloats and the model loses focus on what matters. The 5-cap +
newest-first invariants pin that.
"""

from __future__ import annotations

from kryon.intelligence.tool_templates import (
    _detect_tools_in_args,
    format_templates_for_recent_tools,
)


# ---------------------------------------------------------------------------
# _detect_tools_in_args
# ---------------------------------------------------------------------------


def test_detect_finds_nc_in_simple_invocation() -> None:
    assert "nc" in _detect_tools_in_args("nc -q 1 -w 5 10.0.0.1 8000")


def test_detect_finds_tool_inside_pipe_chain() -> None:
    """The detector matches anywhere in the string — so an inner
    pipeline like ``echo 'foo' | nc target port`` should match nc."""
    detected = _detect_tools_in_args("echo 'help' | nc 10.0.0.1 8000")
    assert "nc" in detected


def test_detect_finds_multiple_tools_in_chained_invocation() -> None:
    """A macro chain that runs GetNPUsers then hashcat should match
    both names."""
    detected = _detect_tools_in_args(
        "GetNPUsers.py -no-pass -dc-ip 1.2.3.4 thm.local/ && "
        "hashcat -m 18200 hashes.txt rockyou.txt"
    )
    assert "GetNPUsers.py" in detected
    assert "hashcat" in detected


def test_detect_finds_impacket_dotpy_suffix() -> None:
    detected = _detect_tools_in_args(
        "secretsdump.py -just-dc-ntlm thm.local/alice:'P' @10.0.0.1"
    )
    assert "secretsdump.py" in detected


def test_detect_returns_empty_for_unknown_tool() -> None:
    assert _detect_tools_in_args("some-random-binary --flag x") == []


def test_detect_returns_empty_for_empty_input() -> None:
    assert _detect_tools_in_args("") == []


# ---------------------------------------------------------------------------
# format_templates_for_recent_tools
# ---------------------------------------------------------------------------


def test_format_returns_empty_string_when_no_history() -> None:
    assert format_templates_for_recent_tools([]) == ""


def test_format_returns_empty_string_when_no_known_tools() -> None:
    assert format_templates_for_recent_tools(
        ["totally-unrelated-thing arg1 arg2"]
    ) == ""


def test_format_includes_canonical_invocation_for_detected_tool() -> None:
    out = format_templates_for_recent_tools(["nc 10.0.0.1 8000"])
    assert "Canonical tool invocations" in out
    assert "nc" in out
    # The canonical invocation must mention -q and -w (the anti-
    # pattern the template is meant to remediate).
    assert "-q 1" in out
    assert "-w 5" in out


def test_format_deduplicates_same_tool_across_history() -> None:
    """If the model used nc five times in history, the block should
    list nc exactly once — not five entries."""
    history = [f"nc 10.0.0.1 800{i}" for i in range(5)]
    out = format_templates_for_recent_tools(history)
    # Header line plus one entry block per tool. nc should appear
    # under exactly one ``**nc**`` heading.
    assert out.count("**nc**") == 1


def test_format_caps_at_5_distinct_tools() -> None:
    """When the history spans more than 5 distinct tools the block
    must cap at 5 to keep the prompt focused. The most-recent 5 win."""
    history = [
        "smbclient -L //x -N",
        "ldapsearch -x -H ldap://x -b ...",
        "GetNPUsers.py -no-pass ...",
        "hashcat -m 18200 ...",
        "secretsdump.py ...",
        "nmap -sV ...",
        "curl http://x",
        "nc x 8000",
    ]
    out = format_templates_for_recent_tools(history)
    # Count tool heading occurrences. Each is ``- **name**``.
    headings = out.count("- **")
    assert headings == 5


def test_format_prefers_newest_history_when_capping() -> None:
    """With 8 tools in history and a 5-cap, the FIVE MOST RECENT
    should win — not the first five. Verify by checking that the
    last tool (nc, newest) appears and the first (smbclient, oldest)
    does not when we exceed the cap."""
    history = [
        "smbclient -L //x -N",  # oldest
        "ldapsearch -x -H ldap://x -b ...",
        "GetNPUsers.py -no-pass ...",
        "hashcat -m 18200 ...",
        "secretsdump.py ...",
        "nmap -sV ...",
        "curl http://x",
        "nc x 8000",  # newest
    ]
    out = format_templates_for_recent_tools(history)
    assert "**nc**" in out
    assert "**smbclient**" not in out


def test_format_renders_each_tool_with_why_line() -> None:
    """Every rendered template has a ``*Why*:`` rationale line so the
    model knows WHY those flags are canonical."""
    out = format_templates_for_recent_tools(["curl http://x"])
    assert "*Why*:" in out
    # The curl rationale must mention --max-time (its anti-pattern).
    assert "--max-time" in out
