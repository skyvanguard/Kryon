"""Test cli_print_tool_output deduplication logic with KRYON_STREAM=false"""

import os
import time

import pytest

from kryon.util import cli_print_tool_output


@pytest.fixture(autouse=True)
def reset_cli_print_state():
    """Reset cli_print_tool_output state before each test"""
    # Clear any existing state
    if hasattr(cli_print_tool_output, "_displayed_commands"):
        cli_print_tool_output._displayed_commands.clear()
    if hasattr(cli_print_tool_output, "_command_display_times"):
        cli_print_tool_output._command_display_times.clear()
    if hasattr(cli_print_tool_output, "_seen_calls"):
        cli_print_tool_output._seen_calls.clear()
    if hasattr(cli_print_tool_output, "_streaming_sessions"):
        cli_print_tool_output._streaming_sessions.clear()
    # F77.D / Fase 11 — flat renderer dedups by call_id, not by
    # command_key. Reset its seen-set too so each test starts clean.
    from kryon.util.streaming import _reset_render_dedup

    _reset_render_dedup()
    yield


def test_deduplication_with_streaming_disabled(capsys):
    """Test that duplicate suppression works correctly when KRYON_STREAM=false.

    After F77.D the primary dedup key is call_id, not tool_name:command.
    Passing the same call_id twice should suppress the second render."""
    os.environ["KRYON_STREAM"] = "false"

    # First call should display
    cli_print_tool_output(
        tool_name="run_command",
        args={"command": "ls -la"},
        output="test output",
        call_id="call_abc123",
        streaming=False,
    )

    captured = capsys.readouterr()
    assert "test output" in captured.out

    # Immediate duplicate (same call_id) should be suppressed by the
    # F77.D _dedup_render_check.
    cli_print_tool_output(
        tool_name="run_command",
        args={"command": "ls -la"},
        output="test output",
        call_id="call_abc123",
        streaming=False,
    )

    captured = capsys.readouterr()
    assert captured.out == ""  # Should be empty, duplicate suppressed

    # A different call_id (e.g. a fresh tool invocation in a later turn)
    # always renders, even with the same args.
    cli_print_tool_output(
        tool_name="run_command",
        args={"command": "ls -la"},
        output="test output 2",
        call_id="call_def456",
        streaming=False,
    )

    captured = capsys.readouterr()
    assert "test output 2" in captured.out


def test_deduplication_with_streaming_enabled(capsys):
    """Test that duplicate suppression works correctly when KRYON_STREAM=true"""
    os.environ["KRYON_STREAM"] = "true"

    # First call should display
    cli_print_tool_output(
        tool_name="run_command",
        args={"command": "pwd"},
        output="test output",
        call_id="call_xyz789",
        streaming=False,
    )

    captured = capsys.readouterr()
    assert "test output" in captured.out

    # Duplicate same call_id should always be suppressed
    cli_print_tool_output(
        tool_name="run_command",
        args={"command": "pwd"},
        output="test output",
        call_id="call_xyz789",
        streaming=False,
    )

    captured = capsys.readouterr()
    assert captured.out == ""  # Should be empty, duplicate suppressed


def test_different_commands_always_display(capsys):
    """Test that different commands are not considered duplicates"""
    os.environ["KRYON_STREAM"] = "false"

    # First command
    cli_print_tool_output(
        tool_name="run_command",
        args={"command": "ls"},
        output="output 1",
        streaming=False,
    )

    captured = capsys.readouterr()
    assert "output 1" in captured.out

    # Different command should display
    cli_print_tool_output(
        tool_name="run_command",
        args={"command": "pwd"},
        output="output 2",
        streaming=False,
    )

    captured = capsys.readouterr()
    assert "output 2" in captured.out


def test_empty_output_always_suppressed(capsys):
    """Test that empty output is always suppressed"""
    os.environ["KRYON_STREAM"] = "false"

    cli_print_tool_output(tool_name="run_command", args={"command": "test"}, output="", streaming=False)

    captured = capsys.readouterr()
    assert captured.out == ""  # Empty output should not display


def test_parallel_mode_deduplication(capsys):
    """Test deduplication in parallel mode with agent context"""
    os.environ["KRYON_STREAM"] = "false"

    # Simulate parallel agent execution with agent context
    token_info_p1 = {"agent_name": "TestAgent", "agent_id": "P1", "interaction_counter": 1}

    token_info_p2 = {"agent_name": "TestAgent", "agent_id": "P2", "interaction_counter": 1}

    # Same command from different parallel agents should both display
    cli_print_tool_output(
        tool_name="run_command",
        args={"command": "ls"},
        output="output from P1",
        token_info=token_info_p1,
        streaming=False,
    )

    captured = capsys.readouterr()
    assert "output from P1" in captured.out

    cli_print_tool_output(
        tool_name="run_command",
        args={"command": "ls"},
        output="output from P2",
        token_info=token_info_p2,
        streaming=False,
    )

    captured = capsys.readouterr()
    assert "output from P2" in captured.out  # Different agent context, should display
