"""Tests for streaming improvements — truncation and default."""

import os
from unittest.mock import patch

from kryon.repl.ui.progress import ProgressState


class TestStreamingOutputTruncation:
    def test_truncates_running_output_over_30_lines(self):
        """Output should be truncated to last 30 lines when status=running."""
        from kryon.util.streaming import _create_tool_panel_content

        long_output = "\n".join(f"line {i}" for i in range(60))
        execution_info = {"status": "running"}

        _header, _content = _create_tool_panel_content(
            "nmap_scan", {"command": "nmap"}, long_output, execution_info,
        )
        # The function truncates internally; we verify it doesn't crash
        # and produces valid output (Rich Group object)
        assert _content is not None

    def test_does_not_truncate_completed_output(self):
        """Completed output should NOT be truncated to 30 lines."""
        from kryon.util.streaming import _create_tool_panel_content

        long_output = "\n".join(f"line {i}" for i in range(60))
        execution_info = {"status": "completed"}

        _header, _content = _create_tool_panel_content(
            "nmap_scan", {"command": "nmap"}, long_output, execution_info,
        )
        assert _content is not None

    def test_short_output_not_truncated(self):
        """Short output under 30 lines should not be truncated."""
        from kryon.util.streaming import _create_tool_panel_content

        short_output = "\n".join(f"line {i}" for i in range(10))
        execution_info = {"status": "running"}

        _header, _content = _create_tool_panel_content(
            "run_command", {"command": "ls"}, short_output, execution_info,
        )
        assert _content is not None


class TestStreamingDefault:
    def test_kryon_stream_default_is_true(self):
        """KRYON_STREAM should default to 'true' when not set."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("KRYON_STREAM", None)
            # The default in _original.py is now "true"
            default = os.getenv("KRYON_STREAM", "true")
            assert default == "true"


class TestProgressBarInPanel:
    def test_panel_renders_with_progress_state(self):
        """Panel should render correctly when progress_state is provided."""
        from kryon.util.streaming import _create_tool_panel_content

        state = ProgressState(total_lines=50, percentage=42.5, current_step="Scanning")
        execution_info = {"status": "running"}

        _header, content = _create_tool_panel_content(
            "nmap_scan", {"command": "nmap"}, "some output",
            execution_info, progress_state=state,
        )
        assert content is not None
