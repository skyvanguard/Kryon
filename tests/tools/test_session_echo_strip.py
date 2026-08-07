"""T4-A2: the PTY echoes stdin back, so without filtering the model reads its own
command as output. get_new_output must strip the echo line of the last-sent command."""

from __future__ import annotations

import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

from kryon.tools.common._sessions import ShellSession


def _make_session() -> ShellSession:
    # Build without starting a real process.
    s = ShellSession.__new__(ShellSession)
    s.output_buffer = []
    s._buffer_lock = __import__("threading").Lock()
    s._last_output_position = 0
    s._last_input = ""
    return s


def test_echo_line_is_stripped():
    s = _make_session()
    s._last_input = "whoami"
    s.output_buffer = ["whoami", "root"]
    out = s.get_new_output(mark_position=False)
    assert "root" in out
    assert out.strip().splitlines() == ["root"]  # echo removed


def test_only_first_echo_removed_real_output_kept():
    s = _make_session()
    s._last_input = "id"
    # 'id' legitimately appears in output (uid) — only the leading echo goes.
    s.output_buffer = ["id", "uid=0(root) gid=0", "id"]
    out = s.get_new_output(mark_position=False)
    lines = out.split("\n")
    assert lines[0].startswith("uid=0")
    assert "id" in lines  # the trailing real 'id' survived


def test_no_last_input_is_noop():
    s = _make_session()
    s._last_input = ""
    s.output_buffer = ["some output", "more"]
    out = s.get_new_output(mark_position=False)
    assert out == "some output\nmore"
