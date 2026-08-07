"""_compose_command_output — the non-streaming exec path must always give the model
a usable signal (stdout + stderr + exit code), never an empty block.

Regression: the old `output = stdout or stderr` dropped stderr when stdout was
non-empty and never reported the exit code, so a failing command returned "" or
partial output with no error — the model saw a blank EXTERNAL SERVER RESPONSE fence
and retried blind (observed live against an example target)."""

from __future__ import annotations

from kryon.tools.common._executors import _compose_command_output


def test_stdout_only():
    assert _compose_command_output("hello\n", "", 0) == "hello"


def test_stderr_surfaced_even_when_stdout_present():
    # The old code discarded stderr whenever stdout was non-empty.
    out = _compose_command_output("partial\n", "boom: permission denied\n", 1)
    assert "partial" in out
    assert "boom: permission denied" in out
    assert "[stderr]" in out
    assert "[exit code 1]" in out


def test_stderr_only():
    out = _compose_command_output("", "not found\n", 127)
    assert "not found" in out
    assert "[exit code 127]" in out


def test_zero_exit_has_no_exit_marker():
    assert "[exit code" not in _compose_command_output("ok", "", 0)


def test_empty_output_returns_sentinel_not_blank():
    # The exact bug: nmap under torsocks produced nothing; must NOT return "".
    out = _compose_command_output("", "", 0)
    assert out.strip() != ""
    assert "no stdout/stderr" in out


def test_empty_output_with_nonzero_exit_reports_code():
    out = _compose_command_output("", "", 1)
    assert out.strip() != ""
    assert "exit code 1" in out


def test_none_returncode_is_tolerated():
    out = _compose_command_output("", "", None)
    assert out.strip() != ""
    assert "[exit code" not in out  # None is not reported as a failure marker


# --------------------------------------------------------------------------- #
# curl exit-code gloss. `curl -s` suppresses its own stderr, so a failed fetch #
# left only "[exit code 6]"; the model read it as a timeout and looped. Gloss  #
# the code (only for curl, only when stderr is empty) so it can diagnose DNS.  #
# --------------------------------------------------------------------------- #


def test_curl_exit6_is_glossed_as_dns():
    out = _compose_command_output("", "", 6, "curl -s http://www.host/")
    assert "exit code 6" in out
    assert "DNS" in out  # the model now sees "couldn't resolve host (DNS)"


def test_curl_exit7_is_glossed_as_connect():
    out = _compose_command_output("", "", 7, "curl -sI http://host/")
    assert "conectar" in out.lower()


def test_non_curl_exit6_is_not_glossed():
    # exit 6 means something else for other programs — don't assume curl's meaning.
    out = _compose_command_output("", "", 6, "grep pattern file")
    assert out == "[exit code 6]"


def test_curl_gloss_skipped_when_stderr_present():
    # If curl DID emit stderr (no -s), show the real diagnostic, not the gloss.
    out = _compose_command_output("", "curl: (6) Could not resolve host: x\n", 6, "curl http://x/")
    assert "Could not resolve host" in out
    assert "verificá el nombre" not in out


def test_curl_unknown_exit_code_not_glossed():
    out = _compose_command_output("", "", 99, "curl -s http://x/")
    assert out == "[exit code 99]"
