"""The native model adapter must treat a transient server fault (5xx / a local
model's malformed-tool_call parse error) as retryable, not fatal.

Regression: a single HTTP 500 "Failed to parse tool call arguments" from llama.cpp
aborted engage/REPL runs outright — the reflective_runner nudge only covers
`kryon investigate`. The fix lives in the common adapter so the safety net reaches
every call site.
"""

from __future__ import annotations

from kryon.sdk.agents.models.openai_native import _is_transient_model_error


class _StatusErr(Exception):
    def __init__(self, status_code: int) -> None:
        super().__init__(f"http {status_code}")
        self.status_code = status_code


class InternalServerError(Exception):
    """Mimics openai.InternalServerError by class name."""


class APIConnectionError(Exception):
    pass


def test_5xx_status_is_transient():
    assert _is_transient_model_error(_StatusErr(500))
    assert _is_transient_model_error(_StatusErr(502))
    assert _is_transient_model_error(_StatusErr(503))
    assert _is_transient_model_error(_StatusErr(504))


def test_malformed_tool_call_parse_error_is_NOT_retried_here():
    # The parse error is the model emitting bad JSON (deterministic at low temp):
    # retrying the same request burns tokens for nothing. It's handled one layer
    # up by the reflective_runner nudge, not by a blind adapter retry.
    assert not _is_transient_model_error(
        Exception("Error code: 500 - Failed to parse tool call arguments as JSON")
    )
    assert not _is_transient_model_error(Exception("parse tool call failed"))


def test_error_class_names_are_transient():
    assert _is_transient_model_error(InternalServerError("boom"))
    assert _is_transient_model_error(APIConnectionError("conn reset"))


def test_client_errors_and_logic_errors_are_not_transient():
    assert not _is_transient_model_error(_StatusErr(400))
    assert not _is_transient_model_error(_StatusErr(401))
    assert not _is_transient_model_error(_StatusErr(404))
    assert not _is_transient_model_error(ValueError("bad input"))
    assert not _is_transient_model_error(KeyError("missing"))
