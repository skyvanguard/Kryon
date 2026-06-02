"""Tests for the shared run-termination classifier (P0 error-handling symmetry)."""

from __future__ import annotations

import pytest

from kryon.sdk.agents.exceptions import (
    MaxTurnsExceeded,
    ModelBehaviorError,
    PriceLimitExceeded,
    StuckError,
)
from kryon.sdk.agents.run_outcome import (
    RECOVERABLE_RUN_EXCEPTIONS,
    RunOutcome,
    classify_run_exception,
)


@pytest.mark.unit
def test_stuck_error_classifies_as_stuck_with_tool_name():
    # Arrange
    exc = StuckError(tool_name="run_command", repeat_count=4, window_size=6)

    # Act
    outcome = classify_run_exception(exc)

    # Assert
    assert isinstance(outcome, RunOutcome)
    assert outcome.status == "stuck"
    assert "run_command" in outcome.message


@pytest.mark.unit
def test_max_turns_classifies_as_incomplete():
    outcome = classify_run_exception(MaxTurnsExceeded("hit the cap"))

    assert outcome is not None
    assert outcome.status == "incomplete"


@pytest.mark.unit
def test_price_limit_classifies_as_budget_exceeded():
    outcome = classify_run_exception(PriceLimitExceeded(current_cost=1.5, price_limit=1.0))

    assert outcome is not None
    assert outcome.status == "budget_exceeded"


@pytest.mark.unit
def test_unrecognised_exception_returns_none():
    # A genuine crash is NOT a graceful early stop — caller must propagate it.
    assert classify_run_exception(ModelBehaviorError("bad json")) is None
    assert classify_run_exception(RuntimeError("boom")) is None
    assert classify_run_exception(ValueError("nope")) is None


@pytest.mark.unit
def test_recoverable_tuple_matches_classifier():
    # Every type in the tuple must classify to a non-None outcome, and the
    # tuple must be usable directly in an ``except`` clause.
    assert RECOVERABLE_RUN_EXCEPTIONS == (StuckError, MaxTurnsExceeded, PriceLimitExceeded)
    for exc in (
        StuckError(tool_name="x", repeat_count=4, window_size=6),
        MaxTurnsExceeded("m"),
        PriceLimitExceeded(current_cost=2.0, price_limit=1.0),
    ):
        assert isinstance(exc, RECOVERABLE_RUN_EXCEPTIONS)
        assert classify_run_exception(exc) is not None
