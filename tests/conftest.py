from __future__ import annotations

import os

# Enable the red-team / offensive modules for the test session (matches the
# per-subdir conftests in tests/skills, tests/state, tests/tools/autonomous).
# Many tests import offensive tools (privilege_escalation, lateral_movement,
# data_exfiltration, autonomous/evasion) gated behind KRYON_RED_TEAM; without
# this their import fails at collection. setdefault → an operator can still run
# `KRYON_RED_TEAM=false pytest` to exercise the gate-disabled path.
os.environ.setdefault("KRYON_RED_TEAM", "true")

import pytest

from kryon.sdk.agents.models import _openai_shared
from kryon.sdk.agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from kryon.sdk.agents.models.openai_responses import OpenAIResponsesModel
from kryon.sdk.agents.tracing import set_trace_processors, set_tracing_disabled
from kryon.sdk.agents.tracing.setup import GLOBAL_TRACE_PROVIDER
from tests.testing_processor import SPAN_PROCESSOR_TESTING


# This fixture will run once before any tests are executed
@pytest.fixture(scope="session", autouse=True)
def setup_span_processor():
    set_trace_processors([SPAN_PROCESSOR_TESTING])


# This fixture will run before each test
@pytest.fixture(autouse=True)
def clear_span_processor():
    # Ensure tracing is enabled (some modules like cli.py disable it globally)
    set_tracing_disabled(False)
    # Always ensure our test processor is set (handles import order issues)
    set_trace_processors([SPAN_PROCESSOR_TESTING])
    SPAN_PROCESSOR_TESTING.clear()
    yield
    SPAN_PROCESSOR_TESTING.force_flush()
    SPAN_PROCESSOR_TESTING.shutdown()
    SPAN_PROCESSOR_TESTING.clear()


# This fixture will run before each test
@pytest.fixture(autouse=True)
def clear_openai_settings():
    _openai_shared._default_openai_key = None
    _openai_shared._default_openai_client = None
    _openai_shared._use_responses_by_default = True


# This fixture will run after all tests end
@pytest.fixture(autouse=True, scope="session")
def shutdown_trace_provider():
    yield
    GLOBAL_TRACE_PROVIDER.shutdown()


@pytest.fixture(autouse=True)
def disable_real_model_clients(monkeypatch, request):
    # If the test is marked to allow the method call, don't override it.
    if request.node.get_closest_marker("allow_call_model_methods"):
        return

    def failing_version(*args, **kwargs):
        pytest.fail("Real models should not be used in tests!")

    monkeypatch.setattr(OpenAIResponsesModel, "get_response", failing_version)
    monkeypatch.setattr(OpenAIResponsesModel, "stream_response", failing_version)
    monkeypatch.setattr(OpenAIChatCompletionsModel, "get_response", failing_version)
    monkeypatch.setattr(OpenAIChatCompletionsModel, "stream_response", failing_version)


@pytest.fixture(autouse=True)
def relax_stuck_detector(monkeypatch, request):
    """F85.E — Most SDK tests legitimately loop the same tool call to
    exercise MaxTurns / handoff / streaming behaviour. The StuckDetector
    would abort those runs at the 3rd identical triple, masking the
    real assertion. Relax thresholds to 999 by default; tests that
    specifically exercise the detector (``tests/sdk/test_stuck_detector.py``)
    construct their own ``StuckDetector(...)`` with explicit thresholds
    that bypass this env var.
    """
    if request.node.get_closest_marker("strict_stuck_detector"):
        return
    monkeypatch.setenv("KRYON_STUCK_ABORT_AT", "999")
    monkeypatch.setenv("KRYON_STUCK_INTERVENE_AT", "998")
    monkeypatch.setenv("KRYON_STUCK_WINDOW", "999")
