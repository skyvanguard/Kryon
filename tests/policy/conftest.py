"""F153 — Policy test isolation.

``apply_policy_to_env`` writes directly to ``os.environ``. Without
this autouse fixture, env state leaks between tests and into the
neighbouring scoring/parsing suites (caught when the adversarial
tests started picking up KRYON_ADVERSARIAL_STRICT=true that policy
tests had set)."""

from __future__ import annotations

import os

import pytest

_TRACKED = (
    "KRYON_MODEL",
    "KRYON_LLM_TEMPERATURE",
    "KRYON_ADVERSARIAL_STRICT",
    "KRYON_CVE_VALIDATE",
    "KRYON_CVE_CACHE_REQUIRED",
    "KRYON_CVE_CACHE_PATH",
    "KRYON_REQUIRE_GROUNDING",
    "KRYON_GROUNDING_CONFIDENCE_CAP",
    "KRYON_REDACT_PAN",
    "KRYON_DEEP_REASONING",
)


@pytest.fixture(autouse=True)
def _isolate_policy_env():
    saved = {k: os.environ.get(k) for k in _TRACKED}
    for k in _TRACKED:
        os.environ.pop(k, None)
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
