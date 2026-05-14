"""F153 — Pre-flight policy tests."""

from __future__ import annotations

import pytest

from kryon.policy.preflight import (
    EngagementPolicy,
    apply_policy_to_env,
    is_reasoning_model,
    resolve_policy,
)

# ---------------------------------------------------------------------------
# is_reasoning_model
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "model",
    [
        "kryon-r1-14b",
        "kryon-r1-14b:latest",
        "deepseek-r1:14b",
        "axonvertex/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:Q8_0_24K",
    ],
)
def test_reasoning_models_detected(model):
    assert is_reasoning_model(model) is True


@pytest.mark.parametrize(
    "model",
    [
        "kryon-14b",
        "kryon-14b:latest",
        "qwen3:14b",
        "qwen3-coder:30b-32k",
        "gemma4:26b",
        "",
    ],
)
def test_non_reasoning_models(model):
    assert is_reasoning_model(model) is False


def test_reasoning_marker_case_insensitive():
    assert is_reasoning_model("KRYON-R1-14B") is True
    assert is_reasoning_model("DeepSeek-R1") is True


# ---------------------------------------------------------------------------
# resolve_policy — defaults
# ---------------------------------------------------------------------------


def test_default_policy_for_instruct_model(monkeypatch):
    for env in (
        "KRYON_MODEL",
        "KRYON_LLM_TEMPERATURE",
        "KRYON_ADVERSARIAL_STRICT",
        "KRYON_CVE_VALIDATE",
        "KRYON_REQUIRE_GROUNDING",
        "KRYON_REDACT_PAN",
        "KRYON_CVE_CACHE_REQUIRED",
    ):
        monkeypatch.delenv(env, raising=False)
    monkeypatch.setenv("KRYON_MODEL", "kryon-14b")

    p = resolve_policy()
    assert p.reasoning_model is False
    assert p.adversarial_strict is False  # not auto-on for instruct
    assert p.require_grounding is False
    assert p.cve_validate is True  # default on
    assert p.redact_pan is True
    assert p.temperature == 0.0


def test_default_policy_for_r1_auto_strict(monkeypatch):
    for env in (
        "KRYON_ADVERSARIAL_STRICT",
        "KRYON_REQUIRE_GROUNDING",
    ):
        monkeypatch.delenv(env, raising=False)
    monkeypatch.setenv("KRYON_MODEL", "kryon-r1-14b")

    p = resolve_policy()
    assert p.reasoning_model is True
    # R1 auto-on for strict + grounding.
    assert p.adversarial_strict is True
    assert p.require_grounding is True
    assert p.cve_validate is True


def test_explicit_off_overrides_auto_strict(monkeypatch):
    """When operator explicitly sets KRYON_ADVERSARIAL_STRICT=false the
    auto-on for R1 is suppressed."""
    monkeypatch.setenv("KRYON_MODEL", "kryon-r1-14b")
    monkeypatch.setenv("KRYON_ADVERSARIAL_STRICT", "false")
    monkeypatch.setenv("KRYON_REQUIRE_GROUNDING", "false")

    p = resolve_policy()
    assert p.reasoning_model is True
    assert p.adversarial_strict is False
    assert p.require_grounding is False


def test_temperature_from_env(monkeypatch):
    monkeypatch.setenv("KRYON_MODEL", "kryon-14b")
    monkeypatch.setenv("KRYON_LLM_TEMPERATURE", "0.7")
    p = resolve_policy()
    assert p.temperature == 0.7


def test_temperature_invalid_falls_back_to_zero(monkeypatch):
    monkeypatch.setenv("KRYON_MODEL", "kryon-14b")
    monkeypatch.setenv("KRYON_LLM_TEMPERATURE", "not-a-number")
    p = resolve_policy()
    assert p.temperature == 0.0


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------


def test_banner_contains_key_fields():
    p = EngagementPolicy(
        model="kryon-r1-14b",
        temperature=0.0,
        adversarial_strict=True,
        cve_validate=True,
        cve_cache_required=False,
        require_grounding=True,
        redact_pan=True,
        reasoning_model=True,
    )
    banner = p.banner()
    assert "kryon-r1-14b" in banner
    assert "(reasoning)" in banner
    assert "strict=on" in banner
    assert "grounding=on" in banner


def test_banner_instruct_model_no_reasoning_label():
    p = EngagementPolicy(
        model="kryon-14b",
        temperature=0.0,
        adversarial_strict=False,
        cve_validate=True,
        cve_cache_required=False,
        require_grounding=False,
        redact_pan=True,
        reasoning_model=False,
    )
    banner = p.banner()
    assert "kryon-14b" in banner
    assert "(reasoning)" not in banner


# ---------------------------------------------------------------------------
# apply_policy_to_env
# ---------------------------------------------------------------------------


def test_apply_policy_sets_unset_envs(monkeypatch):
    for env in (
        "KRYON_LLM_TEMPERATURE",
        "KRYON_ADVERSARIAL_STRICT",
        "KRYON_CVE_VALIDATE",
        "KRYON_REQUIRE_GROUNDING",
        "KRYON_REDACT_PAN",
        "KRYON_CVE_CACHE_REQUIRED",
    ):
        monkeypatch.delenv(env, raising=False)

    p = EngagementPolicy(
        model="kryon-r1-14b",
        temperature=0.0,
        adversarial_strict=True,
        cve_validate=True,
        cve_cache_required=False,
        require_grounding=True,
        redact_pan=True,
        reasoning_model=True,
    )
    apply_policy_to_env(p)
    import os

    assert os.environ["KRYON_ADVERSARIAL_STRICT"] == "true"
    assert os.environ["KRYON_REQUIRE_GROUNDING"] == "true"
    assert os.environ["KRYON_CVE_VALIDATE"] == "true"


def test_apply_policy_does_not_overwrite_existing_env(monkeypatch):
    monkeypatch.setenv("KRYON_ADVERSARIAL_STRICT", "false")

    p = EngagementPolicy(
        model="kryon-r1-14b",
        temperature=0.0,
        adversarial_strict=True,
        cve_validate=True,
        cve_cache_required=False,
        require_grounding=True,
        redact_pan=True,
        reasoning_model=True,
    )
    apply_policy_to_env(p)
    import os

    # Operator's explicit "false" survives.
    assert os.environ["KRYON_ADVERSARIAL_STRICT"] == "false"
