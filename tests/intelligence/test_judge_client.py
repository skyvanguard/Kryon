"""Tests for the shared judge client (guardian + finding judges)."""

from __future__ import annotations

from kryon.intelligence.judge_client import _judge_model, build_judge, judge_profile_enabled


def test_profile_disabled_by_default(monkeypatch):
    monkeypatch.delenv("KRYON_CAPABLE_MODEL", raising=False)
    monkeypatch.delenv("KRYON_RED_TEAM", raising=False)
    assert judge_profile_enabled() is False


def test_profile_enabled_by_capable_or_redteam(monkeypatch):
    monkeypatch.delenv("KRYON_RED_TEAM", raising=False)
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
    assert judge_profile_enabled() is True
    monkeypatch.delenv("KRYON_CAPABLE_MODEL", raising=False)
    monkeypatch.setenv("KRYON_RED_TEAM", "1")
    assert judge_profile_enabled() is True


def test_build_judge_none_in_banca_safe(monkeypatch):
    monkeypatch.delenv("KRYON_CAPABLE_MODEL", raising=False)
    monkeypatch.delenv("KRYON_RED_TEAM", raising=False)
    # banca-safe → judge must not build (non-determinism can't leak into the hash)
    assert build_judge() is None


def test_judge_model_precedence(monkeypatch):
    monkeypatch.delenv("KRYON_GUARDIAN_MODEL", raising=False)
    monkeypatch.delenv("KRYON_MODEL", raising=False)
    assert _judge_model() == "qwen-unc"
    monkeypatch.setenv("KRYON_MODEL", "deepseek")
    assert _judge_model() == "deepseek"
    monkeypatch.setenv("KRYON_GUARDIAN_MODEL", "guardian-x")
    assert _judge_model() == "guardian-x"  # guardian model wins


def test_build_judge_none_on_client_construction_error(monkeypatch):
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")

    # client is built ONCE in build_judge (S5 pooling); a construction failure →
    # no judge (None), so the caller falls back to the deterministic path.
    class _Boom:
        def __init__(self, *a, **k):
            raise RuntimeError("no endpoint")

    import openai

    monkeypatch.setattr(openai, "OpenAI", _Boom)
    assert build_judge() is None


def test_judge_callable_fail_open_on_runtime_error(monkeypatch):
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")

    # a runtime error DURING a completion (not construction) → "" (fail-open),
    # never raises, so the caller keeps its deterministic default.
    class _FakeClient:
        def __init__(self, *a, **k):
            self.chat = self

        @property
        def completions(self):
            return self

        def create(self, *a, **k):
            raise RuntimeError("endpoint down mid-call")

    import openai

    monkeypatch.setattr(openai, "OpenAI", _FakeClient)
    judge = build_judge()
    assert judge is not None
    assert judge("anything") == ""
