"""FASE 11.H — duck-typed model_dump + LiteLLM usage patch.

Two helpers in ``openai_chatcompletions.py`` that close pre-existing
SDK bugs surfaced by the Pyrat bench (2026-05-26):

  - ``_safe_model_dump``: replaces brittle ``.model_dump()`` calls so
    a ``types.SimpleNamespace`` response message (Ollama returns this
    in some tool-call shapes) doesn't crash the turn.
  - ``_patch_response_usage_for_litellm``: injects the
    ``output_tokens_details`` / ``input_tokens_details`` fields LiteLLM
    pydantic v2 expects, eliminating the noisy ValidationError trace
    every turn emitted to stderr.
"""

from __future__ import annotations

from types import SimpleNamespace

from kryon.sdk.agents.models.openai_chatcompletions import (
    _patch_response_usage_for_litellm,
    _safe_model_dump,
)


# ---------------------------------------------------------------------------
# _safe_model_dump
# ---------------------------------------------------------------------------


def test_safe_model_dump_handles_simplenamespace() -> None:
    """The exact failure mode from Pyrat bench: SimpleNamespace from
    Ollama tool-call response. Canonical model_dump() raises
    ``AttributeError: '__pydantic_extra__'``; we must return a dict."""
    ns = SimpleNamespace(content="hi", role="assistant", tool_calls=None)
    out = _safe_model_dump(ns)
    assert isinstance(out, dict)
    assert out["content"] == "hi"
    assert out["role"] == "assistant"


def test_safe_model_dump_uses_pydantic_path_when_available() -> None:
    """If the object IS a Pydantic model (model_dump callable), we must
    use it — the duck-typing fallback would lose Pydantic-only fields
    like computed properties."""

    class _Fake:
        def model_dump(self) -> dict:
            return {"canonical": True}

    out = _safe_model_dump(_Fake())
    assert out == {"canonical": True}


def test_safe_model_dump_handles_dict() -> None:
    """Mapping inputs should round-trip cleanly."""
    out = _safe_model_dump({"k": "v", "n": 1})
    assert out == {"k": "v", "n": 1}


def test_safe_model_dump_never_raises_on_weird_input() -> None:
    """Last-resort fallback: any object that resists all dict-conversion
    paths must still return a dict (with _repr) — never crash."""

    class _Weird:
        __slots__ = ()  # no __dict__, no model_dump, not a Mapping

    out = _safe_model_dump(_Weird())
    assert isinstance(out, dict)
    assert "_repr" in out


def test_safe_model_dump_falls_through_when_model_dump_raises() -> None:
    """A buggy model_dump that raises must NOT bubble — fall through to
    vars() / dict() / repr() instead."""

    class _BrokenPydantic:
        def model_dump(self) -> dict:
            raise RuntimeError("simulated pydantic v2 strict validation")

        x = "fallback-value"

    out = _safe_model_dump(_BrokenPydantic())
    # vars() picks up the class attr through __dict__ inspection on
    # an instance; the important assertion is "no crash + dict-shaped".
    assert isinstance(out, dict)


# ---------------------------------------------------------------------------
# _patch_response_usage_for_litellm
# ---------------------------------------------------------------------------


def test_patch_usage_injects_missing_details_into_dict() -> None:
    """Ollama returns usage as a plain dict without _details subfields.
    The patch must add them so LiteLLM's pydantic v2 validator passes."""

    class _Resp:
        pass

    r = _Resp()
    r.usage = {
        "prompt_tokens": 100,
        "completion_tokens": 50,
        "input_tokens": 100,
        "output_tokens": 50,
    }
    _patch_response_usage_for_litellm(r)
    assert "output_tokens_details" in r.usage
    assert r.usage["output_tokens_details"] == {"reasoning_tokens": 0}
    assert "input_tokens_details" in r.usage
    assert r.usage["input_tokens_details"] == {"cached_tokens": 0}


def test_patch_usage_preserves_existing_details() -> None:
    """If a real OpenAI response already has the details fields (e.g.
    o1 reasoning_tokens > 0), the patch must NOT overwrite them."""

    class _Resp:
        pass

    r = _Resp()
    r.usage = {
        "prompt_tokens": 100,
        "completion_tokens": 50,
        "output_tokens_details": {"reasoning_tokens": 1234},
    }
    _patch_response_usage_for_litellm(r)
    assert r.usage["output_tokens_details"]["reasoning_tokens"] == 1234


def test_patch_usage_handles_none_usage() -> None:
    """``response.usage = None`` is legal in some streaming paths —
    must not crash."""

    class _Resp:
        pass

    r = _Resp()
    r.usage = None
    # No assertion needed — the test is "does not raise".
    _patch_response_usage_for_litellm(r)


def test_patch_usage_handles_missing_usage_attr() -> None:
    """Even if the response doesn't have ``.usage`` at all, must not
    crash."""

    class _Resp:
        pass

    _patch_response_usage_for_litellm(_Resp())


def test_patch_usage_handles_object_shaped_usage() -> None:
    """OpenAI direct responses return usage as a Pydantic model, not
    a dict. The patch should set attributes via setattr."""

    class _Usage:
        prompt_tokens = 10
        completion_tokens = 5

    class _Resp:
        pass

    r = _Resp()
    r.usage = _Usage()
    _patch_response_usage_for_litellm(r)
    assert hasattr(r.usage, "output_tokens_details")
    assert hasattr(r.usage, "input_tokens_details")
