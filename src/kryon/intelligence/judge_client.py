"""Reusable LLM-judge client for the guardian + finding judges.

A *judge* is a SECOND model that adjudicates something the deterministic layer
cannot settle on its own:

  - the **guardian-judge** decides whether a gray-zone MUTATING action
    (POST/PUT/DELETE on an authorized target) is safe to run — the subtle
    "this write looks out-of-scope / harmful" case a regex can't catch;
  - the **finding-judge** decides whether an ``inferred`` finding (CVE-by-version,
    SAST-no-runtime — the class the deterministic layer can't re-probe) is a
    REAL vulnerability or a false positive.

Both are **opt-in and NON-deterministic**, so they must never run in the
banca-safe (reproducible) profile — ``judge_profile_enabled()`` gates on the
offensive-profile flags. The client is **fail-open**: any error/timeout returns
an empty string and the caller keeps its deterministic default. It reuses the
native OpenAI-compatible endpoint (Qwen local / DeepSeek) already used across
the runtime — same ``OPENAI_BASE_URL`` / ``OPENAI_API_KEY`` convention as
``reflective_runner._reasoning_next_action``.
"""

from __future__ import annotations

import os
from collections.abc import Callable

from kryon.util.env import is_capable_model, is_red_team


def judge_profile_enabled() -> bool:
    """True only in the offensive / capable profile.

    The judge is non-deterministic (a model call), so it must NEVER run in the
    banca-safe path where reproducibility-by-hash is a contract. ``is_capable_model``
    (KRYON_CAPABLE_MODEL) and ``is_red_team`` (KRYON_RED_TEAM) are the existing
    offensive-profile flags — both default OFF, i.e. banca-safe by default.
    """
    return is_capable_model() or is_red_team()


def _judge_model() -> str:
    """Model alias for the judge. Prefers the dedicated ``KRYON_GUARDIAN_MODEL``,
    then the main ``KRYON_MODEL``, then the active local alias."""
    return (
        os.getenv("KRYON_GUARDIAN_MODEL", "").strip()
        or os.getenv("KRYON_MODEL", "").strip()
        or "qwen-unc"
    )


def build_judge(*, max_tokens: int = 400, timeout: float = 45.0) -> Callable[[str], str] | None:
    """Build a **sync** judge callable ``(prompt) -> reply``.

    Returns ``None`` when the profile is banca-safe (``judge_profile_enabled()``
    is False) or the OpenAI SDK is unavailable — the caller then keeps its
    deterministic default. ``temperature=0`` for maximum reproducibility within
    a run. The callable itself is best-effort: any error returns ``""``.

    Sync (not async) on purpose so the async callers can bridge it off the event
    loop with ``await asyncio.to_thread(...)`` — one implementation serves both
    the (async) tool executor and the (sync setup phase of) investigate.
    """
    if not judge_profile_enabled():
        return None
    try:
        from openai import OpenAI
    except Exception:  # noqa: BLE001 — SDK missing → no judge, caller falls back
        return None

    model = _judge_model()
    # Build the client ONCE (its httpx connection pool is reused across calls) —
    # finding_judge calls the judge once per inferred finding, so a per-call
    # client would leak sockets and skip connection reuse.
    try:
        client = OpenAI(
            base_url=os.getenv("OPENAI_BASE_URL") or None,
            api_key=os.getenv("OPENAI_API_KEY") or "llama",
            timeout=timeout,
        )
    except Exception:  # noqa: BLE001 — construction failed → no judge
        return None

    def _judge(prompt: str) -> str:
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                temperature=0.0,
            )
            msg = resp.choices[0].message
            return (msg.content or "") or (getattr(msg, "reasoning_content", "") or "")
        except Exception:  # noqa: BLE001 — fail-open: caller keeps deterministic default
            return ""

    return _judge
