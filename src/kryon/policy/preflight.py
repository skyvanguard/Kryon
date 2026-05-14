"""F153 — Engagement pre-flight policy.

At the start of every engagement, resolve the active operational
policy and surface it to the operator. Today the policy bundles:

  - model (from ``KRYON_MODEL``)
  - LLM temperature (from ``KRYON_LLM_TEMPERATURE`` / F155 default)
  - adversarial-strict mode (F148: ``KRYON_ADVERSARIAL_STRICT``)
  - CVE validation gate (F151: ``KRYON_CVE_VALIDATE``)
  - tool-output grounding (F152: ``KRYON_REQUIRE_GROUNDING``)
  - PAN redaction (F119: ``KRYON_REDACT_PAN``)

When the model is a **reasoning model** (R1 distill, DeepSeek-R1,
Foundation-Sec-reasoning), we **auto-enable** the stricter validation
gates unless the operator explicitly turned them off. The reasoning
model's strength (chain-of-thought) is also its weakness — it
generates more findings, including hallucinations. The auto-strict
policy keeps the defaults banca-safe without forcing the operator to
remember which envs to flip.

This module is pure / no I/O — the operator gets a single banner
showing what the engagement will run with.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class EngagementPolicy:
    """Resolved policy for one engagement."""

    model: str
    temperature: float
    adversarial_strict: bool
    cve_validate: bool
    cve_cache_required: bool
    require_grounding: bool
    redact_pan: bool
    reasoning_model: bool
    # F159 — Qwen3 dense (kryon-14b) supports opt-in thinking mode via
    # the ``/think`` token in the preamble. When the operator sets
    # KRYON_DEEP_REASONING=true (or passes --deep-reasoning), the
    # orchestrator injects ``/think`` and the preflight gate treats
    # the run as reasoning-active for downstream strictness defaults.
    deep_reasoning: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def reasoning_active(self) -> bool:
        """True when this engagement should emit chain-of-thought —
        either because the model itself is reasoning-class (R1 distill)
        or because the operator opted in via deep_reasoning."""
        return self.reasoning_model or self.deep_reasoning

    def banner(self) -> str:
        """One-line summary suitable for the engagement banner."""
        parts = [
            f"model={self.model}",
            f"temp={self.temperature}",
            f"strict={'on' if self.adversarial_strict else 'off'}",
            f"cve_validate={'on' if self.cve_validate else 'off'}",
            f"grounding={'on' if self.require_grounding else 'off'}",
            f"redact_pan={'on' if self.redact_pan else 'off'}",
        ]
        # Insert reasoning label right after the model name so the
        # operator sees the run mode at a glance.
        if self.reasoning_model:
            parts.insert(1, "(reasoning)")
        elif self.deep_reasoning:
            parts.insert(1, "(deep-reasoning)")
        return "Policy: " + " ".join(parts)


# ---------------------------------------------------------------------------
# Model classification
# ---------------------------------------------------------------------------


# Substrings that mark a model as "reasoning" (chain-of-thought heavy).
# Match is case-insensitive and substring-based so variants
# (e.g. ``kryon-r1-14b:latest``, ``deepseek-r1:14b``) all match.
_REASONING_MARKERS: tuple[str, ...] = (
    "r1-",
    "-r1",
    "deepseek-r1",
    "reasoning",
)


def is_reasoning_model(model: str) -> bool:
    if not model:
        return False
    m = model.lower()
    return any(marker in m for marker in _REASONING_MARKERS)


# ---------------------------------------------------------------------------
# Policy resolution
# ---------------------------------------------------------------------------


def _env_bool(name: str, default: bool) -> tuple[bool, bool]:
    """Return ``(value, was_explicit)``. Empty env → returns the
    default with ``was_explicit=False`` so callers can detect
    auto-on cases."""
    raw = os.environ.get(name, "")
    if not raw:
        return default, False
    return raw.strip().lower() in {"1", "true", "yes", "on"}, True


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def resolve_policy() -> EngagementPolicy:
    """Read the active env, apply F153 auto-strict for reasoning models,
    and return a frozen ``EngagementPolicy``."""
    model = os.environ.get("KRYON_MODEL", "kryon-14b").strip()
    reasoning = is_reasoning_model(model)

    # F159 — Opt-in deep reasoning. ``KRYON_DEEP_REASONING=true`` makes
    # any base instruct model (Qwen3 dense / kryon-14b) emit chain-of-
    # thought via the ``/think`` token. Auto-on strict + grounding the
    # same way reasoning-class models do.
    deep_reasoning, _ = _env_bool("KRYON_DEEP_REASONING", default=False)
    reasoning_active = reasoning or deep_reasoning

    # F160 — Qwen3 thinking mode + Qwen3 official docs recommend
    # temperature 0.6 (not 0.0) when ``/think`` is active. Temperature 0
    # under thinking mode tends to loop the chain-of-thought because
    # every token is the argmax, the model never breaks out of a stall.
    # The dense Qwen3 + thinking_recommended params land at 0.6 / top_p
    # 0.95 / top_k 20 — matching the Modelfile defaults except temp.
    temperature_default = 0.6 if reasoning_active else 0.0
    temperature = _env_float("KRYON_LLM_TEMPERATURE", temperature_default)

    strict_default = reasoning_active
    adversarial_strict, _ = _env_bool("KRYON_ADVERSARIAL_STRICT", default=strict_default)

    cve_validate, _ = _env_bool("KRYON_CVE_VALIDATE", default=True)
    cve_cache_required, _ = _env_bool("KRYON_CVE_CACHE_REQUIRED", default=False)

    grounding_default = reasoning_active
    require_grounding, _ = _env_bool("KRYON_REQUIRE_GROUNDING", default=grounding_default)

    redact_pan, _ = _env_bool("KRYON_REDACT_PAN", default=True)

    return EngagementPolicy(
        model=model,
        temperature=temperature,
        adversarial_strict=adversarial_strict,
        cve_validate=cve_validate,
        cve_cache_required=cve_cache_required,
        require_grounding=require_grounding,
        redact_pan=redact_pan,
        reasoning_model=reasoning,
        deep_reasoning=deep_reasoning,
    )


def apply_policy_to_env(policy: EngagementPolicy) -> None:
    """Push the resolved policy values back into the environment so
    downstream modules (which consult env vars directly) see the
    auto-derived defaults. ``os.environ.setdefault`` so we never
    overwrite an explicit operator choice."""
    os.environ.setdefault("KRYON_MODEL", policy.model)
    os.environ.setdefault("KRYON_LLM_TEMPERATURE", str(policy.temperature))
    os.environ.setdefault("KRYON_ADVERSARIAL_STRICT", "true" if policy.adversarial_strict else "false")
    os.environ.setdefault("KRYON_CVE_VALIDATE", "true" if policy.cve_validate else "false")
    os.environ.setdefault("KRYON_CVE_CACHE_REQUIRED", "true" if policy.cve_cache_required else "false")
    os.environ.setdefault("KRYON_REQUIRE_GROUNDING", "true" if policy.require_grounding else "false")
    os.environ.setdefault("KRYON_REDACT_PAN", "true" if policy.redact_pan else "false")
    os.environ.setdefault("KRYON_DEEP_REASONING", "true" if policy.deep_reasoning else "false")
