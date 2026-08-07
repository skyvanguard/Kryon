"""KryonSettings — typed single source of truth for core runtime config.

Reads ``KRYON_*`` / ``OPENAI_*`` env vars ONCE with documented defaults that
match the values previously scattered across the codebase. Scope is the CORE
config (model, LLM endpoint, agent, execution profile, paths, timeouts) — the
high-drift surface. Feature-specific flags (per-tool fire gates, nmap timing,
etc.) stay where they're read; this module is for the values that were
duplicated and prone to divergence.

Usage:
    from kryon.config import settings
    s = settings()              # cached, reads env once
    s.model                     # "kryon-local" (or KRYON_MODEL)
    settings(refresh=True)      # re-read env (tests / after setenv)

`kryon config` (see cli/config_cmd.py) dumps the effective values.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

# Canonical parsers (this module existed to END env-parse duplication — so it
# must not re-roll its own; delegate to util.env, the single source of truth).
from kryon.util.env import env_bool as _env_bool, env_float as _env_float, env_int as _env_int

# Historical fallback for unknown models. Kept so the 200k default that
# ``_get_model_max_tokens`` used before this resolver existed is preserved for
# any model we don't recognize.
_DEFAULT_MODEL_MAX_TOKENS = 200_000

# Best-effort context-window map, matched by case-insensitive substring on the
# model / alias name. Only REAL model names go here — NOT neutral aliases like
# ``kryon-local``: over-estimating a swapped-in small model's context is
# dangerous (the auto-compact threshold would land past the server's real
# limit, so the provider rejects the request before compaction ever fires).
# For aliases, set ``KRYON_MODEL_MAX_TOKENS`` explicitly (it always wins).
_KNOWN_MODEL_CONTEXT: tuple[tuple[str, int], ...] = (
    # DeepSeek V4 Flash — the active model. 1M context window.
    ("deepseek-v4-flash", 1_000_000),
    ("v4-flash", 1_000_000),
    ("v4flash", 1_000_000),
    ("deepseek-v4", 1_000_000),
    # DeepSeek remote chat / reasoner — 128K.
    ("deepseek-reasoner", 128_000),
    ("deepseek-chat", 128_000),
    # Local GGUF swap-tests (see docker compose comments).
    ("jan-nano", 32_768),
    ("devstral", 128_000),
)


def resolve_model_max_tokens(model_name: str | None, env_override: str | None = None) -> int:
    """Context-window size (input tokens) for a model, best-effort.

    Precedence: explicit ``env_override`` (``KRYON_MODEL_MAX_TOKENS``) >
    known-model substring map > ``_DEFAULT_MODEL_MAX_TOKENS``. Always returns a
    positive int. A malformed / non-positive override is ignored (falls through).
    """
    if env_override and env_override.strip():
        try:
            v = int(env_override.strip())
            if v > 0:
                return v
        except ValueError:
            pass
    low = (model_name or "").lower()
    for fragment, ctx in _KNOWN_MODEL_CONTEXT:
        if fragment in low:
            return ctx
    return _DEFAULT_MODEL_MAX_TOKENS


# Prompt/reflection context sizing. Many fixed truncations (the reflective loop's
# observation preview, injected ground-truth evidence, hunter prompt clamps) were
# calibrated to the 4B-local's tight window; on a large window (V4 Flash 1M) they
# starve the model of context it can easily hold — worst in the reflective loop
# that DRIVES the model. Scale those 4B-era defaults up on a large window.
_LARGE_WINDOW_TOKENS = 500_000
_LARGE_WINDOW_CONTEXT_MULTIPLIER = 8


def resolve_context_budget(small_default: int, model_max_tokens: int | None = None) -> int:
    """Scale a 4B-era fixed prompt/reflection char budget to the model's window.

    Small/medium windows keep ``small_default`` (banca-safe for the 4B-local); a
    large window (>=500k, e.g. V4 Flash 1M) multiplies it so the reflective loop /
    injected ground-truth isn't truncated to a fraction of what the model holds.
    Mirrors resolve_tool_result_cap / resolve_micro_compact_budget.
    """
    if model_max_tokens is None:
        try:
            model_max_tokens = settings().model_max_tokens
        except Exception:  # noqa: BLE001 — config must never break the prompt path
            model_max_tokens = _DEFAULT_MODEL_MAX_TOKENS
    # Capable model OR ≥500K window → lift the 4B-era budget so the reflective loop /
    # injected ground-truth isn't starved. A capable reasoner on a 64K DSpark window
    # (<500K) still needs the lift; a weak 4B on a 128K window does not.
    try:
        from kryon.util.env import is_capable_model  # noqa: PLC0415

        capable = is_capable_model()
    except Exception:  # noqa: BLE001 — config must never break the prompt path
        capable = False
    if capable or model_max_tokens >= _LARGE_WINDOW_TOKENS:
        return small_default * _LARGE_WINDOW_CONTEXT_MULTIPLIER
    return small_default


@dataclass(frozen=True)
class KryonSettings:
    """Immutable snapshot of Kryon's core config. Build via ``from_env()``."""

    # --- LLM / model ---
    model: str = "kryon-local"
    openai_base_url: str | None = None
    # Don't store the real key in __repr__/dumps — see redacted_dict().
    openai_api_key: str = "not-set"
    local_llm: bool = False
    use_litellm: bool = False  # escape hatch; default = native AsyncOpenAI model
    llm_temperature: float | None = None  # None → run-loop default (0.0 banca-safe)
    reasoning_effort: str = ""  # "" | low | medium | high
    # Context-window management (drives the auto-compact threshold).
    model_max_tokens: int = _DEFAULT_MODEL_MAX_TOKENS
    auto_compact: bool = True
    auto_compact_threshold: float = 0.8  # compact when input tokens exceed this fraction

    # --- Agent / execution ---
    agent_type: str = "kryon"
    unified: bool = True
    max_turns: int = 50
    guardrails: bool = True
    red_team: bool = False
    stream: bool = False
    debug: int = 0
    price_limit: float = float("inf")

    # --- Timeouts (seconds) ---
    wall_budget_s: float = 0.0  # 0 = unbounded
    chunk_timeout_s: float = 180.0
    prehook_total_timeout_s: float = 180.0
    deterministic_timeout_s: float = 120.0
    http_timeout_s: float = 600.0  # AsyncOpenAI read/total timeout; SDK default is 600s.
    # A slow local reasoner (V4-Flash) needs a big prompt prefill (~18min at
    # ~18 tok/s for a 20K-token prompt) — the 600s default cancels the request
    # mid-prefill. Raise via KRYON_HTTP_TIMEOUT_S for local-LLM runs.

    # --- Paths ---
    workspace_dir: Path = field(default_factory=lambda: Path("/workspace"))
    home_dir: Path = field(default_factory=lambda: Path("~/.kryon").expanduser())

    @classmethod
    def from_env(cls) -> KryonSettings:
        return cls(
            model=os.getenv("KRYON_MODEL", "kryon-local"),
            openai_base_url=os.getenv("OPENAI_BASE_URL") or None,
            openai_api_key=os.getenv("OPENAI_API_KEY", "not-set"),
            local_llm=_env_bool("KRYON_LOCAL_LLM", False),
            use_litellm=_env_bool("KRYON_USE_LITELLM", False),
            llm_temperature=(
                _env_float("KRYON_LLM_TEMPERATURE", float("nan"))
                if os.environ.get("KRYON_LLM_TEMPERATURE", "").strip()
                else None
            ),
            reasoning_effort=os.getenv("KRYON_REASONING_EFFORT", "").strip().lower(),
            model_max_tokens=resolve_model_max_tokens(
                os.getenv("KRYON_MODEL", "kryon-local"),
                os.getenv("KRYON_MODEL_MAX_TOKENS"),
            ),
            auto_compact=_env_bool("KRYON_AUTO_COMPACT", True),
            auto_compact_threshold=_env_float("KRYON_AUTO_COMPACT_THRESHOLD", 0.8),
            agent_type=os.getenv("KRYON_AGENT_TYPE", "kryon"),
            unified=_env_bool("KRYON_UNIFIED", True),
            max_turns=_env_int("KRYON_MAX_TURNS", 50),
            guardrails=_env_bool("KRYON_GUARDRAILS", True),
            red_team=_env_bool("KRYON_RED_TEAM", False),
            stream=_env_bool("KRYON_STREAM", False),
            debug=_env_int("KRYON_DEBUG", 0),
            price_limit=_env_float("KRYON_PRICE_LIMIT", float("inf")),
            wall_budget_s=_env_float("KRYON_WALL_BUDGET_S", 0.0),
            chunk_timeout_s=_env_float("KRYON_CHUNK_TIMEOUT_S", 180.0),
            prehook_total_timeout_s=_env_float("KRYON_PREHOOK_TOTAL_TIMEOUT_S", 180.0),
            deterministic_timeout_s=_env_float("KRYON_DETERMINISTIC_TIMEOUT_S", 120.0),
            http_timeout_s=_env_float("KRYON_HTTP_TIMEOUT_S", 600.0),
            workspace_dir=Path(os.getenv("KRYON_WORKSPACE_DIR", "/workspace")),
            home_dir=Path(os.getenv("KRYON_HOME", "~/.kryon")).expanduser(),
        )

    def redacted_dict(self) -> dict[str, Any]:
        """All fields as a dict, with the API key masked — safe to print/log."""
        out: dict[str, Any] = {}
        for f in fields(self):
            val = getattr(self, f.name)
            if f.name == "openai_api_key":
                val = "***set***" if val and val != "not-set" else val
            out[f.name] = str(val) if isinstance(val, Path) else val
        return out


_CACHED: KryonSettings | None = None


def settings(refresh: bool = False) -> KryonSettings:
    """Return the cached settings, reading the environment on first call.

    ``refresh=True`` re-reads the env (use in tests after monkeypatching, or
    after the CLI mutates env vars before the agent runs)."""
    global _CACHED
    if _CACHED is None or refresh:
        _CACHED = KryonSettings.from_env()
    return _CACHED
