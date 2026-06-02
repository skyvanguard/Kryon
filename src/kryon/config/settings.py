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
    s.model                     # "Kryon-MOE-35B" (or KRYON_MODEL)
    settings(refresh=True)      # re-read env (tests / after setenv)

`kryon config` (see cli/config_cmd.py) dumps the effective values.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class KryonSettings:
    """Immutable snapshot of Kryon's core config. Build via ``from_env()``."""

    # --- LLM / model ---
    model: str = "Kryon-MOE-35B"
    openai_base_url: str | None = None
    # Don't store the real key in __repr__/dumps — see redacted_dict().
    openai_api_key: str = "not-set"
    local_llm: bool = False
    use_litellm: bool = False  # escape hatch; default = native AsyncOpenAI model
    llm_temperature: float | None = None  # None → run-loop default (0.0 banca-safe)
    reasoning_effort: str = ""  # "" | low | medium | high

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

    # --- Paths ---
    workspace_dir: Path = field(default_factory=lambda: Path("/workspace"))
    home_dir: Path = field(default_factory=lambda: Path("~/.kryon").expanduser())

    @classmethod
    def from_env(cls) -> KryonSettings:
        return cls(
            model=os.getenv("KRYON_MODEL", "Kryon-MOE-35B"),
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
