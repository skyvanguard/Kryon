"""Canonical env-var parsing helpers (single source of truth).

El idiom truthy ``os.environ.get(name, ...).strip().lower() in {"1","true",
"yes","on"}`` estaba reimplementado en ~17 sitios (varios como ``_env_bool``
local idéntico) con defaults inconsistentes. Centralizado acá.
"""

from __future__ import annotations

import os

_TRUTHY = frozenset({"1", "true", "yes", "on"})


def env_bool(name: str, default: bool = False) -> bool:
    """True si la env var ``name`` está seteada a un valor truthy
    (``1``/``true``/``yes``/``on``, case-insensitive). ``default`` si está
    ausente o vacía."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in _TRUTHY


def env_int(name: str, default: int) -> int:
    """Int env var, or ``default`` if absent/empty/unparseable."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def env_float(name: str, default: float) -> float:
    """Float env var, or ``default`` if absent/empty/unparseable."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def is_red_team() -> bool:
    """Single source of truth for the KRYON_RED_TEAM offensive gate. Use this
    everywhere instead of re-parsing the env var — the ad-hoc variants
    (``in ("1","true","yes")`` without ``on``, with/without ``.strip()``) caused
    a 'half-open' gate where ``KRYON_RED_TEAM=on`` enabled some active modules
    but not others."""
    return env_bool("KRYON_RED_TEAM")


def is_capable_model() -> bool:
    """KRYON_CAPABLE_MODEL — the operator is running a frontier/large model (e.g.
    DeepSeek-V4-Flash 284B) that can DRIVE the kill-chain, not just narrate the
    deterministic engine.

    Default OFF preserves the 4B-local behavior (banca-safe): the harness IMPOSES —
    hard planner directives, autoexec, 5-turn phase caps, greedy temp, drop-on-doubt
    finding gates. When ON, those degrade from IMPOSE to SUGGEST so the capable model
    leads and determinism is a safety net, not a ceiling.

    Deliberately SEPARATE from :func:`is_reasoning_model`: that marker also activates
    require_grounding + adversarial_strict (which over-filter findings). Capability
    and reasoning-class are different axes — a capable model needs a raised turn
    budget WITHOUT the strict grounding gates."""
    return env_bool("KRYON_CAPABLE_MODEL")


def preserve_reasoning() -> bool:
    """KRYON_PRESERVE_REASONING — on a reasoning-only stop (the model concluded in
    ``reasoning_content`` with empty ``content``), promote that reasoning to
    ``content`` so the answer survives into the report + the persisted session
    history, EVEN when not in the full capable regime.

    Why it's separate from :func:`is_capable_model`: a large local reasoning model
    (e.g. qwen-unc / Qwen3.5-122B) is often run in the fast non-capable regime for
    latency, but its reasoning is signal, not the 4B's junk-imitation. Without this,
    its reasoning-only turns lose the answer entirely (empty final_output → the turn,
    and a resumed session, remember the question but not the reply). Default OFF
    preserves the 4B-local behavior (reasoning-only stops are force-retried into a
    tool_call, never promoted — promoting 4B junk poisons the history)."""
    return env_bool("KRYON_PRESERVE_REASONING")


def force_tool_turns() -> int:
    """How many of the first LLM calls per turn are forced to tool_choice="required".

    8 for the 4B-local (which won't reliably call tools on its own); **0 for a capable
    model** (KRYON_CAPABLE_MODEL) — it has agency and drives tools when there IS
    something to act on, so forcing even one tool_call per turn is the "IMPOSE" the
    capable regime rejects (it made trivial or no-target requests fire spurious tools
    and ignore an explicit "no tools"). A capable model that stalls is caught by the
    reasoning-only-stop recovery, and real engagements get their tool work from the
    deterministic pre_hooks — neither needs this blind head-start. Set
    ``KRYON_FORCE_TOOL_TURNS`` to re-impose a nudge (e.g. 1) when a specific run wants
    it; the override wins over either default."""
    default = 0 if is_capable_model() else 8
    return env_int("KRYON_FORCE_TOOL_TURNS", default)


def is_local_llm() -> bool:
    """Single source of truth for the KRYON_LOCAL_LLM gate (local OpenAI-compat
    endpoint → robust parsers + usage patch). ``OLLAMA`` is a deprecated alias.

    Same half-open-gate class as :func:`is_red_team`: the four ad-hoc readers
    diverged (some omit ``on``, one did ``getenv(...) or getenv("OLLAMA")`` so
    ANY non-empty value — even ``KRYON_LOCAL_LLM=0`` — read as ON). Route all of
    them here so the flag means one thing."""
    return env_bool("KRYON_LOCAL_LLM") or env_bool("OLLAMA")


def anon_proxy() -> str | None:
    """Proxy (SOCKS5/HTTP) through which OUTBOUND recon traffic must be routed for
    anonymized engagements — Tor, a VPN, or a redirector. Returns the proxy URL
    (e.g. ``socks5://127.0.0.1:9050``) or ``None`` when unset.

    OPSEC-critical: Go recon binaries (ffuf, nuclei, subfinder, gobuster) issue
    raw syscalls instead of libc ``connect()``, so they BYPASS torsocks — wrapping
    the agent in torsocks does NOT anonymize them. A live run leaked the host's
    real IP through ffuf for exactly this reason. When this is set, every Go tool
    command builder MUST inject its native proxy flag (ffuf ``-x``, nuclei/subfinder
    ``-proxy``, gobuster ``--proxy``) so the tool routes through the proxy itself.

    ``KRYON_ANON_PROXY`` is the canonical name; ``KRYON_SOCKS_PROXY`` is an alias.
    """
    raw = (os.environ.get("KRYON_ANON_PROXY") or os.environ.get("KRYON_SOCKS_PROXY") or "").strip()
    return raw or None


def is_demo_mode() -> bool:
    """KRYON_DEMO_MODE — legacy presentation gate. The clean operator-terminal
    narration is now the DEFAULT (see :func:`is_verbose`), so this flag is a
    no-op kept for backward compatibility. Purely cosmetic."""
    return env_bool("KRYON_DEMO_MODE")


def is_verbose() -> bool:
    """KRYON_VERBOSE (or KRYON_DEBUG=2) — show the internal scaffolding labels
    (matched skill names, ``pre-hook`` tool paths + timeouts). OFF by default:
    the UI stays clean/product-grade out of the box, so a demo or a real
    install needs no flag to look right. Verbose is opt-in for debugging."""
    import os

    return env_bool("KRYON_VERBOSE") or os.environ.get("KRYON_DEBUG", "").strip() == "2"
