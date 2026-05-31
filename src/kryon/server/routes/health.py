"""Health check endpoints."""

from __future__ import annotations

import asyncio
import os
import time

from fastapi import APIRouter

from kryon import __version__
from kryon.server.logging_config import get_logger
from kryon.server.models import HealthResponse, ReadinessCheck, ReadinessResponse

logger = get_logger(__name__)

router = APIRouter(tags=["health"])

_startup_time = time.monotonic()

# LLM health cache (TTL 30s, protected by asyncio.Lock to prevent thundering herd)
_llm_cache: dict[str, object] = {"check": None, "ts": 0.0}
_llm_cache_lock = asyncio.Lock()
_LLM_CACHE_TTL = 30.0


async def _ping_llm() -> ReadinessCheck:
    """Ping LLM provider with a minimal completion. Cached for 30s."""
    now = time.monotonic()
    if _llm_cache["check"] is not None and (now - _llm_cache["ts"]) < _LLM_CACHE_TTL:  # type: ignore[operator]
        return _llm_cache["check"]  # type: ignore[return-value]

    async with _llm_cache_lock:
        # Double-check after acquiring lock
        now = time.monotonic()
        if _llm_cache["check"] is not None and (now - _llm_cache["ts"]) < _LLM_CACHE_TTL:  # type: ignore[operator]
            return _llm_cache["check"]  # type: ignore[return-value]

        base_url = os.environ.get("OPENAI_BASE_URL", "").strip()
        # OLLAMA=true now means "local OpenAI-compatible endpoint" (llama-server
        # or Ollama's /v1 shim) — both are reached via base_url, NOT litellm's
        # native ollama/ provider (which talks /api/chat and breaks llama-server).
        has_local = os.environ.get("OLLAMA", "").lower() == "true" or bool(base_url)
        has_openai = bool(os.environ.get("OPENAI_API_KEY"))
        has_anthropic = bool(os.environ.get("ANTHROPIC_API_KEY"))

        if not (has_local or has_openai or has_anthropic):
            check = ReadinessCheck(status="degraded", error="No LLM provider configured")
            _llm_cache.update(check=check, ts=now)
            return check

        kwargs: dict[str, object] = {
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 1,
            "timeout": 5,
        }
        if base_url:
            # Generic OpenAI-compatible endpoint (llama-server / Ollama /v1 / DeepSeek).
            kwargs["model"] = f"openai/{os.environ.get('KRYON_MODEL', 'Kryon-MOE-35B')}"
            kwargs["api_base"] = base_url
            kwargs["api_key"] = os.environ.get("OPENAI_API_KEY", "llama")
        else:
            kwargs["model"] = "gpt-4o-mini"
        try:
            import litellm

            await litellm.acompletion(**kwargs)
            check = ReadinessCheck(status="healthy", error=None)
        except Exception as exc:
            check = ReadinessCheck(status="degraded", error=f"LLM ping failed: {exc}")

        _llm_cache.update(check=check, ts=now)
        return check


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Basic health check — fast, no external dependencies."""
    from kryon.agents import get_available_agents

    agents = get_available_agents()
    return HealthResponse(
        status="ok",
        version=__version__,
        agents_count=len(agents),
    )


@router.get("/health/ready", response_model=ReadinessResponse)
async def readiness_check() -> ReadinessResponse:
    """Readiness check — validates database, RAG, and AI provider subsystems."""
    checks: dict[str, ReadinessCheck] = {}

    # Database check
    try:
        from kryon.memory.store import MemoryStore

        store = MemoryStore()
        conn = store._get_conn()
        conn.execute("SELECT 1")
        checks["database"] = ReadinessCheck(status="healthy", error=None)
    except Exception:
        checks["database"] = ReadinessCheck(status="unhealthy", error="Database unavailable")

    # RAG / Knowledge Base check
    try:
        from kryon.knowledge.engines.rag_engine import RAGEngine

        engine = RAGEngine()
        stats = engine.get_stats()
        doc_count = stats.get("total_documents", 0)
        checks["knowledge_base"] = ReadinessCheck(
            status="healthy" if doc_count > 0 else "degraded",
            error=None if doc_count > 0 else "Knowledge base empty",
        )
    except ImportError:
        checks["knowledge_base"] = ReadinessCheck(status="skipped", error="Not installed")
    except Exception:
        checks["knowledge_base"] = ReadinessCheck(status="unhealthy", error="Unavailable")

    # AI / LLM provider check (with active ping, cached 30s)
    checks["ai_provider"] = await _ping_llm()

    overall = "healthy"
    for c in checks.values():
        if c.status == "unhealthy":
            overall = "unhealthy"
            break
        if c.status == "degraded":
            overall = "degraded"

    # Sanitize check errors to avoid leaking provider/model details
    sanitized_checks = {}
    for name, c in checks.items():
        sanitized_checks[name] = ReadinessCheck(
            status=c.status,
            error=c.status if c.status != "healthy" else None,
        )

    return ReadinessResponse(
        status=overall,
        version=__version__,
        checks=sanitized_checks,
    )
