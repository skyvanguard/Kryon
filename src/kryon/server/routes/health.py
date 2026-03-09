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

        has_ollama = os.environ.get("OLLAMA", "").lower() == "true"
        has_openai = bool(os.environ.get("OPENAI_API_KEY"))
        has_anthropic = bool(os.environ.get("ANTHROPIC_API_KEY"))

        if not (has_ollama or has_openai or has_anthropic):
            check = ReadinessCheck(status="degraded", error="No LLM provider configured")
            _llm_cache.update(check=check, ts=now)
            return check

        model = f"ollama/{os.environ.get('KRYON_MODEL', 'qwen3:8b')}" if has_ollama else "gpt-4o-mini"
        try:
            import litellm

            await litellm.acompletion(
                model=model,
                messages=[{"role": "user", "content": "ping"}],
                max_tokens=1,
                timeout=5,
            )
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
    uptime = time.monotonic() - _startup_time

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

    return ReadinessResponse(
        status=overall,
        version=__version__,
        uptime_seconds=round(uptime, 1),
        checks=checks,
    )
