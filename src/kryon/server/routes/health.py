"""Health check endpoints."""

from __future__ import annotations

import time

from fastapi import APIRouter

from kryon.server.models import HealthResponse, ReadinessCheck, ReadinessResponse

router = APIRouter(tags=["health"])

_startup_time = time.monotonic()


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Basic health check — fast, no external dependencies."""
    from kryon.agents import get_available_agents

    agents = get_available_agents()
    return HealthResponse(
        status="ok",
        version="1.0.0",
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
        row = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
        version = row["version"] if row else 0
        checks["database"] = ReadinessCheck(status="healthy", error=None)
    except Exception as exc:
        checks["database"] = ReadinessCheck(status="unhealthy", error=str(exc))

    # RAG / Knowledge Base check
    try:
        from kryon.knowledge.engines.rag_engine import RAGEngine

        engine = RAGEngine()
        stats = engine.get_stats()
        doc_count = stats.get("total_documents", 0)
        checks["knowledge_base"] = ReadinessCheck(
            status="healthy" if doc_count > 0 else "degraded",
            error=None if doc_count > 0 else "No documents in knowledge base",
        )
    except ImportError:
        checks["knowledge_base"] = ReadinessCheck(status="skipped", error="RAG not installed")
    except Exception as exc:
        checks["knowledge_base"] = ReadinessCheck(status="unhealthy", error=str(exc))

    # AI provider check
    try:
        import os

        has_openai = bool(os.environ.get("OPENAI_API_KEY"))
        has_anthropic = bool(os.environ.get("ANTHROPIC_API_KEY"))
        if has_openai or has_anthropic:
            provider = "openai" if has_openai else "anthropic"
            checks["ai_provider"] = ReadinessCheck(status="healthy", error=None)
        else:
            checks["ai_provider"] = ReadinessCheck(
                status="degraded", error="No AI API key configured"
            )
    except Exception as exc:
        checks["ai_provider"] = ReadinessCheck(status="unhealthy", error=str(exc))

    overall = "healthy"
    for c in checks.values():
        if c.status == "unhealthy":
            overall = "unhealthy"
            break
        if c.status == "degraded":
            overall = "degraded"

    return ReadinessResponse(
        status=overall,
        version="1.0.0",
        uptime_seconds=round(uptime, 1),
        checks=checks,
    )
