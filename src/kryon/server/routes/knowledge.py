"""Knowledge base API endpoints — RAG query, add, stats, and scraping."""

from __future__ import annotations

import asyncio
import json
import uuid

from fastapi import APIRouter, Depends, Query

from kryon.server.auth import require_api_key
from kryon.server.exceptions import not_found
from kryon.server.logging_config import get_logger
from kryon.server.models import (
    KnowledgeAddRequest,
    KnowledgeAddResponse,
    KnowledgeQueryRequest,
    KnowledgeQueryResponse,
    KnowledgeStatsResponse,
    ScrapeRequest,
    ScrapeResponse,
)
from kryon.server.sse import sse_response

logger = get_logger(__name__)

router = APIRouter(tags=["knowledge"], dependencies=[Depends(require_api_key)])


# ---------------------------------------------------------------------------
# In-memory scrape task registry (protected by asyncio.Lock)
# ---------------------------------------------------------------------------

_scrape_tasks: dict[str, dict] = {}
_scrape_tasks_lock = asyncio.Lock()
_SCRAPE_TASKS_MAX = 50


async def _cleanup_completed_scrapes() -> None:
    """Remove completed scrape entries when the registry grows too large."""
    if len(_scrape_tasks) <= _SCRAPE_TASKS_MAX:
        return
    done = [tid for tid, t in _scrape_tasks.items() if t["status"] != "running"]
    for tid in done:
        _scrape_tasks.pop(tid, None)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/knowledge/query", response_model=KnowledgeQueryResponse)
async def query_knowledge(req: KnowledgeQueryRequest) -> KnowledgeQueryResponse:
    """Query the RAG knowledge base."""
    from kryon.knowledge import query_knowledge as _query

    result = await asyncio.to_thread(
        _query,
        question=req.question,
        top_k=req.top_k,
        source_filter=req.source_filter,
        use_llm=req.use_llm,
    )

    return KnowledgeQueryResponse(
        question=result["question"],
        answer=result.get("answer"),
        sources=result.get("sources", []),
        num_sources=len(result.get("sources", [])),
    )


@router.get("/knowledge/query/stream")
async def query_knowledge_stream(
    question: str = Query(..., min_length=1, max_length=2000),
    top_k: int = Query(5, ge=1, le=50),
    source_filter: str | None = None,
):
    """Stream a RAG answer via Server-Sent Events."""
    from kryon.knowledge import get_streaming_rag_engine

    engine = get_streaming_rag_engine()

    async def _event_generator():
        full_answer = ""
        async for token in engine.query_stream(question, top_k=top_k, source_filter=source_filter):
            full_answer += token
            yield f"data: {json.dumps({'token': token})}\n\n"
        yield f"event: done\ndata: {json.dumps({'answer': full_answer})}\n\n"

    return sse_response(_event_generator())


@router.post("/knowledge/add", response_model=KnowledgeAddResponse)
async def add_knowledge(req: KnowledgeAddRequest) -> KnowledgeAddResponse:
    """Add a document to the knowledge base."""
    from kryon.knowledge import add_document

    doc_id = await asyncio.to_thread(add_document, content=req.content, source=req.source, **(req.metadata or {}))

    logger.info("Knowledge document added: source=%s", req.source)
    return KnowledgeAddResponse(doc_id=doc_id, success=True)


@router.get("/knowledge/stats", response_model=KnowledgeStatsResponse)
async def get_knowledge_stats() -> KnowledgeStatsResponse:
    """Get knowledge base statistics."""
    from kryon.knowledge import get_knowledge_stats as _stats

    stats = await asyncio.to_thread(_stats)

    return KnowledgeStatsResponse(
        total_documents=stats.get("total_knowledge_items", 0),
        sources=stats.get("sources", {}),
        llm_configured=stats.get("llm_configured", False),
        llm_model=stats.get("llm_model", "unknown"),
    )


@router.post("/knowledge/scrape", response_model=ScrapeResponse)
async def start_scrape(req: ScrapeRequest) -> ScrapeResponse:
    """Start a background scraping job."""
    async with _scrape_tasks_lock:
        await _cleanup_completed_scrapes()
        task_id = str(uuid.uuid4())[:8]
        _scrape_tasks[task_id] = {"status": "running", "documents_added": 0, "errors": []}

    async def _run_scrape():
        from kryon.knowledge import add_document
        from kryon.knowledge.scrapers import SCRAPER_REGISTRY

        count = 0
        errors: list[str] = []

        for source in req.sources:
            if source not in SCRAPER_REGISTRY:
                errors.append(f"{source}: unknown source (available: {list(SCRAPER_REGISTRY.keys())})")
                continue

            try:
                scraper_cls = SCRAPER_REGISTRY[source]
                scraper = scraper_cls()
                items = await asyncio.to_thread(scraper.scrape, max_results=req.nvd_count)
                for item in items:
                    await asyncio.to_thread(
                        add_document,
                        content=item["content"],
                        source=item["metadata"].get("source", source),
                        **item["metadata"],
                    )
                count += len(items)
            except Exception as e:
                errors.append(f"{source}: {e}")

        async with _scrape_tasks_lock:
            _scrape_tasks[task_id]["status"] = "completed"
            _scrape_tasks[task_id]["documents_added"] = count
            _scrape_tasks[task_id]["errors"] = errors

    asyncio.create_task(_run_scrape())

    logger.info("Scrape task started: id=%s sources=%s", task_id, req.sources)
    return ScrapeResponse(
        task_id=task_id,
        status="started",
        message=f"Scraping started for sources: {', '.join(req.sources)}",
    )


@router.get("/knowledge/scrape/{task_id}")
async def get_scrape_status(task_id: str) -> dict:
    """Get status of a scraping task."""
    task = _scrape_tasks.get(task_id)
    if not task:
        logger.warning("Scrape task not found: %s", task_id)
        raise not_found("Scrape task", task_id)
    return {"task_id": task_id, **task}
