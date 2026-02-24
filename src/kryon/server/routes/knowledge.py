"""Knowledge base API endpoints — RAG query, add, stats, and scraping."""

from __future__ import annotations

import asyncio
import json
import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from kryon.server.auth import require_api_key

router = APIRouter(tags=["knowledge"], dependencies=[Depends(require_api_key)])


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class KnowledgeQueryRequest(BaseModel):
    question: str
    top_k: int = 5
    source_filter: str | None = None
    use_llm: bool = False


class KnowledgeQueryResponse(BaseModel):
    question: str
    answer: str | None = None
    sources: list[dict] = []
    num_sources: int = 0


class KnowledgeAddRequest(BaseModel):
    content: str
    source: str
    metadata: dict | None = None


class KnowledgeAddResponse(BaseModel):
    doc_id: str
    success: bool


class KnowledgeStatsResponse(BaseModel):
    total_documents: int = 0
    sources: dict = {}
    llm_configured: bool = False
    llm_model: str = "unknown"


class ScrapeRequest(BaseModel):
    sources: list[str] = ["intelligence", "nvd"]
    nvd_days: int = 30
    nvd_count: int = 200


class ScrapeResponse(BaseModel):
    task_id: str
    status: str
    message: str


# ---------------------------------------------------------------------------
# In-memory scrape task registry
# ---------------------------------------------------------------------------

_scrape_tasks: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/knowledge/query", response_model=KnowledgeQueryResponse)
async def query_knowledge(req: KnowledgeQueryRequest) -> KnowledgeQueryResponse:
    """Query the RAG knowledge base."""
    from kryon.knowledge import query_knowledge as _query

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None,
        lambda: _query(
            question=req.question,
            top_k=req.top_k,
            source_filter=req.source_filter,
            use_llm=req.use_llm,
        ),
    )

    return KnowledgeQueryResponse(
        question=result["question"],
        answer=result.get("answer"),
        sources=result.get("sources", []),
        num_sources=len(result.get("sources", [])),
    )


@router.get("/knowledge/query/stream")
async def query_knowledge_stream(question: str, top_k: int = 5, source_filter: str | None = None):
    """Stream a RAG answer via Server-Sent Events."""
    from kryon.knowledge import get_streaming_rag_engine

    engine = get_streaming_rag_engine()

    async def _event_generator():
        full_answer = ""
        async for token in engine.query_stream(question, top_k=top_k, source_filter=source_filter):
            full_answer += token
            yield f"data: {json.dumps({'token': token})}\n\n"
        yield f"event: done\ndata: {json.dumps({'answer': full_answer})}\n\n"

    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/knowledge/add", response_model=KnowledgeAddResponse)
async def add_knowledge(req: KnowledgeAddRequest) -> KnowledgeAddResponse:
    """Add a document to the knowledge base."""
    from kryon.knowledge import add_document

    loop = asyncio.get_event_loop()
    doc_id = await loop.run_in_executor(
        None,
        lambda: add_document(content=req.content, source=req.source, **(req.metadata or {})),
    )

    return KnowledgeAddResponse(doc_id=doc_id, success=True)


@router.get("/knowledge/stats", response_model=KnowledgeStatsResponse)
async def get_knowledge_stats() -> KnowledgeStatsResponse:
    """Get knowledge base statistics."""
    from kryon.knowledge import get_knowledge_stats as _stats

    loop = asyncio.get_event_loop()
    stats = await loop.run_in_executor(None, _stats)

    return KnowledgeStatsResponse(
        total_documents=stats.get("total_knowledge_items", 0),
        sources=stats.get("sources", {}),
        llm_configured=stats.get("llm_configured", False),
        llm_model=stats.get("llm_model", "unknown"),
    )


@router.post("/knowledge/scrape", response_model=ScrapeResponse)
async def start_scrape(req: ScrapeRequest) -> ScrapeResponse:
    """Start a background scraping job."""
    task_id = str(uuid.uuid4())[:8]

    async def _run_scrape():
        from kryon.knowledge import add_document

        count = 0
        errors: list[str] = []

        if "intelligence" in req.sources:
            try:
                from kryon.knowledge.scrapers.intelligence_scraper import IntelligenceScraper

                scraper = IntelligenceScraper(max_items=200)
                items = scraper.scrape()
                for item in items:
                    add_document(
                        content=item["content"],
                        source=item["metadata"].get("source", "intelligence-feed"),
                        **item["metadata"],
                    )
                count += len(items)
            except Exception as e:
                errors.append(f"intelligence: {e}")

        if "nvd" in req.sources:
            try:
                from kryon.knowledge.scrapers.nvd_scraper import NVDScraper

                scraper = NVDScraper()
                items = scraper.scrape(days_back=req.nvd_days, max_results=req.nvd_count)
                for item in items:
                    add_document(
                        content=item["content"],
                        source=item["metadata"].get("source", "nvd"),
                        **item["metadata"],
                    )
                count += len(items)
            except Exception as e:
                errors.append(f"nvd: {e}")

        if "github" in req.sources:
            try:
                from kryon.knowledge.scrapers.github_scraper import GitHubScraper

                scraper = GitHubScraper()
                items = scraper.scrape(min_stars=50, max_results=50)
                for item in items:
                    add_document(
                        content=item["content"],
                        source=item["metadata"].get("source", "github"),
                        **item["metadata"],
                    )
                count += len(items)
            except Exception as e:
                errors.append(f"github: {e}")

        _scrape_tasks[task_id]["status"] = "completed"
        _scrape_tasks[task_id]["documents_added"] = count
        _scrape_tasks[task_id]["errors"] = errors

    _scrape_tasks[task_id] = {"status": "running", "documents_added": 0, "errors": []}
    asyncio.create_task(_run_scrape())

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
        raise HTTPException(status_code=404, detail=f"Scrape task '{task_id}' not found")
    return {"task_id": task_id, **task}
