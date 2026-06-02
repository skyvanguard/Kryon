"""Run execution and SSE streaming endpoints."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException

from kryon.sdk.agents.run_outcome import classify_run_exception
from kryon.server.auth import require_api_key
from kryon.server.exceptions import not_found
from kryon.server.logging_config import get_logger
from kryon.server.models import RunRequest, RunResponse, RunStatus, SessionCreateRequest, SessionResponse
from kryon.server.sessions import SessionManager
from kryon.server.sse import sse_response
from kryon.server.streaming import done_event, error_event, stream_event_to_sse

logger = get_logger(__name__)

router = APIRouter(tags=["runs"], dependencies=[Depends(require_api_key)])

# Injected by app.py at startup
_session_manager: SessionManager | None = None


def set_session_manager(sm: SessionManager) -> None:
    global _session_manager
    _session_manager = sm


def _get_sm() -> SessionManager:
    if _session_manager is None:
        raise RuntimeError("SessionManager not initialized")
    return _session_manager


@router.post("/runs", response_model=RunResponse)
async def create_run(req: RunRequest):
    """Execute an agent run (sync or start streaming)."""
    sm = _get_sm()

    # Resolve agent
    from kryon.agents import get_agent_by_name

    try:
        agent = get_agent_by_name(req.agent_key)
    except ValueError as e:
        logger.warning("Agent not found: %s — %s", req.agent_key, e)
        raise HTTPException(status_code=404, detail="Agent not found")

    # Build input history from session if provided
    input_items: str | list = req.input
    session = None
    if req.session_id:
        session = sm.get_session(req.session_id)
        if session is None:
            raise not_found("Session", req.session_id)
        agent = session.agent
        # Build conversation history
        if session.input_history:
            input_items = session.input_history + [
                {"role": "user", "content": req.input},
            ]

    run_state = sm.create_run(req.agent_key, session_id=req.session_id)
    logger.info("Run created: agent=%s stream=%s", req.agent_key, req.stream)

    if req.stream:
        # Return run_id immediately; client connects to /runs/{id}/stream
        run_state.status = "pending_stream"

        async def _run_streamed():
            from kryon.sdk.agents import Runner
            from kryon.sdk.agents.run_config_factory import get_run_config

            try:
                async with sm.semaphore:
                    result = Runner.run_streamed(
                        agent, input=input_items, max_turns=req.max_turns, run_config=get_run_config()
                    )
                    async for event in result.stream_events():
                        sse = stream_event_to_sse(event)
                        if sse:
                            run_state.events.append({"sse": sse})
                    run_state.output = result.final_output or ""
                    run_state.agent_name = result.last_agent.name if result.last_agent else ""
                    run_state.status = "completed"
                    # Update session history
                    if session is not None:
                        session.input_history = list(result.to_input_list())
            except asyncio.CancelledError:
                run_state.status = "cancelled"
            except Exception as exc:
                outcome = classify_run_exception(exc)
                if outcome is None:
                    logger.error("Agent execution failed: %s", exc, exc_info=True)
                    run_state.status = "failed"
                    run_state.output = "Agent execution failed"
                else:
                    # Graceful early stop (stuck / max-turns / budget): deliver
                    # the partial note, not a hard failure — mirrors the CLI.
                    logger.warning("Agent stream ended early (%s): %s", outcome.status, exc)
                    run_state.status = outcome.status
                    run_state.output = outcome.message

        run_state.task = asyncio.create_task(_run_streamed())

        return RunResponse(
            run_id=run_state.run_id,
            status="streaming",
            output="",
            agent=req.agent_key,
        )

    # Synchronous (non-streaming) run
    from kryon.sdk.agents import Runner
    from kryon.sdk.agents.run_config_factory import get_run_config

    try:
        async with sm.semaphore:
            result = await Runner.run(agent, input=input_items, max_turns=req.max_turns, run_config=get_run_config())
    except Exception as exc:
        outcome = classify_run_exception(exc)
        if outcome is None:
            # Genuine crash — keep the opaque 500 (don't leak internals).
            run_state.status = "failed"
            run_state.output = "Agent execution failed"
            logger.exception("Agent run failed: run_id=%s agent=%s", run_state.run_id, req.agent_key)
            raise HTTPException(status_code=500, detail="Agent run failed due to an internal error") from exc
        # Graceful early stop (stuck / max-turns / budget) is NOT a server
        # error. Return 200 with a structured partial status, mirroring the
        # CLI investigate / reflective-runner partial-report behaviour.
        logger.warning(
            "Agent run ended early (%s): run_id=%s agent=%s",
            outcome.status,
            run_state.run_id,
            req.agent_key,
        )
        run_state.status = outcome.status
        run_state.output = outcome.message
        return RunResponse(
            run_id=run_state.run_id,
            status=outcome.status,
            output=outcome.message,
            agent=req.agent_key,
        )

    run_state.status = "completed"
    output = result.final_output or ""
    run_state.output = output
    run_state.agent_name = result.last_agent.name if result.last_agent else ""

    # Update session history
    if session is not None:
        session.input_history = list(result.to_input_list())

    usage_data = {}
    if result.raw_responses:
        last_usage = result.raw_responses[-1].usage
        if last_usage:
            usage_data["total_tokens"] = last_usage.total_tokens

    return RunResponse(
        run_id=run_state.run_id,
        status="completed",
        output=output,
        agent=run_state.agent_name,
        usage=usage_data,
    )


@router.get("/runs/{run_id}/stream")
async def stream_run(run_id: str):
    """SSE stream of events for a running agent execution."""
    sm = _get_sm()
    run = sm.get_run(run_id)
    if run is None:
        raise not_found("Run", run_id)

    async def _event_generator():
        idx = 0
        while True:
            # Yield any buffered events
            while idx < len(run.events):
                yield run.events[idx]["sse"]
                idx += 1

            # "stuck" / "incomplete" / "budget_exceeded" are graceful partial
            # stops — terminal, but delivered as a normal done-event carrying
            # the partial note (not an error). Without them here the stream
            # would loop forever waiting for a status that never comes.
            if run.status in ("completed", "failed", "cancelled", "stuck", "incomplete", "budget_exceeded"):
                if run.status == "failed":
                    yield error_event(run.output)
                else:
                    yield done_event(run.output)
                break

            await asyncio.sleep(0.05)

    return sse_response(_event_generator())


@router.get("/runs/{run_id}", response_model=RunStatus)
async def get_run_status(run_id: str):
    """Get the current status of a run."""
    sm = _get_sm()
    run = sm.get_run(run_id)
    if run is None:
        raise not_found("Run", run_id)
    return RunStatus(
        run_id=run.run_id,
        status=run.status,
        agent=run.agent_name or None,
        output=run.output if run.status != "running" else None,
    )


@router.delete("/runs/{run_id}")
async def cancel_run(run_id: str):
    """Cancel a running execution."""
    sm = _get_sm()
    if not sm.cancel_run(run_id):
        logger.warning("Run not found for cancel: %s", run_id)
        raise not_found("Run", run_id)
    logger.info("Run cancelled: %s", run_id)
    return {"status": "cancelled", "run_id": run_id}


# --- Sessions ---


@router.post("/sessions", response_model=SessionResponse)
async def create_session(req: SessionCreateRequest):
    """Create a new conversation session with an agent."""
    sm = _get_sm()
    from kryon.agents import get_agent_by_name

    try:
        agent = get_agent_by_name(req.agent_key)
    except ValueError as e:
        logger.warning("Agent not found: %s — %s", req.agent_key, e)
        raise HTTPException(status_code=404, detail="Agent not found")

    session = sm.create_session(req.agent_key, agent)
    logger.info("Session created: agent=%s session_id=%s", req.agent_key, session.session_id)
    return SessionResponse(
        session_id=session.session_id,
        agent_key=session.agent_key,
        created_at=session.created_at,
        message_count=0,
    )


@router.get("/sessions", response_model=list[SessionResponse])
async def list_sessions():
    """List all active sessions."""
    sm = _get_sm()
    return [
        SessionResponse(
            session_id=s.session_id,
            agent_key=s.agent_key,
            created_at=s.created_at,
            message_count=len(s.messages),
        )
        for s in sm.list_sessions()
    ]
