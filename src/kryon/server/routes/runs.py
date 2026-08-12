"""Run execution and SSE streaming endpoints."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException

from kryon.sdk.agents.run_outcome import classify_run_exception
from kryon.server.auth import require_api_key
from kryon.server.auth.deps import get_current_user
from kryon.server.auth.models import User
from kryon.server.exceptions import not_found
from kryon.server.logging_config import get_logger
from kryon.server.models import RunRequest, RunResponse, RunStatus, SessionCreateRequest, SessionResponse
from kryon.server.sessions import SessionManager
from kryon.server.sse import sse_response
from kryon.server.streaming import done_event, error_event, stream_event_to_sse
from kryon.services.history_sanitize import ensure_final_assistant, sanitize_history_for_persist

logger = get_logger(__name__)

router = APIRouter(tags=["runs"], dependencies=[Depends(require_api_key)])

# Injected by app.py at startup
_session_manager: SessionManager | None = None


def set_session_manager(sm: SessionManager) -> None:
    global _session_manager
    _session_manager = sm


def _owns(user: User | None, owner_user_id: str | None) -> bool:
    """Ownership check that preserves single-tenant API-key mode. Allows when there
    is no JWT user (API-key-only deployment) or the resource has no owner; in a
    multi-user setup an admin sees all, others only their own."""
    if user is None or owner_user_id is None:
        return True
    if getattr(user, "role", "") == "admin":
        return True
    return user.id == owner_user_id


def _get_sm() -> SessionManager:
    if _session_manager is None:
        raise RuntimeError("SessionManager not initialized")
    return _session_manager


@router.post("/runs", response_model=RunResponse)
async def create_run(req: RunRequest, user: User | None = Depends(get_current_user)):
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
        # Ownership: don't let a user resume (read + inject into) another user's
        # session by guessing/obtaining its id (previously any caller could).
        if not _owns(user, session.owner_user_id):
            raise not_found("Session", req.session_id)  # 404, don't confirm existence
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

        if req.rich_events:
            # Rich path (opt-in): drive the FULL Kryon turn — determinism +
            # pre_hooks + reflective loop — via the turn-service, streaming rich
            # AgentEvents. A CallbackSink pushes each event as an SSE frame onto
            # run_state.events, so the existing /runs/{id}/stream poller serves it
            # unchanged. This is the endpoint the Charm/TUI client drives.
            from kryon.services.agent_events import CallbackSink
            from kryon.services.turn_service import run_turn

            rich_sink = CallbackSink(lambda e: run_state.append_event(e.to_sse()))

            async def _run_turn_streamed():
                from kryon.sdk.agents.run_config_factory import get_run_config

                try:
                    async with sm.semaphore:
                        turn_result = await run_turn(
                            agent,
                            req.input,
                            sink=rich_sink,
                            max_turns=req.max_turns,
                            run_config=get_run_config(),
                            free_run=req.free_run,
                        )
                        # The report + findings ride the `done`/`finding` events;
                        # run_state.output stays empty (the stream carries everything).
                        run_state.output = ""
                        run_state.agent_name = req.agent_key
                        run_state.status = "completed"
                        # #1 continuity: persist the accumulated conversation to the
                        # session (the stateful agent already REMEMBERS across turns —
                        # this just captures it so the session survives restart / can be
                        # listed & resumed). The agent's model owns the running history.
                        if session is not None:
                            hist = getattr(getattr(agent, "model", None), "message_history", None)
                            if isinstance(hist, list):
                                # Strip the reflective runner's internal directives
                                # (forced-synthesis / reflection nudges) so a resumed
                                # session replays only the real conversation and its
                                # chat template doesn't stall on repeated user roles;
                                # then guarantee the turn's final answer is captured —
                                # a thinking model with reasoning-only output never
                                # lands its reply in message_history, which would drop
                                # it from the resumed conversation.
                                cleaned = sanitize_history_for_persist(hist)
                                session.input_history = ensure_final_assistant(
                                    cleaned, turn_result.get("final_output", "")
                                )
                                sm.persist_session(session)
                except asyncio.CancelledError:
                    run_state.status = "cancelled"
                except Exception as exc:  # run_turn itself never raises; guards the plumbing
                    logger.error("Rich turn run failed: %s", exc, exc_info=True)
                    run_state.status = "failed"
                    run_state.output = "Agent turn failed"

            run_state.task = asyncio.create_task(_run_turn_streamed())
            return RunResponse(run_id=run_state.run_id, status="streaming", output="", agent=req.agent_key)

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
                            run_state.append_event(sse)
                    run_state.output = result.final_output or ""
                    run_state.agent_name = result.last_agent.name if result.last_agent else ""
                    run_state.status = "completed"
                    # Update session history
                    if session is not None:
                        session.input_history = sanitize_history_for_persist(result.to_input_list())
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
        session.input_history = sanitize_history_for_persist(result.to_input_list())

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
        served = 0
        while True:
            # Serve every frame this reader hasn't seen yet. `events_since` maps the
            # `served` cursor onto the ring buffer's live window, so a long run that
            # overflows the buffer degrades gracefully instead of mis-indexing or
            # looping forever (both of which the old positional `run.events[idx]` did).
            new, served = run.events_since(served)
            for sse in new:
                yield sse

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
async def create_session(req: SessionCreateRequest, user: User | None = Depends(get_current_user)):
    """Create a new conversation session with an agent."""
    sm = _get_sm()
    from kryon.agents import get_agent_by_name

    try:
        agent = get_agent_by_name(req.agent_key, model_override=req.model)  # #3 per-session model
    except ValueError as e:
        logger.warning("Agent not found: %s — %s", req.agent_key, e)
        raise HTTPException(status_code=404, detail="Agent not found")

    session = sm.create_session(req.agent_key, agent, owner_user_id=(user.id if user else None), model=req.model)
    logger.info("Session created: agent=%s session_id=%s", req.agent_key, session.session_id)
    return SessionResponse(
        session_id=session.session_id,
        agent_key=session.agent_key,
        created_at=session.created_at,
        message_count=len(session.input_history),
    )


@router.get("/sessions", response_model=list[SessionResponse])
async def list_sessions(user: User | None = Depends(get_current_user)):
    """List active sessions owned by the caller (all, for admin / API-key mode)."""
    sm = _get_sm()
    return [
        SessionResponse(
            session_id=s.session_id,
            agent_key=s.agent_key,
            created_at=s.created_at,
            message_count=len(s.input_history),
        )
        for s in sm.list_sessions()
        if _owns(user, s.owner_user_id)  # don't enumerate other users' sessions
    ]
