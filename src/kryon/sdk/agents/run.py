from __future__ import annotations

import asyncio
import copy
import os
from dataclasses import dataclass, field, replace
from typing import Any, cast

from openai.types.responses import ResponseCompletedEvent

from ._run_impl import (
    AgentToolUseTracker,
    NextStepFinalOutput,
    NextStepHandoff,
    NextStepRunAgain,
    QueueCompleteSentinel,
    RunImpl,
    SingleStepResult,
    TraceCtxManager,
    get_model_tracing_impl,
)
from .agent import Agent
from .agent_output import AgentOutputSchema
from .exceptions import (
    AgentsException,
    InputGuardrailTripwireTriggered,
    MaxTurnsExceeded,
    ModelBehaviorError,
    OutputGuardrailTripwireTriggered,
)
from .guardrail import InputGuardrail, InputGuardrailResult, OutputGuardrail, OutputGuardrailResult
from .handoffs import Handoff, HandoffInputFilter, handoff
from .items import ItemHelpers, ModelResponse, RunItem, TResponseInputItem
from .lifecycle import RunHooks
from .logger import logger
from .model_settings import ModelSettings
from .models.interface import Model, ModelProvider
from .models.openai_provider import OpenAIProvider
from .result import RunResult, RunResultStreaming
from .run_context import RunContextWrapper, TContext
from .stream_events import AgentUpdatedStreamEvent, RawResponsesStreamEvent
from .tool import Tool
from .tracing import Span, SpanError, agent_span, get_current_trace, trace
from .tracing.span_data import AgentSpanData
from .usage import Usage
from .util import _coro, _error_tracing

# F85.B — Budget hardening.
#
# KRYON_MAX_TURNS caps how many LLM turns a single run can execute before the
# orchestrator forces termination via MaxTurnsExceeded. The previous default
# of float("inf") let a stuck agent burn the full API key. 40 covers ~99% of
# real engagements (median engage runs 4-12 turns); operators with genuinely
# long workflows can override via the env var.
max_turns_env = os.getenv("KRYON_MAX_TURNS")
DEFAULT_MAX_TURNS: float
if max_turns_env is not None:
    try:
        DEFAULT_MAX_TURNS = int(max_turns_env)
    except ValueError:
        try:
            DEFAULT_MAX_TURNS = float(max_turns_env)
        except ValueError:
            DEFAULT_MAX_TURNS = 40
else:
    # C — capable model gets a raised turn budget (its is_capable_model docstring
    # asks for it); a long kill-chain shouldn't hit the 4B-tuned 40-turn wall.
    # Resolved at import; in the docker deploy KRYON_CAPABLE_MODEL is in the env
    # before load. Entry points (engage/investigate) pass their own cap anyway —
    # this is the SDK fallback. Explicit KRYON_MAX_TURNS still wins (branch above).
    from kryon.util.env import is_capable_model  # noqa: PLC0415

    DEFAULT_MAX_TURNS = 100 if is_capable_model() else 40

# KRYON_PRICE_LIMIT is read AND enforced by kryon.util.cost_tracker (which
# wraps the chat-completions call path). We keep the parsed value here as
# DEFAULT_PRICE_LIMIT so it's discoverable next to MAX_TURNS, but the actual
# abort lives in CostTracker.check_budget() — see openai_chatcompletions.py
# call sites (lines ~906, 912, 1046, 1596). Default 5 USD per run keeps a
# bug-induced loop from emptying the wallet; raise via env or RunConfig.
price_limit_env = os.getenv("KRYON_PRICE_LIMIT")
if price_limit_env is not None:
    try:
        DEFAULT_PRICE_LIMIT = float(price_limit_env)
    except ValueError:
        DEFAULT_PRICE_LIMIT = 5.0
else:
    DEFAULT_PRICE_LIMIT = 5.0


# --- Cross-chunk StuckDetector persistence -------------------------------
# `Runner.run` builds a fresh StuckDetector per call. A chunked driver like the
# reflective runner calls `Runner.run` once per ~4-turn chunk, so without this a
# multi-turn loop (alternating/re-derivation) resets the detector's window every
# chunk and never trips abort. A driver wraps its whole loop in
# `shared_stuck_detector()`; every chunk then reuses the SAME detector, so its
# window/counters span the entire run. Absent that ctx, behaviour is unchanged.
import contextlib as _contextlib  # noqa: E402
from contextvars import ContextVar as _ContextVar  # noqa: E402

_SHARED_STUCK_DETECTOR: _ContextVar[Any] = _ContextVar("kryon_shared_stuck_detector", default=None)


def _default_temperature() -> float:
    """Sampling temperature when neither caller nor env set one. Greedy (0.0) for the
    4B-local (reproducible/banca-safe); 0.4 for a capable model (KRYON_CAPABLE_MODEL)
    so it varies enumeration/hypotheses instead of repeating one path."""
    from kryon.util.env import is_capable_model  # noqa: PLC0415

    return 0.4 if is_capable_model() else 0.0


def _build_stuck_detector():
    """Construct a StuckDetector from env (window default 8 — one more than the
    old 6 so a two-tool A,B,A,B alternation reaches abort_at=4 instead of
    stalling at count 3)."""
    from ._stuck_detector import StuckDetector
    from kryon.util.env import is_capable_model  # noqa: PLC0415

    # A capable model may legitimately re-issue a command (poll a job, re-probe an
    # endpoint after changing state elsewhere) — it shouldn't hit the 4B abort_at=4.
    # Raise the abort bands + window for capable; intervene stays at 2 (early,
    # non-destructive nudge). The 4B keeps the tight bands (real-loop guard).
    _cap = is_capable_model()
    window = int(os.getenv("KRYON_STUCK_WINDOW", "12" if _cap else "8"))
    intervene = int(os.getenv("KRYON_STUCK_INTERVENE_AT", "2"))
    abort = int(os.getenv("KRYON_STUCK_ABORT_AT", "8" if _cap else "4"))
    return StuckDetector(window_size=window, intervene_at=intervene, abort_at=abort)


@_contextlib.contextmanager
def shared_stuck_detector(detector=None):
    """Share one StuckDetector across every `Runner.run` in this context (e.g.
    all chunks of a reflective run), so cross-chunk loops are actually caught."""
    det = detector if detector is not None else _build_stuck_detector()
    token = _SHARED_STUCK_DETECTOR.set(det)
    try:
        yield det
    finally:
        _SHARED_STUCK_DETECTOR.reset(token)


@dataclass
class RunConfig:
    """Configures settings for the entire agent run."""

    model: str | Model | None = None
    """The model to use for the entire agent run. If set, will override the model set on every
    agent. The model_provider passed in below must be able to resolve this model name.
    """

    model_provider: ModelProvider = field(default_factory=OpenAIProvider)
    """The model provider to use when looking up string model names. Defaults to OpenAI."""

    model_settings: ModelSettings | None = None
    """Configure global model settings. Any non-null values will override the agent-specific model
    settings.
    """

    handoff_input_filter: HandoffInputFilter | None = None
    """A global input filter to apply to all handoffs. If `Handoff.input_filter` is set, then that
    will take precedence. The input filter allows you to edit the inputs that are sent to the new
    agent. See the documentation in `Handoff.input_filter` for more details.
    """

    input_guardrails: list[InputGuardrail[Any]] | None = None
    """A list of input guardrails to run on the initial run input."""

    output_guardrails: list[OutputGuardrail[Any]] | None = None
    """A list of output guardrails to run on the final output of the run."""

    tracing_disabled: bool = False
    """Whether tracing is disabled for the agent run. If disabled, we will not trace the agent run.
    """

    trace_include_sensitive_data: bool = True
    """Whether we include potentially sensitive data (for example: inputs/outputs of tool calls or
    LLM generations) in traces. If False, we'll still create spans for these events, but the
    sensitive data will not be included.
    """

    workflow_name: str = "Agent workflow"
    """The name of the run, used for tracing. Should be a logical name for the run, like
    "Code generation workflow" or "Customer support agent".
    """

    trace_id: str | None = None
    """A custom trace ID to use for tracing. If not provided, we will generate a new trace ID."""

    group_id: str | None = None
    """
    A grouping identifier to use for tracing, to link multiple traces from the same conversation
    or process. For example, you might use a chat thread ID.
    """

    trace_metadata: dict[str, Any] | None = None
    """
    An optional dictionary of additional metadata to include with the trace.
    """


class Runner:
    @classmethod
    async def run(
        cls,
        starting_agent: Agent[TContext],
        input: str | list[TResponseInputItem],
        *,
        context: TContext | None = None,
        max_turns: int = DEFAULT_MAX_TURNS,  # type: ignore[assignment]
        hooks: RunHooks[TContext] | None = None,
        run_config: RunConfig | None = None,
        stuck_detector: Any | None = None,
    ) -> RunResult:
        """Run a workflow starting at the given agent. The agent will run in a loop until a final
        output is generated. The loop runs like so:
        1. The agent is invoked with the given input.
        2. If there is a final output (i.e. the agent produces something of type
            `agent.output_type`, the loop terminates.
        3. If there's a handoff, we run the loop again, with the new agent.
        4. Else, we run tool calls (if any), and re-run the loop.

        In two cases, the agent may raise an exception:
        1. If the max_turns is exceeded, a MaxTurnsExceeded exception is raised.
        2. If a guardrail tripwire is triggered, a GuardrailTripwireTriggered exception is raised.

        Note that only the first agent's input guardrails are run.

        Args:
            starting_agent: The starting agent to run.
            input: The initial input to the agent. You can pass a single string for a user message,
                or a list of input items.
            context: The context to run the agent with.
            max_turns: The maximum number of turns to run the agent for. A turn is defined as one
                AI invocation (including any tool calls that might occur).
            hooks: An object that receives callbacks on various lifecycle events.
            run_config: Global settings for the entire agent run.

        Returns:
            A run result containing all the inputs, guardrail results and the output of the last
            agent. Agents may perform handoffs, so we don't know the specific type of the output.
        """
        if hooks is None:
            hooks = RunHooks[Any]()
        if run_config is None:
            run_config = RunConfig()

        tool_use_tracker = AgentToolUseTracker()

        with TraceCtxManager(
            workflow_name=run_config.workflow_name,
            trace_id=run_config.trace_id,
            group_id=run_config.group_id,
            metadata=run_config.trace_metadata,
            disabled=run_config.tracing_disabled,
        ):
            current_turn = 0
            original_input: str | list[TResponseInputItem] = copy.deepcopy(input)
            generated_items: list[RunItem] = []
            model_responses: list[ModelResponse] = []

            # F85.E — Attach a per-run StuckDetector so _run_impl can
            # flag tool-call loops. Window / thresholds are tunable via
            # env vars for experimentation; defaults come from the
            # Manus/agent-patterns prior-art consensus.
            # Reuse a driver-provided detector (explicit param, or the
            # shared_stuck_detector context) so a chunked run keeps ONE detector
            # across chunks; else build a fresh one from env (window default 8).
            _shared_detector = stuck_detector if stuck_detector is not None else _SHARED_STUCK_DETECTOR.get()

            # F123 — Pull the active ActionLog from the registry so the
            # _run_impl tool-call hook can persist per-tool entries.
            # Optional: when no orchestrator is active, get_active_log()
            # returns (None, "agent") and the audit path is a no-op.
            try:
                from kryon.audit.action_log import get_active_log

                active_audit_log, active_audit_phase = get_active_log()
            except Exception:  # pragma: no cover
                active_audit_log, active_audit_phase = None, "agent"

            context_wrapper: RunContextWrapper[TContext] = RunContextWrapper(
                context=context,  # type: ignore
                stuck_detector=_shared_detector if _shared_detector is not None else _build_stuck_detector(),
                audit_log=active_audit_log,
                audit_phase=active_audit_phase,
            )

            input_guardrail_results: list[InputGuardrailResult] = []

            current_span: Span[AgentSpanData] | None = None
            current_agent = starting_agent
            should_run_agent_start_hooks = True

            try:
                while True:
                    # Start an agent span if we don't have one. This span is ended if the current
                    # agent changes, or if the agent loop ends.
                    if current_span is None:
                        handoff_names = [h.agent_name for h in cls._get_handoffs(current_agent)]
                        if output_schema := cls._get_output_schema(current_agent):
                            output_type_name = output_schema.output_type_name()
                        else:
                            output_type_name = "str"

                        current_span = agent_span(
                            name=current_agent.name,
                            handoffs=handoff_names,
                            output_type=output_type_name,
                        )
                        current_span.start(mark_as_current=True)

                        all_tools = await cls._get_all_tools(current_agent)
                        current_span.span_data.tools = [t.name for t in all_tools]

                    current_turn += 1
                    if current_turn > max_turns:
                        _error_tracing.attach_error_to_span(
                            current_span,
                            SpanError(
                                message="Max turns exceeded",
                                data={"max_turns": max_turns},
                            ),
                        )
                        raise MaxTurnsExceeded(f"Max turns ({max_turns}) exceeded")

                    logger.debug(
                        f"Running agent {current_agent.name} (turn {current_turn})",
                    )

                    if current_turn == 1:
                        # Run input guardrails BEFORE the first turn, not concurrently
                        # with it. gather(guardrails, turn) let the turn-1 tools execute
                        # before a tripped guardrail could raise — so a scope/authorization
                        # guardrail couldn't actually stop the first action. Sequential =
                        # defense-in-depth: a tripwire now aborts before any tool runs.
                        # (The tool-layer scope cage still guards every call; this also
                        # covers non-scope guardrails and runs with no cage declared.)
                        input_guardrail_results = await cls._run_input_guardrails(
                            starting_agent,
                            starting_agent.input_guardrails + (run_config.input_guardrails or []),
                            copy.deepcopy(input),
                            context_wrapper,
                        )
                        turn_result = await cls._run_single_turn(
                            agent=current_agent,
                            all_tools=all_tools,
                            original_input=original_input,
                            generated_items=generated_items,
                            hooks=hooks,
                            context_wrapper=context_wrapper,
                            run_config=run_config,
                            should_run_agent_start_hooks=should_run_agent_start_hooks,
                            tool_use_tracker=tool_use_tracker,
                        )
                    else:
                        turn_result = await cls._run_single_turn(
                            agent=current_agent,
                            all_tools=all_tools,
                            original_input=original_input,
                            generated_items=generated_items,
                            hooks=hooks,
                            context_wrapper=context_wrapper,
                            run_config=run_config,
                            should_run_agent_start_hooks=should_run_agent_start_hooks,
                            tool_use_tracker=tool_use_tracker,
                        )
                    should_run_agent_start_hooks = False

                    model_responses.append(turn_result.model_response)
                    original_input = turn_result.original_input
                    generated_items = turn_result.generated_items

                    if isinstance(turn_result.next_step, NextStepFinalOutput):
                        output_guardrail_results = await cls._run_output_guardrails(
                            current_agent.output_guardrails + (run_config.output_guardrails or []),
                            current_agent,
                            turn_result.next_step.output,
                            context_wrapper,
                        )
                        return RunResult(
                            input=original_input,
                            new_items=generated_items,
                            raw_responses=model_responses,
                            final_output=turn_result.next_step.output,
                            _last_agent=current_agent,
                            input_guardrail_results=input_guardrail_results,
                            output_guardrail_results=output_guardrail_results,
                        )
                    elif isinstance(turn_result.next_step, NextStepHandoff):
                        # Get the previous agent before switching
                        previous_agent = current_agent
                        current_agent = cast(Agent[TContext], turn_result.next_step.new_agent)

                        # Transfer message history for swarm patterns
                        # Check if both agents have models with message_history
                        if (
                            hasattr(previous_agent, "model")
                            and hasattr(previous_agent.model, "message_history")
                            and hasattr(current_agent, "model")
                            and hasattr(current_agent.model, "message_history")
                        ):
                            # Import the is_swarm_pattern function from patterns utils
                            try:
                                from kryon.agents.patterns.utils import is_swarm_pattern

                                # Check if either agent is part of a swarm pattern
                                if is_swarm_pattern(previous_agent) or is_swarm_pattern(current_agent):
                                    # Transfer the message history to the new agent
                                    current_agent.model.message_history = previous_agent.model.message_history
                                    # Also share history in AGENT_MANAGER
                                    if hasattr(previous_agent, "name") and hasattr(current_agent, "name"):
                                        from kryon.sdk.agents.simple_agent_manager import (
                                            AGENT_MANAGER,
                                        )

                                        AGENT_MANAGER.share_swarm_history(previous_agent.name, current_agent.name)
                            except ImportError:
                                # If we can't import, check if agents have bidirectional handoffs
                                # by looking if the new agent can handoff back to the previous agent
                                if hasattr(current_agent, "handoffs"):
                                    for handoff_item in current_agent.handoffs:
                                        if (
                                            hasattr(handoff_item, "agent_name")
                                            and handoff_item.agent_name == previous_agent.name
                                        ):
                                            # Bidirectional handoff detected, share history
                                            current_agent.model.message_history = previous_agent.model.message_history
                                            break

                        # Register the handoff agent with AGENT_MANAGER for tracking
                        # This ensures patterns/swarms work with commands like /history and /graph
                        from kryon.sdk.agents.simple_agent_manager import AGENT_MANAGER

                        if hasattr(current_agent, "name"):
                            # For non-parallel patterns, use set_active_agent which will handle it as single agent
                            # This maintains compatibility with single agent commands
                            AGENT_MANAGER.set_active_agent(current_agent, current_agent.name)

                        current_span.finish(reset_current=True)
                        current_span = None
                        should_run_agent_start_hooks = True
                    elif isinstance(turn_result.next_step, NextStepRunAgain):
                        pass
                    else:
                        raise AgentsException(f"Unknown next step type: {type(turn_result.next_step)}")
            finally:
                if current_span:
                    current_span.finish(reset_current=True)

    @classmethod
    def run_sync(
        cls,
        starting_agent: Agent[TContext],
        input: str | list[TResponseInputItem],
        *,
        context: TContext | None = None,
        max_turns: int = DEFAULT_MAX_TURNS,  # type: ignore[assignment]
        hooks: RunHooks[TContext] | None = None,
        run_config: RunConfig | None = None,
    ) -> RunResult:
        """Run a workflow synchronously, starting at the given agent. Note that this just wraps the
        `run` method, so it will not work if there's already an event loop (e.g. inside an async
        function, or in a Jupyter notebook or async context like FastAPI). For those cases, use
        the `run` method instead.

        The agent will run in a loop until a final output is generated. The loop runs like so:
        1. The agent is invoked with the given input.
        2. If there is a final output (i.e. the agent produces something of type
            `agent.output_type`, the loop terminates.
        3. If there's a handoff, we run the loop again, with the new agent.
        4. Else, we run tool calls (if any), and re-run the loop.

        In two cases, the agent may raise an exception:
        1. If the max_turns is exceeded, a MaxTurnsExceeded exception is raised.
        2. If a guardrail tripwire is triggered, a GuardrailTripwireTriggered exception is raised.

        Note that only the first agent's input guardrails are run.

        Args:
            starting_agent: The starting agent to run.
            input: The initial input to the agent. You can pass a single string for a user message,
                or a list of input items.
            context: The context to run the agent with.
            max_turns: The maximum number of turns to run the agent for. A turn is defined as one
                AI invocation (including any tool calls that might occur).
            hooks: An object that receives callbacks on various lifecycle events.
            run_config: Global settings for the entire agent run.

        Returns:
            A run result containing all the inputs, guardrail results and the output of the last
            agent. Agents may perform handoffs, so we don't know the specific type of the output.
        """
        # asyncio.run (not the deprecated get_event_loop().run_until_complete): this
        # is a sync entry point, so a fresh loop is correct. Raises if called from a
        # running loop — which is the right failure (use the async `run` there).
        return asyncio.run(
            cls.run(
                starting_agent,
                input,
                context=context,
                max_turns=max_turns,
                hooks=hooks,
                run_config=run_config,
            )
        )

    @classmethod
    def run_streamed(
        cls,
        starting_agent: Agent[TContext],
        input: str | list[TResponseInputItem],
        context: TContext | None = None,
        max_turns: int = DEFAULT_MAX_TURNS,  # type: ignore[assignment]
        hooks: RunHooks[TContext] | None = None,
        run_config: RunConfig | None = None,
    ) -> RunResultStreaming:
        """Run a workflow starting at the given agent in streaming mode. The returned result object
        contains a method you can use to stream semantic events as they are generated.

        The agent will run in a loop until a final output is generated. The loop runs like so:
        1. The agent is invoked with the given input.
        2. If there is a final output (i.e. the agent produces something of type
            `agent.output_type`, the loop terminates.
        3. If there's a handoff, we run the loop again, with the new agent.
        4. Else, we run tool calls (if any), and re-run the loop.

        In two cases, the agent may raise an exception:
        1. If the max_turns is exceeded, a MaxTurnsExceeded exception is raised.
        2. If a guardrail tripwire is triggered, a GuardrailTripwireTriggered exception is raised.

        Note that only the first agent's input guardrails are run.

        Args:
            starting_agent: The starting agent to run.
            input: The initial input to the agent. You can pass a single string for a user message,
                or a list of input items.
            context: The context to run the agent with.
            max_turns: The maximum number of turns to run the agent for. A turn is defined as one
                AI invocation (including any tool calls that might occur).
            hooks: An object that receives callbacks on various lifecycle events.
            run_config: Global settings for the entire agent run.

        Returns:
            A result object that contains data about the run, as well as a method to stream events.
        """
        if hooks is None:
            hooks = RunHooks[Any]()
        if run_config is None:
            run_config = RunConfig()

        # If there's already a trace, we don't create a new one. In addition, we can't end the
        # trace here, because the actual work is done in `stream_events` and this method ends
        # before that.
        new_trace = (
            None
            if get_current_trace()
            else trace(
                workflow_name=run_config.workflow_name,
                trace_id=run_config.trace_id,
                group_id=run_config.group_id,
                metadata=run_config.trace_metadata,
                disabled=run_config.tracing_disabled,
            )
        )
        # Need to start the trace here, because the current trace contextvar is captured at
        # asyncio.create_task time
        if new_trace:
            new_trace.start(mark_as_current=True)

        output_schema = cls._get_output_schema(starting_agent)
        # Parity with the non-streaming path (run.py:249-274): attach the per-run
        # StuckDetector (F85.E loop-abort) and the active ActionLog (F123 per-tool
        # audit) so a STREAMED run — the CLI's default (KRYON_STREAM defaults true)
        # — also aborts tool-call loops and produces forensic audit entries. Without
        # this both were silently None for every streamed run (loop burned the whole
        # budget; audit gap for banking engagements).
        _shared_detector = _SHARED_STUCK_DETECTOR.get()
        try:
            from kryon.audit.action_log import get_active_log

            active_audit_log, active_audit_phase = get_active_log()
        except Exception:  # pragma: no cover
            active_audit_log, active_audit_phase = None, "agent"
        context_wrapper: RunContextWrapper[TContext] = RunContextWrapper(
            context=context,  # type: ignore
            stuck_detector=_shared_detector if _shared_detector is not None else _build_stuck_detector(),
            audit_log=active_audit_log,
            audit_phase=active_audit_phase,
        )

        streamed_result = RunResultStreaming(
            input=copy.deepcopy(input),
            new_items=[],
            current_agent=starting_agent,
            raw_responses=[],
            final_output=None,
            is_complete=False,
            current_turn=0,
            max_turns=max_turns,
            input_guardrail_results=[],
            output_guardrail_results=[],
            _current_agent_output_schema=output_schema,
            _trace=new_trace,
        )

        # Kick off the actual agent loop in the background and return the streamed result object.
        streamed_result._run_impl_task = asyncio.create_task(
            cls._run_streamed_impl(
                starting_input=input,
                streamed_result=streamed_result,
                starting_agent=starting_agent,
                max_turns=max_turns,
                hooks=hooks,
                context_wrapper=context_wrapper,
                run_config=run_config,
            )
        )
        return streamed_result

    @classmethod
    async def _run_input_guardrails_with_queue(
        cls,
        agent: Agent[Any],
        guardrails: list[InputGuardrail[TContext]],
        input: str | list[TResponseInputItem],
        context: RunContextWrapper[TContext],
        streamed_result: RunResultStreaming,
        parent_span: Span[Any],
    ):
        queue = streamed_result._input_guardrail_queue

        # We'll run the guardrails and push them onto the queue as they complete
        guardrail_tasks = [
            asyncio.create_task(RunImpl.run_single_input_guardrail(agent, guardrail, input, context))
            for guardrail in guardrails
        ]
        guardrail_results = []
        try:
            for done in asyncio.as_completed(guardrail_tasks):
                result = await done
                if result.output.tripwire_triggered:
                    _error_tracing.attach_error_to_span(
                        parent_span,
                        SpanError(
                            message="Guardrail tripwire triggered",
                            data={
                                "guardrail": result.guardrail.get_name(),
                                "type": "input_guardrail",
                            },
                        ),
                    )
                queue.put_nowait(result)
                guardrail_results.append(result)
        except Exception:
            for t in guardrail_tasks:
                t.cancel()
            raise

        streamed_result.input_guardrail_results = guardrail_results

    @classmethod
    async def _run_streamed_impl(
        cls,
        starting_input: str | list[TResponseInputItem],
        streamed_result: RunResultStreaming,
        starting_agent: Agent[TContext],
        max_turns: int,
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
    ):
        current_span: Span[AgentSpanData] | None = None
        current_agent = starting_agent
        current_turn = 0
        should_run_agent_start_hooks = True
        tool_use_tracker = AgentToolUseTracker()

        streamed_result._event_queue.put_nowait(AgentUpdatedStreamEvent(new_agent=current_agent))

        try:
            while True:
                if streamed_result.is_complete:
                    break

                # Start an agent span if we don't have one. This span is ended if the current
                # agent changes, or if the agent loop ends.
                if current_span is None:
                    handoff_names = [h.agent_name for h in cls._get_handoffs(current_agent)]
                    if output_schema := cls._get_output_schema(current_agent):
                        output_type_name = output_schema.output_type_name()
                    else:
                        output_type_name = "str"

                    current_span = agent_span(
                        name=current_agent.name,
                        handoffs=handoff_names,
                        output_type=output_type_name,
                    )
                    current_span.start(mark_as_current=True)

                    all_tools = await cls._get_all_tools(current_agent)
                    tool_names = [t.name for t in all_tools]
                    current_span.span_data.tools = tool_names
                current_turn += 1
                streamed_result.current_turn = current_turn

                if current_turn > max_turns:
                    _error_tracing.attach_error_to_span(
                        current_span,
                        SpanError(
                            message="Max turns exceeded",
                            data={"max_turns": max_turns},
                        ),
                    )
                    streamed_result._event_queue.put_nowait(QueueCompleteSentinel())
                    break

                if current_turn == 1:
                    # Run the input guardrails and put the results on the queue.
                    _gr_input = starting_agent.input_guardrails + (run_config.input_guardrails or [])
                    streamed_result._input_guardrails_task = asyncio.create_task(
                        cls._run_input_guardrails_with_queue(
                            starting_agent,
                            _gr_input,
                            copy.deepcopy(ItemHelpers.input_to_new_input_list(starting_input)),
                            context_wrapper,
                            streamed_result,
                            current_span,
                        )
                    )
                    # Close the guardrail-vs-tool race: a scope/authorization tripwire
                    # must block turn-1 TOOL execution, not surface only later when the
                    # event consumer drains the queue (by which point a side-effecting
                    # first-turn tool already ran). Parity with the non-streaming path
                    # (run.py:326-331): await the guardrails and raise BEFORE the turn.
                    # Results stay queued for the consumer.
                    if _gr_input:
                        await streamed_result._input_guardrails_task
                        for _gr in streamed_result.input_guardrail_results:
                            if _gr.output.tripwire_triggered:
                                # Enqueue the completion sentinel BEFORE raising.
                                # This raise sits outside the inner try/except
                                # (743-842) that normally drains the queue, so
                                # without this the background task dies with the
                                # exception while stream_events() stays blocked on
                                # `_event_queue.get()` forever (deadlock).
                                streamed_result.is_complete = True
                                streamed_result._event_queue.put_nowait(QueueCompleteSentinel())
                                raise InputGuardrailTripwireTriggered(_gr)
                try:
                    turn_result = await cls._run_single_turn_streamed(
                        streamed_result,
                        current_agent,
                        hooks,
                        context_wrapper,
                        run_config,
                        should_run_agent_start_hooks,
                        tool_use_tracker,
                        all_tools,
                    )
                    should_run_agent_start_hooks = False

                    # Process the turn result
                    streamed_result.raw_responses = streamed_result.raw_responses + [turn_result.model_response]
                    streamed_result.input = turn_result.original_input
                    streamed_result.new_items = turn_result.generated_items

                    if isinstance(turn_result.next_step, NextStepHandoff):
                        # Get the previous agent before switching
                        previous_agent = current_agent
                        current_agent = turn_result.next_step.new_agent

                        # Transfer message history for swarm patterns
                        # Check if both agents have models with message_history
                        if (
                            hasattr(previous_agent, "model")
                            and hasattr(previous_agent.model, "message_history")
                            and hasattr(current_agent, "model")
                            and hasattr(current_agent.model, "message_history")
                        ):
                            # Import the is_swarm_pattern function from patterns utils
                            try:
                                from kryon.agents.patterns.utils import is_swarm_pattern

                                # Check if either agent is part of a swarm pattern
                                if is_swarm_pattern(previous_agent) or is_swarm_pattern(current_agent):
                                    # Transfer the message history to the new agent
                                    current_agent.model.message_history = previous_agent.model.message_history
                                    # Also share history in AGENT_MANAGER
                                    if hasattr(previous_agent, "name") and hasattr(current_agent, "name"):
                                        from kryon.sdk.agents.simple_agent_manager import (
                                            AGENT_MANAGER,
                                        )

                                        AGENT_MANAGER.share_swarm_history(previous_agent.name, current_agent.name)
                            except ImportError:
                                # If we can't import, check if agents have bidirectional handoffs
                                # by looking if the new agent can handoff back to the previous agent
                                if hasattr(current_agent, "handoffs"):
                                    for handoff_item in current_agent.handoffs:
                                        if (
                                            hasattr(handoff_item, "agent_name")
                                            and handoff_item.agent_name == previous_agent.name
                                        ):
                                            # Bidirectional handoff detected, share history
                                            current_agent.model.message_history = previous_agent.model.message_history
                                            break

                        current_span.finish(reset_current=True)
                        current_span = None
                        should_run_agent_start_hooks = True
                        streamed_result._event_queue.put_nowait(AgentUpdatedStreamEvent(new_agent=current_agent))
                    elif isinstance(turn_result.next_step, NextStepFinalOutput):
                        streamed_result._output_guardrails_task = asyncio.create_task(
                            cls._run_output_guardrails(
                                current_agent.output_guardrails + (run_config.output_guardrails or []),
                                current_agent,
                                turn_result.next_step.output,
                                context_wrapper,
                            )
                        )

                        try:
                            output_guardrail_results = await streamed_result._output_guardrails_task
                        except Exception:
                            # Exceptions will be checked in the stream_events loop
                            output_guardrail_results = []

                        streamed_result.output_guardrail_results = output_guardrail_results
                        streamed_result.final_output = turn_result.next_step.output
                        streamed_result.is_complete = True
                        streamed_result._event_queue.put_nowait(QueueCompleteSentinel())
                    elif isinstance(turn_result.next_step, NextStepRunAgain):
                        pass
                except (KeyboardInterrupt, asyncio.CancelledError) as e:
                    # Re-raise to propagate the interruption
                    raise e
                except Exception as e:
                    if current_span:
                        _error_tracing.attach_error_to_span(
                            current_span,
                            SpanError(
                                message="Error in agent run",
                                data={"error": str(e)},
                            ),
                        )
                    streamed_result.is_complete = True
                    streamed_result._event_queue.put_nowait(QueueCompleteSentinel())
                    raise

            streamed_result.is_complete = True
        finally:
            if current_span:
                current_span.finish(reset_current=True)

    @classmethod
    async def _run_single_turn_streamed(
        cls,
        streamed_result: RunResultStreaming,
        agent: Agent[TContext],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
        should_run_agent_start_hooks: bool,
        tool_use_tracker: AgentToolUseTracker,
        all_tools: list[Tool],
    ) -> SingleStepResult:
        if should_run_agent_start_hooks:
            await asyncio.gather(
                hooks.on_agent_start(context_wrapper, agent),
                (agent.hooks.on_start(context_wrapper, agent) if agent.hooks else _coro.noop_coroutine()),
            )

        output_schema = cls._get_output_schema(agent)

        streamed_result.current_agent = agent
        streamed_result._current_agent_output_schema = output_schema

        system_prompt = await agent.get_system_prompt(context_wrapper)

        handoffs = cls._get_handoffs(agent)
        model = cls._get_model(agent, run_config)
        model_settings = agent.model_settings.resolve(run_config.model_settings)
        model_settings = RunImpl.maybe_reset_tool_choice(agent, tool_use_tracker, model_settings)
        # resolve() returns `self` when there's no run-level override, so the
        # defaults applied below would mutate the caller's agent.model_settings
        # in place (leaking temperature=0.0 onto the agent object, breaking
        # agent identity/equality). Copy first so mutations stay local.
        model_settings = replace(model_settings)
        # F155 — Default LLM temperature from env. Lower temperature
        # reduces hallucinations (R1 distill especially) at the cost
        # of creativity. Banca-safe default is 0.0; can be overridden
        # per-run via KRYON_LLM_TEMPERATURE or per-agent via the
        # ``model_settings.temperature`` field. Only set when the
        # caller hasn't already specified one.
        if model_settings.temperature is None:
            env_temp = os.environ.get("KRYON_LLM_TEMPERATURE", "").strip()
            if env_temp:
                try:
                    model_settings.temperature = float(env_temp)
                except ValueError:
                    pass
            else:

                # Greedy decoding (0.0) kills exploration for an agentic run — a
                # capable model varies enumeration/hypotheses at ~0.4. The 4B-local
                # default stays 0.0 (banca-safe reproducibility).
                model_settings.temperature = _default_temperature()

        # F184 — propagate ``KRYON_REASONING_EFFORT`` env (low|medium|high)
        # into model_settings so gpt-oss / o1 / o3 / R1 distill pick up
        # the right CoT budget. Same precedence rule as temperature:
        # caller's setting wins, env fills the gap, no default
        # (means: leave None → backend's Modelfile default applies).
        if not getattr(model_settings, "reasoning_effort", None):
            env_effort = os.environ.get("KRYON_REASONING_EFFORT", "").strip().lower()
            if env_effort in {"low", "medium", "high"}:
                model_settings.reasoning_effort = env_effort

        # Ensure agent model is set in model_settings for streaming mode
        if not hasattr(model_settings, "agent_model") or not model_settings.agent_model:
            if isinstance(agent.model, str):
                model_settings.agent_model = agent.model
            elif isinstance(run_config.model, str):
                model_settings.agent_model = run_config.model

        final_response: ModelResponse | None = None

        input = ItemHelpers.input_to_new_input_list(streamed_result.input)
        input.extend([item.to_input_item() for item in streamed_result.new_items])

        # 1. Stream the output events
        async for event in model.stream_response(
            system_prompt,
            input,
            model_settings,
            all_tools,
            output_schema,
            handoffs,
            get_model_tracing_impl(run_config.tracing_disabled, run_config.trace_include_sensitive_data),
        ):
            if isinstance(event, ResponseCompletedEvent):
                usage = (
                    Usage(
                        requests=1,
                        input_tokens=event.response.usage.input_tokens,
                        output_tokens=event.response.usage.output_tokens,
                        total_tokens=event.response.usage.total_tokens,
                    )
                    if event.response.usage
                    else Usage()
                )
                final_response = ModelResponse(
                    output=event.response.output,
                    usage=usage,
                    referenceable_id=event.response.id,
                )

            streamed_result._event_queue.put_nowait(RawResponsesStreamEvent(data=event))

        # 2. At this point, the streaming is complete for this turn of the agent loop.
        if not final_response:
            raise ModelBehaviorError("Model did not produce a final response!")

        # Accumulate usage on the shared context (parity with _get_new_response:1222).
        # Without this, a caller/hook reading context_wrapper.usage mid-stream saw
        # stale/zero usage during a streamed run.
        context_wrapper.usage.add(final_response.usage)

        # 3. Now, we can process the turn as we do in the non-streaming case
        single_step_result = None
        try:
            single_step_result = await cls._get_single_step_result_from_response(
                agent=agent,
                original_input=streamed_result.input,
                pre_step_items=streamed_result.new_items,
                new_response=final_response,
                output_schema=output_schema,
                all_tools=all_tools,
                handoffs=handoffs,
                hooks=hooks,
                context_wrapper=context_wrapper,
                run_config=run_config,
                tool_use_tracker=tool_use_tracker,
            )

            RunImpl.stream_step_result_to_queue(single_step_result, streamed_result._event_queue)
            return single_step_result
        except (KeyboardInterrupt, asyncio.CancelledError) as e:
            # When interrupted, we need to ensure the message history is consistent
            # The tool calls were already added during streaming, but results were not
            # If we have a partial result, stream it before re-raising
            if single_step_result:
                RunImpl.stream_step_result_to_queue(single_step_result, streamed_result._event_queue)
            raise e

    @classmethod
    async def _run_single_turn(
        cls,
        *,
        agent: Agent[TContext],
        all_tools: list[Tool],
        original_input: str | list[TResponseInputItem],
        generated_items: list[RunItem],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
        should_run_agent_start_hooks: bool,
        tool_use_tracker: AgentToolUseTracker,
    ) -> SingleStepResult:
        # Ensure we run the hooks before anything else
        if should_run_agent_start_hooks:
            await asyncio.gather(
                hooks.on_agent_start(context_wrapper, agent),
                (agent.hooks.on_start(context_wrapper, agent) if agent.hooks else _coro.noop_coroutine()),
            )

        system_prompt = await agent.get_system_prompt(context_wrapper)

        output_schema = cls._get_output_schema(agent)
        handoffs = cls._get_handoffs(agent)
        input = ItemHelpers.input_to_new_input_list(original_input)
        input.extend([generated_item.to_input_item() for generated_item in generated_items])

        new_response = await cls._get_new_response(
            agent,
            system_prompt,
            input,
            output_schema,
            all_tools,
            handoffs,
            context_wrapper,
            run_config,
            tool_use_tracker,
        )

        return await cls._get_single_step_result_from_response(
            agent=agent,
            original_input=original_input,
            pre_step_items=generated_items,
            new_response=new_response,
            output_schema=output_schema,
            all_tools=all_tools,
            handoffs=handoffs,
            hooks=hooks,
            context_wrapper=context_wrapper,
            run_config=run_config,
            tool_use_tracker=tool_use_tracker,
        )

    @classmethod
    async def _get_single_step_result_from_response(
        cls,
        *,
        agent: Agent[TContext],
        all_tools: list[Tool],
        original_input: str | list[TResponseInputItem],
        pre_step_items: list[RunItem],
        new_response: ModelResponse,
        output_schema: AgentOutputSchema | None,
        handoffs: list[Handoff],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
        tool_use_tracker: AgentToolUseTracker,
    ) -> SingleStepResult:
        processed_response = RunImpl.process_model_response(
            agent=agent,
            all_tools=all_tools,
            response=new_response,
            output_schema=output_schema,
            handoffs=handoffs,
        )

        # Log tools used with robust type checking
        if hasattr(processed_response, "tools_used") and processed_response.tools_used:
            for _i, tool_call in enumerate(processed_response.tools_used):
                try:
                    # Safely extract tool name with multiple fallbacks
                    try:
                        if hasattr(tool_call, "tool"):
                            if isinstance(tool_call.tool, str):
                                pass
                            elif hasattr(tool_call.tool, "name"):
                                pass
                            else:
                                str(tool_call.tool)
                    except Exception:
                        pass

                    # Safely extract call_id
                    try:
                        if hasattr(tool_call, "call_id"):
                            str(tool_call.call_id)
                    except Exception:
                        pass

                    # Safely extract parsed_args
                    try:
                        if hasattr(tool_call, "parsed_args"):
                            str(tool_call.parsed_args)
                    except Exception:
                        pass
                except Exception:
                    pass

        tool_use_tracker.add_tool_use(agent, processed_response.tools_used)

        return await RunImpl.execute_tools_and_side_effects(
            agent=agent,
            original_input=original_input,
            pre_step_items=pre_step_items,
            new_response=new_response,
            processed_response=processed_response,
            output_schema=output_schema,
            hooks=hooks,
            context_wrapper=context_wrapper,
            run_config=run_config,
        )

    @classmethod
    async def _run_input_guardrails(
        cls,
        agent: Agent[Any],
        guardrails: list[InputGuardrail[TContext]],
        input: str | list[TResponseInputItem],
        context: RunContextWrapper[TContext],
    ) -> list[InputGuardrailResult]:
        if not guardrails:
            return []

        guardrail_tasks = [
            asyncio.create_task(RunImpl.run_single_input_guardrail(agent, guardrail, input, context))
            for guardrail in guardrails
        ]

        guardrail_results = []

        for done in asyncio.as_completed(guardrail_tasks):
            result = await done
            if result.output.tripwire_triggered:
                # Cancel all guardrail tasks if a tripwire is triggered.
                for t in guardrail_tasks:
                    t.cancel()
                _error_tracing.attach_error_to_current_span(
                    SpanError(
                        message="Guardrail tripwire triggered",
                        data={"guardrail": result.guardrail.get_name()},
                    )
                )
                raise InputGuardrailTripwireTriggered(result)
            else:
                guardrail_results.append(result)

        return guardrail_results

    @classmethod
    async def _run_output_guardrails(
        cls,
        guardrails: list[OutputGuardrail[TContext]],
        agent: Agent[TContext],
        agent_output: Any,
        context: RunContextWrapper[TContext],
    ) -> list[OutputGuardrailResult]:
        if not guardrails:
            return []

        guardrail_tasks = [
            asyncio.create_task(RunImpl.run_single_output_guardrail(guardrail, agent, agent_output, context))
            for guardrail in guardrails
        ]

        guardrail_results = []

        for done in asyncio.as_completed(guardrail_tasks):
            result = await done
            if result.output.tripwire_triggered:
                # Cancel all guardrail tasks if a tripwire is triggered.
                for t in guardrail_tasks:
                    t.cancel()
                _error_tracing.attach_error_to_current_span(
                    SpanError(
                        message="Guardrail tripwire triggered",
                        data={"guardrail": result.guardrail.get_name()},
                    )
                )
                raise OutputGuardrailTripwireTriggered(result)
            else:
                guardrail_results.append(result)

        return guardrail_results

    @classmethod
    async def _get_new_response(
        cls,
        agent: Agent[TContext],
        system_prompt: str | None,
        input: list[TResponseInputItem],
        output_schema: AgentOutputSchema | None,
        all_tools: list[Tool],
        handoffs: list[Handoff],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
        tool_use_tracker: AgentToolUseTracker,
    ) -> ModelResponse:
        model = cls._get_model(agent, run_config)
        model_settings = agent.model_settings.resolve(run_config.model_settings)
        model_settings = RunImpl.maybe_reset_tool_choice(agent, tool_use_tracker, model_settings)
        # Copy before applying defaults — see the non-streaming path: resolve()
        # may return the agent's own model_settings, and the mutations below
        # must not leak onto the caller's agent.
        model_settings = replace(model_settings)
        # F155 — Default LLM temperature from env. Lower temperature
        # reduces hallucinations (R1 distill especially) at the cost
        # of creativity. Banca-safe default is 0.0; can be overridden
        # per-run via KRYON_LLM_TEMPERATURE or per-agent via the
        # ``model_settings.temperature`` field. Only set when the
        # caller hasn't already specified one.
        if model_settings.temperature is None:
            env_temp = os.environ.get("KRYON_LLM_TEMPERATURE", "").strip()
            if env_temp:
                try:
                    model_settings.temperature = float(env_temp)
                except ValueError:
                    pass
            else:

                # Greedy decoding (0.0) kills exploration for an agentic run — a
                # capable model varies enumeration/hypotheses at ~0.4. The 4B-local
                # default stays 0.0 (banca-safe reproducibility).
                model_settings.temperature = _default_temperature()

        # F184 — same reasoning_effort env propagation as the streaming
        # path above.
        if not getattr(model_settings, "reasoning_effort", None):
            env_effort = os.environ.get("KRYON_REASONING_EFFORT", "").strip().lower()
            if env_effort in {"low", "medium", "high"}:
                model_settings.reasoning_effort = env_effort

        # Ensure agent model is set in model_settings
        if not hasattr(model_settings, "agent_model") or not model_settings.agent_model:
            if isinstance(agent.model, str):
                model_settings.agent_model = agent.model
            elif isinstance(run_config.model, str):
                model_settings.agent_model = run_config.model

        new_response = await model.get_response(
            system_instructions=system_prompt,
            input=input,
            model_settings=model_settings,
            tools=all_tools,
            output_schema=output_schema,
            handoffs=handoffs,
            tracing=get_model_tracing_impl(run_config.tracing_disabled, run_config.trace_include_sensitive_data),
        )

        context_wrapper.usage.add(new_response.usage)

        return new_response

    @classmethod
    def _get_output_schema(cls, agent: Agent[Any]) -> AgentOutputSchema | None:
        if agent.output_type is None or agent.output_type is str:
            return None

        return AgentOutputSchema(agent.output_type)

    @classmethod
    def _get_handoffs(cls, agent: Agent[Any]) -> list[Handoff]:
        handoffs = []
        for handoff_item in agent.handoffs:
            if isinstance(handoff_item, Handoff):
                handoffs.append(handoff_item)
            elif isinstance(handoff_item, Agent):
                handoffs.append(handoff(handoff_item))
        return handoffs

    @classmethod
    async def _get_all_tools(cls, agent: Agent[Any]) -> list[Tool]:
        return await agent.get_all_tools()

    @classmethod
    def _get_model(cls, agent: Agent[Any], run_config: RunConfig) -> Model:
        model = None
        agent_model = None
        if isinstance(run_config.model, Model):
            model = run_config.model
        elif isinstance(run_config.model, str):
            model = run_config.model_provider.get_model(run_config.model)
            agent_model = run_config.model
        elif isinstance(agent.model, Model):
            model = agent.model
        else:
            model = run_config.model_provider.get_model(agent.model)
            agent_model = agent.model

        # Store the original agent model in model_settings for later use
        if agent_model and hasattr(agent, "model_settings"):
            agent.model_settings.agent_model = agent_model

        # Set agent name if the model supports it (for CLI display)
        if hasattr(model, "set_agent_name"):
            model.set_agent_name(agent.name)

        return model
