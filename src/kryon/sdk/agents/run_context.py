from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Generic, Optional

from typing_extensions import TypeVar

from .usage import Usage

if TYPE_CHECKING:
    from kryon.audit.action_log import ActionLog

    from ._stuck_detector import StuckDetector

TContext = TypeVar("TContext", default=Any)


@dataclass
class RunContextWrapper(Generic[TContext]):
    """This wraps the context object that you passed to `Runner.run()`. It also contains
    information about the usage of the agent run so far.

    NOTE: Contexts are not passed to the LLM. They're a way to pass dependencies and data to code
    you implement, like tool functions, callbacks, hooks, etc.
    """

    context: TContext
    """The context object (or None), passed by you to `Runner.run()`"""

    usage: Usage = field(default_factory=Usage)
    """The usage of the agent run so far. For streamed responses, the usage will be stale until the
    last chunk of the stream is processed.
    """

    stuck_detector: Optional["StuckDetector"] = None
    """F85.E — Per-run loop detector. Populated by ``Runner.run`` at the
    start of each engagement. After each tool call, ``_run_impl`` calls
    ``stuck_detector.record(...)`` and may inject a system message
    ("intervene") or raise ``StuckError`` ("abort") if the same
    (tool, args, result) triple repeats too many times."""

    audit_log: Optional["ActionLog"] = None
    """F123 — Granular forensic audit log. When set, ``_run_impl`` appends
    one JSONL entry per tool call (not only per phase boundary) so post-
    engagement we can answer "what did Kryon do at 14:32?" at tool-level
    granularity. Args + result pass through the PAN redactor before
    persistence. Optional — None means tool-level audit is disabled and
    only the phase-level audit applies."""

    audit_phase: str = "agent"
    """F123 — Phase name to tag every per-tool audit entry with. Set by
    the orchestrator before each phase invocation so the audit log
    associates tool calls with the phase that generated them. Defaults
    to ``"agent"`` for single-shot agent runs that don't use the multi-
    phase orchestrator."""
