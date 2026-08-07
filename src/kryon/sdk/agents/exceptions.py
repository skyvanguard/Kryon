from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .guardrail import InputGuardrailResult, OutputGuardrailResult


class AgentsException(Exception):
    """Base class for all exceptions in the KRYON Agents."""


class MaxTurnsExceeded(AgentsException):
    """Exception raised when the maximum number of turns is exceeded."""

    message: str

    def __init__(self, message: str):
        self.message = message


class ModelBehaviorError(AgentsException):
    """Exception raised when the model does something unexpected, e.g. calling a tool that doesn't
    exist, or providing malformed JSON.
    """

    message: str

    def __init__(self, message: str):
        self.message = message


class UserError(AgentsException):
    """Exception raised when the user makes an error using KRYON."""

    message: str

    def __init__(self, message: str):
        self.message = message


class InputGuardrailTripwireTriggered(AgentsException):
    """Exception raised when a guardrail tripwire is triggered."""

    guardrail_result: "InputGuardrailResult"
    """The result data of the guardrail that was triggered."""

    def __init__(self, guardrail_result: "InputGuardrailResult"):
        self.guardrail_result = guardrail_result
        super().__init__(f"Guardrail {guardrail_result.guardrail.__class__.__name__} triggered tripwire")


class OutputGuardrailTripwireTriggered(AgentsException):
    """Exception raised when a guardrail tripwire is triggered."""

    guardrail_result: "OutputGuardrailResult"
    """The result data of the guardrail that was triggered."""

    def __init__(self, guardrail_result: "OutputGuardrailResult"):
        self.guardrail_result = guardrail_result
        super().__init__(f"Guardrail {guardrail_result.guardrail.__class__.__name__} triggered tripwire")


class PriceLimitExceeded(AgentsException):
    """Raised when the maximum price limit is exceeded."""

    def __init__(self, current_cost: float, price_limit: float):
        super().__init__(f"Maximum price limit (${price_limit:.4f}) exceeded. Current cost: ${current_cost:.4f}")


class StuckError(AgentsException):
    """F85.E — Raised by the StuckDetector when the same
    ``(tool_name, args_hash, result_hash)`` triple repeats too many
    times within the sliding window, signalling the agent is looping
    on a step it cannot make progress on.

    The exception carries the offending triple and the count so the
    orchestrator can decide how to render the failure to the user
    (typically: structured ``outcome="stuck"`` instead of a crash).
    """

    def __init__(self, tool_name: str, repeat_count: int, window_size: int):
        self.tool_name = tool_name
        self.repeat_count = repeat_count
        self.window_size = window_size
        super().__init__(
            f"Agent stuck on tool '{tool_name}': "
            f"identical (tool, args, result) triple seen {repeat_count} times "
            f"in last {window_size} calls. Aborting run."
        )
