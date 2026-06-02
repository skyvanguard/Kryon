"""P0 — Shared classification of *recoverable* run-termination exceptions.

The three entry points that drive an agent run used to disagree on how they
treat a run that ends early:

* ``kryon investigate`` (``cli/investigate.py``) catches everything and emits a
  PARTIAL report,
* the reflective runner (``cli/reflective_runner.py``) finalizes ``StuckError``
  / ``MaxTurnsExceeded`` gracefully with whatever it captured,
* but the REST route (``server/routes/runs.py``) re-raised the *same*
  exceptions as ``HTTP 500 — internal error``.

That asymmetry is what turned a stuck-loop in the CyberGym bench into an opaque
500. This module is the single source of truth: it maps a run-termination
exception to a structured :class:`RunOutcome` (``stuck`` / ``incomplete`` /
``budget_exceeded``) so every caller renders the SAME partial-result semantics
instead of one crashing while another salvages.

A ``None`` return means "this is a genuine crash, not a graceful early stop" —
the caller should propagate it.
"""

from __future__ import annotations

from dataclasses import dataclass

from .exceptions import MaxTurnsExceeded, PriceLimitExceeded, StuckError

# Exceptions that signal a *graceful* early termination whose partial output is
# still worth surfacing — NOT a server error. Callers can use this tuple in an
# ``except`` clause; use :func:`classify_run_exception` to get the structured
# outcome.
RECOVERABLE_RUN_EXCEPTIONS: tuple[type[BaseException], ...] = (
    StuckError,
    MaxTurnsExceeded,
    PriceLimitExceeded,
)


@dataclass(frozen=True)
class RunOutcome:
    """A structured description of a run that ended early but recoverably."""

    status: str
    """Machine-readable outcome: ``stuck`` | ``incomplete`` | ``budget_exceeded``."""

    message: str
    """Human-facing note explaining the partial result (Spanish, UI-facing)."""


def classify_run_exception(exc: BaseException) -> RunOutcome | None:
    """Map a run-termination exception to a :class:`RunOutcome`.

    Returns ``None`` when ``exc`` is NOT a recognised graceful-stop exception —
    i.e. a real crash the caller should re-raise / surface as a 500.
    """
    if isinstance(exc, StuckError):
        tool = getattr(exc, "tool_name", "") or "?"
        return RunOutcome(
            status="stuck",
            message=(
                f"⚠️ El agente entró en un loop irrecuperable sobre la tool "
                f"'{tool}' (misma llamada repetida) y el run se detuvo para no "
                f"consumir presupuesto repitiéndose. La salida es PARCIAL y "
                f"requiere verificación."
            ),
        )
    if isinstance(exc, MaxTurnsExceeded):
        return RunOutcome(
            status="incomplete",
            message=(
                "⚠️ El agente alcanzó el máximo de turnos antes de producir una "
                "respuesta final. La salida es PARCIAL y debe continuarse o "
                "re-ejecutarse con más presupuesto."
            ),
        )
    if isinstance(exc, PriceLimitExceeded):
        return RunOutcome(
            status="budget_exceeded",
            message=(f"⚠️ Se alcanzó el límite de presupuesto durante el run ({exc}). La salida es PARCIAL."),
        )
    return None
