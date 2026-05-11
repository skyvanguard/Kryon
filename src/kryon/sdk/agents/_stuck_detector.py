"""F85.E — Triple-hash stuck-loop detector.

Patrón validado por prior art (Manus, agent-patterns, AutoGPT
post-mortem): hash ``(tool_name, sha256(args), sha256(result))``
para cada tool call que el agente ejecuta. Si el mismo triple aparece
3 veces dentro de una ventana deslizante de 5, el agente está
loopeando — emitir intervención al turno 2 (system message:
"reconsider approach") y abortar el run al turno 3 con ``StuckError``.

Distingue:

  * ``(nmap, {"target":"a"}, "open: 22")`` y
    ``(nmap, {"target":"b"}, "open: 80")``: tool igual, args distintos →
    polling legítimo, no se cuenta como duplicado.
  * ``(get_users, {}, "alice,bob")`` repetido 3 veces → loop real.

Cero estado global: cada ``StuckDetector`` vive dentro del
``RunContextWrapper`` para un único run; ``Runner.run`` instancia uno
nuevo por engagement.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections import deque
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class StuckAction:
    """Resultado de ``StuckDetector.record``: indica al runner qué hacer."""

    kind: str  # "continue" | "intervene" | "abort"
    tool_name: str = ""
    message: str = ""
    repeat_count: int = 0
    window_size: int = 0

    @classmethod
    def continue_(cls) -> StuckAction:
        return cls(kind="continue")

    @classmethod
    def intervene(cls, tool_name: str, count: int, window: int) -> StuckAction:
        return cls(
            kind="intervene",
            tool_name=tool_name,
            repeat_count=count,
            window_size=window,
            message=(
                f"You have called tool '{tool_name}' with identical arguments "
                f"and gotten the identical result {count} times in the last "
                f"{window} tool calls. This means you are not making progress. "
                f"Reconsider your approach: try a different tool, vary the "
                f"arguments, or stop and report partial findings if you have "
                f"exhausted reasonable options. Do NOT call '{tool_name}' "
                f"again with the same arguments."
            ),
        )

    @classmethod
    def abort(cls, tool_name: str, count: int, window: int) -> StuckAction:
        return cls(
            kind="abort",
            tool_name=tool_name,
            repeat_count=count,
            window_size=window,
        )


def _hash_args(args: Any) -> str:
    """Stable hash of arbitrary tool args.

    Tool args llegan como string JSON (Pydantic-serializable) o como
    dict. Normalizamos a JSON con ``sort_keys`` para que
    ``{"a":1,"b":2}`` y ``{"b":2,"a":1}`` colapsen al mismo hash.
    Fallamos suavemente — si los args no son JSON-serializable
    (rare path) usamos ``repr`` como hash key.
    """
    try:
        if isinstance(args, str):
            try:
                parsed = json.loads(args) if args else {}
            except json.JSONDecodeError:
                parsed = args  # tratar como string opaco
        else:
            parsed = args
        canonical = json.dumps(parsed, sort_keys=True, default=str)
    except (TypeError, ValueError):
        canonical = repr(args)
    return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()[:16]


def _hash_result(result: Any) -> str:
    """Stable hash of a tool result. Strings (tool outputs típicos
    del SDK) van directo; objetos los pasamos por ``repr``."""
    if not isinstance(result, str):
        try:
            result = json.dumps(result, sort_keys=True, default=str)
        except (TypeError, ValueError):
            result = repr(result)
    return hashlib.sha256(result.encode("utf-8", errors="replace")).hexdigest()[:16]


class StuckDetector:
    """Sliding-window detector de tool-call loops.

    Default config viene del consenso del prior art: ventana 5,
    intervención al 2do duplicado, abort al 3ro. Ajustable per-run vía
    ``KRYON_STUCK_WINDOW`` / ``KRYON_STUCK_INTERVENE_AT`` /
    ``KRYON_STUCK_ABORT_AT`` env vars para experimentación.
    """

    def __init__(
        self,
        *,
        window_size: int = 5,
        intervene_at: int = 2,
        abort_at: int = 3,
    ) -> None:
        if abort_at <= intervene_at:
            raise ValueError(
                f"abort_at ({abort_at}) must be > intervene_at ({intervene_at})"
            )
        if intervene_at < 2:
            raise ValueError("intervene_at must be >= 2 (1 = first call, no repeat yet)")
        self.window_size = window_size
        self.intervene_at = intervene_at
        self.abort_at = abort_at
        # Recent triples in chronological order; older entries fall off.
        self._window: deque[tuple[str, str, str]] = deque(maxlen=window_size)
        # Track which triples we've already intervened on so the same
        # loop doesn't yield two intervene actions before abort.
        self._intervened: set[tuple[str, str, str]] = set()

    def record(self, tool_name: str, args: Any, result: Any) -> StuckAction:
        """Record a completed tool call and return the recommended
        next action.

        ``args`` can be a JSON string (typical SDK shape) or a dict.
        ``result`` can be any tool output. Both get content-hashed so
        differently-shaped equivalent inputs collapse to the same
        triple.
        """
        triple = (tool_name, _hash_args(args), _hash_result(result))
        self._window.append(triple)
        count = sum(1 for t in self._window if t == triple)

        if count >= self.abort_at:
            logger.warning(
                "StuckDetector: aborting on '%s' (%d/%d identical triples in window of %d)",
                tool_name, count, self.abort_at, self.window_size,
            )
            return StuckAction.abort(tool_name, count, self.window_size)

        if count >= self.intervene_at and triple not in self._intervened:
            self._intervened.add(triple)
            logger.info(
                "StuckDetector: intervening on '%s' (%d/%d identical triples in window of %d)",
                tool_name, count, self.intervene_at, self.window_size,
            )
            return StuckAction.intervene(tool_name, count, self.window_size)

        return StuckAction.continue_()

    def reset(self) -> None:
        """Reset window — useful for tests, and for the orchestrator
        to call between phases when the agent moves to a new sub-goal
        with a fresh tool budget."""
        self._window.clear()
        self._intervened.clear()
