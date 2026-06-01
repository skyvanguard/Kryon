"""F85.E — Triple-hash stuck-loop detector.

Patrón validado por prior art (Manus, agent-patterns, AutoGPT
post-mortem): hash ``(tool_name, sha256(args), sha256(result))``
para cada tool call que el agente ejecuta. Si el mismo triple se
repite dentro de una ventana deslizante, el agente está loopeando.

Default (post fix-pivot): ventana 6, intervención al 2do duplicado y
al 3ro (mensaje escalado "reconsider approach" → "ÚLTIMA advertencia:
pivotá a un ángulo concreto o emití el reporte final ya"), abort al
4to con ``StuckError``. Dar DOS nudges accionables antes de abortar le
da al agente margen real para pivotar en vez de morir al primer
repeat. El abort sigue siendo el tope duro (bounded, banca-safe).

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
    def intervene(
        cls, tool_name: str, count: int, window: int, *, is_final: bool = False
    ) -> StuckAction:
        """Build an actionable "you are looping" nudge.

        ``is_final`` (the last warning before abort) escalates the tone and
        hard-forces a binary choice: pivot to a concretely different action,
        or emit the final report now. The non-final nudge is softer but still
        enumerates concrete pivot angles so the model has somewhere to go
        instead of re-sending the same call.
        """
        if is_final:
            message = (
                f"⚠️ LAST WARNING before this run is aborted. You have repeated "
                f"tool '{tool_name}' with identical arguments and the identical "
                f"result {count} times. Repeating it once more STOPS the run. "
                f"You MUST now do exactly ONE of:\n"
                f"  1. PIVOT — issue a concretely DIFFERENT action: a different "
                f"endpoint/path, a different parameter or HTTP method, a "
                f"different tool, or a different target host. Never re-send the "
                f"same call.\n"
                f"  2. CONCLUDE — emit your FINAL report NOW summarizing what "
                f"you have ALREADY confirmed, even if it is partial.\n"
                f"Pick one. Do NOT call '{tool_name}' with the same arguments."
            )
        else:
            message = (
                f"You have called tool '{tool_name}' with identical arguments "
                f"and gotten the identical result {count} times in the last "
                f"{window} tool calls — you are not making progress. Change your "
                f"approach NOW: try a different endpoint/path, a different "
                f"parameter or HTTP method, a different tool, or pivot to a new "
                f"target host. If you have genuinely exhausted reasonable "
                f"options, stop and report partial findings. Do NOT call "
                f"'{tool_name}' again with the same arguments."
            )
        return cls(
            kind="intervene",
            tool_name=tool_name,
            repeat_count=count,
            window_size=window,
            message=message,
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
        window_size: int = 6,
        intervene_at: int = 2,
        abort_at: int = 4,
    ) -> None:
        if abort_at <= intervene_at:
            raise ValueError(f"abort_at ({abort_at}) must be > intervene_at ({intervene_at})")
        if intervene_at < 2:
            raise ValueError("intervene_at must be >= 2 (1 = first call, no repeat yet)")
        self.window_size = window_size
        self.intervene_at = intervene_at
        self.abort_at = abort_at
        # Recent triples in chronological order; older entries fall off.
        self._window: deque[tuple[str, str, str]] = deque(maxlen=window_size)
        # Track (triple, repeat_count) pairs we've already nudged on, so each
        # distinct count in the warning band [intervene_at, abort_at) fires
        # exactly one (escalating) intervention — instead of going silent
        # after the first one, which left the model no second chance to pivot.
        self._intervened: set[tuple[tuple[str, str, str], int]] = set()

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
                tool_name,
                count,
                self.abort_at,
                self.window_size,
            )
            return StuckAction.abort(tool_name, count, self.window_size)

        # Intervene once per distinct repeat-count inside the warning band
        # [intervene_at, abort_at). Each higher count escalates; the count
        # immediately before abort_at is the final warning. Keying on
        # (triple, count) — not just triple — lets us re-nudge as the loop
        # tightens instead of staying silent after the first intervention.
        if self.intervene_at <= count < self.abort_at:
            key = (triple, count)
            if key not in self._intervened:
                self._intervened.add(key)
                is_final = count >= self.abort_at - 1
                logger.info(
                    "StuckDetector: intervening on '%s' (count=%d, final=%s, "
                    "window=%d)",
                    tool_name,
                    count,
                    is_final,
                    self.window_size,
                )
                return StuckAction.intervene(
                    tool_name, count, self.window_size, is_final=is_final
                )

        return StuckAction.continue_()

    def reset(self) -> None:
        """Reset window — useful for tests, and for the orchestrator
        to call between phases when the agent moves to a new sub-goal
        with a fresh tool budget."""
        self._window.clear()
        self._intervened.clear()
