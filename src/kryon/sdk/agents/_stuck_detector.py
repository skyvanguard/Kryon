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

Segunda señal — ACTION-only (tool+args, sin result). El triple incluye
el ``result_hash``, así que una acción idéntica cuyo output sólo cambia
trivialmente (una búsqueda web cuyo line-count varía, un comando con
timestamp) NUNCA matchea el triple y el detector quedaba ciego — el loop
de duckduckgo real. Se trackea aparte ``(tool, args)`` con umbrales más
laxos (intervención al 4to, abort al 6to) porque es señal más débil que
el triple y una ráfaga corta puede ser polling/paginación legítima.

Cero estado global: cada ``StuckDetector`` vive dentro del
``RunContextWrapper`` para un único run; ``Runner.run`` instancia uno
nuevo por engagement.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
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
    def intervene(cls, tool_name: str, count: int, window: int, *, is_final: bool = False) -> StuckAction:
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
    def intervene_variable(cls, tool_name: str, count: int, window: int, *, is_final: bool = False) -> StuckAction:
        """Nudge for an ACTION loop: same tool+args repeated, but the result
        varies slightly each time (e.g. a web search whose line-count drifts,
        a command with a timestamp). The triple never matches so the
        result-aware path stays silent — but re-issuing the identical action
        is still a loop. The message names that specifically."""
        if is_final:
            message = (
                f"⚠️ LAST WARNING before this run is aborted. You have issued the "
                f"SAME action — tool '{tool_name}' with identical arguments — "
                f"{count} times. The result only changes trivially (counts, "
                f"timestamps); you are NOT making progress. Repeating it once "
                f"more STOPS the run. Do exactly ONE of:\n"
                f"  1. PIVOT — a concretely DIFFERENT action (different "
                f"query/endpoint/parameter/tool/target).\n"
                f"  2. CONCLUDE — emit your FINAL report NOW with what you have "
                f"already confirmed.\n"
                f"Do NOT call '{tool_name}' with the same arguments again."
            )
        else:
            message = (
                f"You have issued the SAME action — tool '{tool_name}' with "
                f"identical arguments — {count} times in the last {window} calls. "
                f"The result barely changes; re-issuing it is not progress. "
                f"Change the query/endpoint/parameter, switch tools, or pivot to "
                f"another target. Do NOT repeat this exact call."
            )
        return cls(
            kind="intervene",
            tool_name=tool_name,
            repeat_count=count,
            window_size=window,
            message=message,
        )

    @classmethod
    def intervene_noprogress(cls, tool_name: str, count: int, window: int, *, is_final: bool = False) -> StuckAction:
        """Nudge for a NO-PROGRESS loop: the SAME tool returned the SAME result while
        the agent VARIED its arguments — different question, identical answer. Both
        args-keyed bands (triple + action) stay silent because the args differ every
        call, so this is the only signal that sees it. Classic shape that slipped
        through before: the model re-issues DIFFERENT planner directives (or re-reads a
        file with slightly different params) that all return the same source/output —
        10 'successful' calls, zero new information, no exploitation step ever taken."""
        if is_final:
            message = (
                f"⚠️ LAST WARNING before this run is aborted. Tool '{tool_name}' has "
                f"returned the SAME result {count} times even though you changed its "
                f"arguments — you are re-deriving information you ALREADY have and making "
                f"no progress. One more and the run STOPS. Do exactly ONE:\n"
                f"  1. ACT — take the next CONCRETE step with what you already know "
                f"(send the forged/exploit request, run the command), not more analysis.\n"
                f"  2. CONCLUDE — emit your FINAL report now.\n"
                f"Do NOT call '{tool_name}' again to re-derive the same thing."
            )
        else:
            message = (
                f"Tool '{tool_name}' returned the SAME result {count} times in the last "
                f"{window} calls despite DIFFERENT arguments — you are not learning "
                f"anything new, just re-analyzing. STOP analyzing and ACT: take the next "
                f"concrete exploitation step with the information you already have, or conclude."
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


# Generic negative/error responses that are NORMAL during enumeration. Five
# different paths returning "404 Not Found" is recon, not a re-derivation loop —
# so they must NOT count toward the args-independent RESULT band, which was
# aborting legitimate sweeps (and 5 identical connection timeouts likewise).
_GENERIC_NEGATIVE_RE = re.compile(
    r"(?:40[0-9]\b|not found|forbidden|unauthorized|connection (?:refused|timed out|reset)|"
    r"no route to host|could not resolve|timed out|empty reply|no such file)",
    re.IGNORECASE,
)


def _is_generic_negative(text: str) -> bool:
    """True when ``text`` looks like a generic negative/error response (404/403/
    timeout/refused) — expected, repeatable output during enumeration."""
    return bool(_GENERIC_NEGATIVE_RE.search(text[:400]))


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
    # Same L4 canonicalization the result hash uses (``_normalize_volatile`` is a
    # module-level global, resolved at call time): two curl calls that differ only in
    # a drifting session cookie / CSRF token (``-H "Cookie: session=.eJw…"``) are the
    # SAME action and must collapse so the ACTION band can catch a web loop.
    canonical = _normalize_volatile(canonical)
    return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()[:16]


# L4 — volatile tokens that make two otherwise-identical outputs (esp. tool
# ERRORS: "timeout after 30.1s", "pid 8412", "0x7ffe…", "/tmp/x8f2") hash
# differently, so a deterministically-broken tool retried with a drifting error
# string slips past every stuck band. Canonicalize them before hashing so the
# repeat collapses to one signature and the detector can catch it.
_VOLATILE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<TS>"),
    (re.compile(r"\b\d+(?:\.\d+)?\s*(?:ms|µs|us|ns|s|sec|secs|seconds|min|mins|minutes?|h|hours?)\b", re.I), "<DUR>"),
    (re.compile(r"\b(?:pid|PID|tid|TID)[\s:=#]*\d+"), "<PID>"),
    (re.compile(r"0x[0-9a-fA-F]{3,}"), "<ADDR>"),
    (re.compile(r"/tmp/[^\s'\"]+|/var/folders/[^\s'\"]+"), "<TMP>"),
    # Signed session cookies / auth tokens / CSRF / JWT — volatile auth material.
    # A web loop (POST /upload → GET /dashboard) slips past every band because the
    # server (Flask itsdangerous, PHP, ASP.NET, …) mints a fresh signed cookie each
    # turn, so two semantically identical HTTP exchanges hash differently. Observed
    # live vs a THM room: 9 distinct ``session=.eJw…`` cookies across one POST/GET
    # loop → result_hash never collided → the detector never fired (4855+ lines).
    (
        re.compile(
            r"(?i)\b(?:session|sessionid|sess|sid|phpsessid|jsessionid|asp\.net_sessionid"
            r"|csrf[_-]?token|csrftoken|xsrf[_-]?token|_csrf|authenticity_token"
            r"|access[_-]?token|refresh[_-]?token|auth[_-]?token|id[_-]?token|token"
            r"|bearer|api[_-]?key|apikey)"
            r"\s*[=:]\s*\.?[A-Za-z0-9._~+/\-]{8,}=*"
        ),
        "<TOKEN>",
    ),
    # Bare JWT / signed-cookie payloads (``eyJ…`` header, or Flask's ``.eJw…``) that
    # appear without a ``key=`` prefix (Set-Cookie value, Authorization body, HTML).
    (re.compile(r"\.?e[yJ][A-Za-z0-9._~+/\-]{16,}=*"), "<JWT>"),
    (re.compile(r"\b\d{6,}\b"), "<N>"),  # long digit runs (ports/small counts kept)
]


def _normalize_volatile(text: str) -> str:
    for pat, repl in _VOLATILE_PATTERNS:
        text = pat.sub(repl, text)
    return text


def _hash_result(result: Any) -> str:
    """Stable hash of a tool result. Strings (tool outputs típicos
    del SDK) van directo; objetos los pasamos por ``repr``. Volatile tokens
    (timestamps/pids/addresses/durations) are canonicalized first (L4)."""
    if not isinstance(result, str):
        try:
            result = json.dumps(result, sort_keys=True, default=str)
        except (TypeError, ValueError):
            result = repr(result)
    result = _normalize_volatile(result)
    return hashlib.sha256(result.encode("utf-8", errors="replace")).hexdigest()[:16]


class StuckDetector:
    """Sliding-window detector de tool-call loops.

    Defaults del ``__init__`` (banda triple): ventana 6, intervención al 2do
    duplicado, abort al 4to. El runtime NO instancia con estos defaults directo
    — ``Runner`` usa el factory ``run._build_stuck_detector()``, cuyo default
    efectivo es **ventana 8** / intervene 2 / abort 4, ajustable per-run vía
    ``KRYON_STUCK_WINDOW`` / ``KRYON_STUCK_INTERVENE_AT`` / ``KRYON_STUCK_ABORT_AT``.
    Las bandas action (4/6) y result (3/5) usan sus propios defaults (abajo).
    """

    # Tools whose CONTRACT is "identical args every call, evolving result": each
    # identical-args invocation advances internal state (execute_planner_directive
    # walks the planner ONE step per call — mass-assign → traversal → … — so the args
    # stay `{}` while the result changes). The ACTION band (args-only) is a FALSE
    # POSITIVE for them: it fires on the repeated identical args even though the result
    # varies = real progress (observed live: the Juice Shop e2e run aborted at turn 8
    # with "6/6 identical ACTIONS — result varies" while the planner was advancing).
    # The TRIPLE and RESULT bands still apply — a genuinely stuck planner returns the
    # SAME directive (same result), which those bands catch.
    _DEFAULT_ADVANCE_TOOLS = frozenset({"execute_planner_directive"})

    def __init__(
        self,
        *,
        window_size: int = 6,
        intervene_at: int = 2,
        abort_at: int = 4,
        action_intervene_at: int = 4,
        action_abort_at: int = 6,
        result_intervene_at: int = 3,
        result_abort_at: int = 5,
        advance_tools: frozenset[str] | None = None,
    ) -> None:
        if abort_at <= intervene_at:
            raise ValueError(f"abort_at ({abort_at}) must be > intervene_at ({intervene_at})")
        if intervene_at < 2:
            raise ValueError("intervene_at must be >= 2 (1 = first call, no repeat yet)")
        if action_abort_at <= action_intervene_at:
            raise ValueError(
                f"action_abort_at ({action_abort_at}) must be > action_intervene_at ({action_intervene_at})"
            )
        if action_intervene_at < 2:
            raise ValueError("action_intervene_at must be >= 2")
        if result_abort_at <= result_intervene_at:
            raise ValueError(
                f"result_abort_at ({result_abort_at}) must be > result_intervene_at ({result_intervene_at})"
            )
        if result_intervene_at < 2:
            raise ValueError("result_intervene_at must be >= 2")
        self.window_size = window_size
        self.intervene_at = intervene_at
        self.abort_at = abort_at
        # Action thresholds are deliberately MORE lenient than the triple ones:
        # an identical (tool, args) whose result only drifts trivially is a
        # weaker loop signal than an identical (tool, args, result), and a short
        # burst can be legitimate polling/pagination — so it gets more rope
        # before we nudge (4) or abort (6). This catches the variable-output
        # loops (e.g. a web search whose line-count changes each call) that the
        # result-aware triple silently misses.
        self.action_intervene_at = action_intervene_at
        self.action_abort_at = action_abort_at
        # Result-keyed band: the ARGS-INDEPENDENT twin of the action band. Catches the
        # loop both args-keyed bands miss — same tool, same OUTPUT, VARYING args (the
        # model re-issues different planner directives / re-reads the same file and gets
        # the same answer every time). Tighter than the action band (3/5 vs 4/6): "same
        # answer to a different question" is a stronger no-progress signal than "same
        # question, drifting answer".
        self.result_intervene_at = result_intervene_at
        self.result_abort_at = result_abort_at
        self._advance_tools = self._DEFAULT_ADVANCE_TOOLS if advance_tools is None else advance_tools
        # L5 — an abort threshold larger than the window can NEVER be reached
        # (it needs N identical entries in a window < N), silently disabling
        # that band when KRYON_STUCK_WINDOW is shrunk below the fixed action/
        # result thresholds. Clamp every abort to the window and keep each
        # intervene within [2, abort-1] so all three bands stay reachable.
        self.abort_at = min(self.abort_at, window_size)
        self.action_abort_at = min(self.action_abort_at, window_size)
        self.result_abort_at = min(self.result_abort_at, window_size)
        self.intervene_at = max(2, min(self.intervene_at, self.abort_at - 1))
        self.action_intervene_at = max(2, min(self.action_intervene_at, self.action_abort_at - 1))
        self.result_intervene_at = max(2, min(self.result_intervene_at, self.result_abort_at - 1))
        # Recent triples in chronological order; older entries fall off.
        self._window: deque[tuple[str, str, str]] = deque(maxlen=window_size)
        # Recent (tool, args) actions — result-independent — same window.
        self._action_window: deque[tuple[str, str]] = deque(maxlen=window_size)
        # Recent (tool, result) — args-independent — same window.
        self._result_window: deque[tuple[str, str]] = deque(maxlen=window_size)
        # Track (triple, repeat_count) pairs we've already nudged on, so each
        # distinct count in the warning band [intervene_at, abort_at) fires
        # exactly one (escalating) intervention — instead of going silent
        # after the first one, which left the model no second chance to pivot.
        self._intervened: set[tuple[tuple[str, str, str], int]] = set()
        # Same idea for the action-only band.
        self._action_intervened: set[tuple[tuple[str, str], int]] = set()
        # And for the result-only band.
        self._result_intervened: set[tuple[tuple[str, str], int]] = set()

    def record(self, tool_name: str, args: Any, result: Any) -> StuckAction:
        """Record a completed tool call and return the recommended
        next action.

        ``args`` can be a JSON string (typical SDK shape) or a dict.
        ``result`` can be any tool output. Both get content-hashed so
        differently-shaped equivalent inputs collapse to the same
        triple.
        """
        args_hash = _hash_args(args)
        result_hash = _hash_result(result)
        triple = (tool_name, args_hash, result_hash)
        self._window.append(triple)
        count = sum(1 for t in self._window if t == triple)

        # Result-independent action signal — same (tool, args), result may drift.
        # Advance-style tools (execute_planner_directive) are EXEMPT: identical args
        # every call is their contract, and each call advances the planner (result
        # varies). Counting them here false-positives; the TRIPLE/RESULT bands still
        # catch a genuine same-directive loop.
        action = (tool_name, args_hash)
        if tool_name in self._advance_tools:
            action_count = 0
        else:
            self._action_window.append(action)
            action_count = sum(1 for a in self._action_window if a == action)

        # Args-independent RESULT signal — same (tool, result), args may differ. The
        # twin the design was missing: catches "different question, identical answer"
        # loops (re-issued planner directives / re-reads that keep returning the same
        # source). Skip trivially-small outputs ("" / one-liners) — those aren't a
        # re-derivation loop and the args-keyed bands already cover repeated-args cases.
        result_meaningful = len(result) >= 24 if isinstance(result, str) else True
        # Generic negatives (404/403/timeout/refused) are expected during
        # enumeration — excluding them stops the RESULT band aborting a legitimate
        # sweep of many paths that all 404.
        if result_meaningful and isinstance(result, str) and _is_generic_negative(result):
            result_meaningful = False
        result_key = (tool_name, result_hash)
        self._result_window.append(result_key if result_meaningful else ("", ""))
        result_count = sum(1 for r in self._result_window if r == result_key) if result_meaningful else 0

        # --- Hard aborts (triple first: it's the stronger signal) ---
        if count >= self.abort_at:
            logger.warning(
                "StuckDetector: aborting on '%s' (%d/%d identical triples in window of %d)",
                tool_name,
                count,
                self.abort_at,
                self.window_size,
            )
            return StuckAction.abort(tool_name, count, self.window_size)
        if action_count >= self.action_abort_at:
            logger.warning(
                "StuckDetector: aborting on '%s' (%d/%d identical ACTIONS — result varies — in window of %d)",
                tool_name,
                action_count,
                self.action_abort_at,
                self.window_size,
            )
            return StuckAction.abort(tool_name, action_count, self.window_size)
        if result_count >= self.result_abort_at:
            logger.warning(
                "StuckDetector: aborting on '%s' (%d/%d identical RESULTS — args vary — in window of %d)",
                tool_name,
                result_count,
                self.result_abort_at,
                self.window_size,
            )
            return StuckAction.abort(tool_name, result_count, self.window_size)

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
                    "StuckDetector: intervening on '%s' (count=%d, final=%s, window=%d)",
                    tool_name,
                    count,
                    is_final,
                    self.window_size,
                )
                return StuckAction.intervene(tool_name, count, self.window_size, is_final=is_final)

        # Action-only intervention — fires when the triple path stays silent
        # because the result drifts (the duckduckgo case). More lenient band.
        if self.action_intervene_at <= action_count < self.action_abort_at:
            akey = (action, action_count)
            if akey not in self._action_intervened:
                self._action_intervened.add(akey)
                is_final = action_count >= self.action_abort_at - 1
                logger.info(
                    "StuckDetector: action-intervening on '%s' (action_count=%d, final=%s, window=%d)",
                    tool_name,
                    action_count,
                    is_final,
                    self.window_size,
                )
                return StuckAction.intervene_variable(tool_name, action_count, self.window_size, is_final=is_final)

        # Result-only intervention — fires when both args-keyed bands stay silent
        # because the args differ each call, yet the tool keeps returning the same
        # output (the re-analysis loop). Tighter band: 3 → final at abort_at-1.
        if result_meaningful and self.result_intervene_at <= result_count < self.result_abort_at:
            rkey = (result_key, result_count)
            if rkey not in self._result_intervened:
                self._result_intervened.add(rkey)
                is_final = result_count >= self.result_abort_at - 1
                logger.info(
                    "StuckDetector: result-intervening on '%s' (result_count=%d, final=%s, window=%d)",
                    tool_name,
                    result_count,
                    is_final,
                    self.window_size,
                )
                return StuckAction.intervene_noprogress(tool_name, result_count, self.window_size, is_final=is_final)

        return StuckAction.continue_()

    def reset(self) -> None:
        """Reset window — useful for tests, and for the orchestrator
        to call between phases when the agent moves to a new sub-goal
        with a fresh tool budget."""
        self._window.clear()
        self._intervened.clear()
        self._action_window.clear()
        self._action_intervened.clear()
        self._result_window.clear()
        self._result_intervened.clear()
