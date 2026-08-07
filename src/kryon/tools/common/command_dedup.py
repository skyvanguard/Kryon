"""Run-scoped dedup for repeated identical commands.

The top live failure of the reflective loop was the model repeating the SAME
stateless command (a `curl ... UNION SELECT ...` probe) without advancing —
Laguna's stuck-abort at turn 16 ("identical triple seen 5 times") and V4-Flash's
recon-curl spin were both this. The StuckDetector caught it but *aborted* the run
instead of redirecting it.

This breaks the loop earlier and more usefully: on the 3rd identical run of a
stateless command, short-circuit with a directive that says "you already have
this result — take the NEXT step", instead of re-executing into an abort. The
1st and 2nd runs still execute (a legit double-check is allowed).

Bounded LRU so state can't grow unbounded. Per-process — a CLI investigate run is
one process; exact-command match keeps cross-run collisions negligible.
"""

from __future__ import annotations

import re
from collections import OrderedDict

_MAX_TRACKED = 60
_SUPPRESS_AT = 3  # execute the 1st + 2nd (grace); suppress the 3rd and later
_counts: OrderedDict[str, int] = OrderedDict()


def _normalize(command: str) -> str:
    return re.sub(r"\s+", " ", (command or "").strip())


def check_repeat(command: str) -> str | None:
    """Record ``command`` and, if it is the 3rd+ identical stateless execution,
    return a 'stop repeating, advance' directive; otherwise return None so the
    caller runs the command normally."""
    key = _normalize(command)
    if not key:
        return None
    n = _counts.get(key, 0) + 1
    _counts[key] = n
    _counts.move_to_end(key)
    while len(_counts) > _MAX_TRACKED:
        _counts.popitem(last=False)
    # A capable model may re-run an identical probe with intent (after changing a
    # precondition elsewhere — uploaded a file, forged a token — so the result WILL
    # differ). Give it more grace before suppressing; the 4B (which loops the same curl)
    # keeps the tight bound.
    suppress_at = _SUPPRESS_AT
    try:
        from kryon.util.env import is_capable_model  # noqa: PLC0415

        if is_capable_model():
            suppress_at = 5
    except Exception:  # noqa: BLE001 — dedup must never break the tool path
        pass
    if n >= suppress_at:
        return (
            f"⚠️ DUPLICATE SUPPRESSED — you have already run this exact command {n} "
            "times and the result will NOT change. Do NOT repeat it. Use the output "
            "you already have and take the NEXT step in the chain: parse that output, "
            "then run the follow-up (extract the data, forge/replay a token, hit the "
            "next endpoint). If the objective is met, emit the final report now."
        )
    return None


def reset() -> None:
    """Clear the dedup window (e.g. between engagements in a persistent process)."""
    _counts.clear()
