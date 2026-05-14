"""F88 — Verdict logic for the retester.

Given a RetestRecord (the engagement reproduction) and what the
current replay observed, decide whether the finding is:

  fixed              — replay can no longer reproduce the original
                       response. Either the endpoint went away
                       (404/410), authentication started rejecting
                       us (401/403), or the response body changed
                       in a way that drops the leak signal.
  still_open         — replay returned a response byte-equivalent to
                       the engagement's record (same status + same
                       body SHA-256). The patch hasn't landed.
  changed            — same status, different body. May be a partial
                       fix or a behavioural change unrelated to the
                       vuln. Surfaces for manual review.
  regressed          — special case where the engagement marked the
                       finding as fixed but the current replay
                       reproduces it again. Only fires when the
                       record carries an explicit `is_currently_fixed`
                       hint (future-fields, not in v1 — reserved).
  error              — replay couldn't run (network failure, etc.)

The verdict is purely a function of (original_status,
original_body_sha256, current_status, current_body_sha256). Pure
function, no I/O — easy to test.
"""

from __future__ import annotations

from dataclasses import dataclass

from kryon.retester.record import RetestRecord

__all__ = [
    "CurrentResponse",
    "RetestVerdict",
    "verdict_for",
]


@dataclass(frozen=True)
class CurrentResponse:
    """What the current replay observed. The body_sha256 is computed
    over the FULL response body even though the verbatim body isn't
    surfaced beyond this object — equivalence detection requires the
    full hash, which is also cheap to compute."""

    http_status: int
    body_sha256: str
    body_fingerprint: str = ""  # first 200 chars; mirrors RetestRecord
    error: str | None = None


@dataclass(frozen=True)
class RetestVerdict:
    """Result of one replay vs original comparison.

    `verdict` is the headline. `confidence` is a 0..1 hint — high
    when the signal is clean (same hash → 1.0; both 4xx → 1.0),
    lower when we're guessing (e.g. same status, different body)."""

    verdict: str  # fixed / still_open / changed / regressed / error
    confidence: float
    reason: str  # human-readable explanation
    original_status: int
    current_status: int | None
    body_changed: bool
    status_changed: bool


# Status families. 2xx = success; 4xx = auth/refusal; 5xx = server
# error. The grouping informs the verdict logic.
def _family(status: int) -> str:
    if 200 <= status < 300:
        return "2xx"
    if 300 <= status < 400:
        return "3xx"
    if 400 <= status < 500:
        return "4xx"
    if 500 <= status < 600:
        return "5xx"
    return "other"


def verdict_for(record: RetestRecord, current: CurrentResponse) -> RetestVerdict:
    """Pure-function verdict.

    Tree:
      1. current.error set → verdict=error
      2. current.body_sha256 == original.body_sha256 AND
         current.http_status == original.http_status
         → still_open (high confidence)
      3. original was 2xx AND current is 4xx/5xx
         → fixed (high confidence — leak-producing path now refuses)
      4. original.body_sha256 != current.body_sha256 AND
         current.http_status == original.http_status
         → changed (medium confidence — partial fix or unrelated
           behavioural change)
      5. original was 2xx AND current is 2xx but status code differs
         (e.g. 200 → 204) → changed (low confidence)
      6. fallthrough → changed (medium confidence)
    """
    if current.error:
        return RetestVerdict(
            verdict="error",
            confidence=1.0,
            reason=f"replay error: {current.error}",
            original_status=record.original_http_status,
            current_status=current.http_status if current.http_status else None,
            body_changed=False,
            status_changed=False,
        )

    body_changed = bool(record.original_body_sha256) and (current.body_sha256 != record.original_body_sha256)
    status_changed = current.http_status != record.original_http_status

    # 2 — byte-equivalent reproduction → still open.
    if not body_changed and not status_changed:
        return RetestVerdict(
            verdict="still_open",
            confidence=1.0,
            reason="response is byte-equivalent to the engagement record",
            original_status=record.original_http_status,
            current_status=current.http_status,
            body_changed=False,
            status_changed=False,
        )

    original_family = _family(record.original_http_status)
    current_family = _family(current.http_status)

    # 3 — leak-producing 2xx now refuses → fixed.
    if original_family == "2xx" and current_family in ("4xx", "5xx"):
        return RetestVerdict(
            verdict="fixed",
            confidence=1.0,
            reason=(
                f"original status {record.original_http_status} (2xx leak) → "
                f"current status {current.http_status} ({current_family} refused)"
            ),
            original_status=record.original_http_status,
            current_status=current.http_status,
            body_changed=body_changed,
            status_changed=True,
        )

    # Edge: original was already a refusal but replay sees 2xx → regressed
    # (a vuln that was previously blocked is now reachable). Surface
    # explicitly so the auditor escalates.
    if original_family in ("4xx", "5xx") and current_family == "2xx":
        return RetestVerdict(
            verdict="regressed",
            confidence=0.9,
            reason=(
                f"original status {record.original_http_status} "
                f"({original_family}) → current 2xx; previously-refused "
                f"path is now reachable"
            ),
            original_status=record.original_http_status,
            current_status=current.http_status,
            body_changed=body_changed,
            status_changed=True,
        )

    # 4-6 — anything else is a content change. Confidence depends on
    # whether the status family stayed the same (more signal) or
    # shifted (less signal).
    confidence = 0.7 if not status_changed else 0.5
    return RetestVerdict(
        verdict="changed",
        confidence=confidence,
        reason=(
            f"response changed: status {record.original_http_status}→"
            f"{current.http_status}, body {'differs' if body_changed else 'unchanged'}"
        ),
        original_status=record.original_http_status,
        current_status=current.http_status,
        body_changed=body_changed,
        status_changed=status_changed,
    )
