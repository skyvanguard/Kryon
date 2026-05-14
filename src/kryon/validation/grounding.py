"""F152 — Tool-output grounding for LLM findings.

A finding is **grounded** when its narration cites the concrete tool
output it was derived from. Without grounding, the LLM is free to
narrate based on training-data plausibility — exactly how R1
invented two CVE IDs against Juice Shop today.

Citation shapes accepted (each phrase ALONE is enough):

  - ``call_id: X`` / ``call X`` / ``call-id X``
  - ``step N`` / ``step #N``
  - ``según output de TOOL`` / ``according to TOOL output``
  - ``based on TOOL`` / ``from TOOL output``

When a finding lacks any citation, ``apply_grounding`` either:

  - **confidence cap to 0.3** (default) — F148 then drops if strict.
  - **flag ``needs_verification=True``** — operator review required.

Env:
  - ``KRYON_REQUIRE_GROUNDING`` default ``false``. When ``true``,
    ungrounded findings get the penalty. F153 auto-flips this to
    ``true`` for reasoning models.
  - ``KRYON_GROUNDING_CONFIDENCE_CAP`` default ``0.3``.

Pure helpers — no I/O.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


_CITATION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bcall[_\- ]?id[\s:=#]+([A-Za-z0-9_\-]{4,})", re.IGNORECASE),
    re.compile(r"\bstep[\s:#]+\d+", re.IGNORECASE),
    re.compile(r"\bseg[uú]n\s+(?:el\s+)?output\s+de\s+([A-Za-z0-9_\-]+)", re.IGNORECASE),
    re.compile(r"\baccording\s+to\s+([A-Za-z0-9_\-]+)\s+output", re.IGNORECASE),
    re.compile(r"\bbased\s+on\s+([A-Za-z0-9_\-]+)\s+(?:output|result|scan)", re.IGNORECASE),
    re.compile(r"\bfrom\s+([A-Za-z0-9_\-]+)\s+output", re.IGNORECASE),
)


def _env_true(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, "")
    if not raw:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _grounding_cap() -> float:
    raw = os.environ.get("KRYON_GROUNDING_CONFIDENCE_CAP", "").strip()
    if not raw:
        return 0.3
    try:
        return max(0.0, min(1.0, float(raw)))
    except ValueError:
        return 0.3


@dataclass
class GroundingResult:
    """Outcome of a single finding's grounding check."""

    grounded: bool
    citations: tuple[str, ...] = field(default_factory=tuple)
    reason: str = ""


def extract_citations(text: str) -> tuple[str, ...]:
    """Walk ``text`` for any of the accepted citation phrases. Returns
    a tuple of citation strings (matched substring) — empty if none.
    Used both as a sub-helper and for telemetry."""
    if not text:
        return ()
    out: list[str] = []
    for pattern in _CITATION_PATTERNS:
        for m in pattern.finditer(text):
            out.append(m.group(0))
    return tuple(out)


def _finding_text(finding) -> str:
    """Concatenate every textual field of the finding so we can
    citation-scan it. Supports dict and dataclass shapes."""
    if isinstance(finding, dict):
        getter = lambda key: finding.get(key, "")  # noqa: E731
    else:
        getter = lambda key: getattr(finding, key, "")  # noqa: E731
    parts: list[str] = []
    for key in ("evidence", "message", "remediation", "title", "description"):
        val = getter(key)
        if val:
            parts.append(str(val))
    return " ".join(parts)


def check_grounding(finding) -> GroundingResult:
    """Inspect a single finding. ``grounded=True`` iff the
    concatenated text contains at least one citation phrase."""
    text = _finding_text(finding)
    citations = extract_citations(text)
    if citations:
        return GroundingResult(grounded=True, citations=citations, reason="cited tool output")
    return GroundingResult(
        grounded=False,
        citations=(),
        reason="no citation to a tool call or step found in finding text",
    )


def apply_grounding(
    findings: list,
    *,
    enabled: bool | None = None,
    cap: float | None = None,
) -> int:
    """Iterate ``findings``, run ``check_grounding``, and apply the
    penalty in place. Returns count of findings that got penalised.

    Penalty: ``confidence = min(current, cap)`` AND
    ``needs_verification = True``. Deterministic findings (confidence
    already 1.0 from F134) get capped too IF they are LLM-emitted —
    but in practice deterministic emitters never go through this gate
    because the caller only invokes it on the LLM path.
    """
    if enabled is None:
        enabled = _env_true("KRYON_REQUIRE_GROUNDING", default=False)
    if not enabled:
        return 0

    threshold = cap if cap is not None else _grounding_cap()
    penalised = 0
    for f in findings:
        result = check_grounding(f)
        if result.grounded:
            continue
        # Cap the confidence + flag for verification. Skip silently
        # if the finding object refuses attribute assignment.
        try:
            current = getattr(f, "confidence", 1.0)
            try:
                current = float(current) if current is not None else 1.0
            except (TypeError, ValueError):
                current = 1.0
            f.confidence = min(current, threshold)
            f.needs_verification = True
            penalised += 1
        except (AttributeError, TypeError):
            # dict shape — mutate keys directly.
            if isinstance(f, dict):
                current_val = f.get("confidence", 1.0)
                try:
                    current_val = float(current_val) if current_val is not None else 1.0
                except (TypeError, ValueError):
                    current_val = 1.0
                f["confidence"] = min(current_val, threshold)
                f["needs_verification"] = True
                penalised += 1
            else:
                continue
    if penalised:
        logger.info("F152 grounding penalised %d ungrounded LLM finding(s)", penalised)
    return penalised
