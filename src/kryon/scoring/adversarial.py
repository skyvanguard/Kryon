"""F148 — Adversarial robustness filter.

F134 ``annotate_confidence`` marks low-confidence LLM findings with
``needs_verification=True`` but keeps them in the report. F148 goes
one step further: **drops** the LLM findings that fail a stricter
quality gate, so the operator's report contains only items the system
can defend.

Decision matrix (default thresholds, env-tunable):

  - Deterministic finding → always keep.
  - LLM finding with confidence ≥ 0.7 → keep.
  - LLM finding with confidence < 0.7 AND empty/missing ``evidence``
    field → **drop**.
  - LLM finding with confidence < 0.7 BUT non-trivial evidence → keep
    (we err on the side of showing the operator something to verify).

Why two layers: confidence (F134) is a coloured-warning UX; this
filter is a "would I show this to a banking client?" gate. The
``KRYON_ADVERSARIAL_STRICT=true`` env raises the bar to "drop anything
needs_verification=True", regardless of evidence — for compliance
runs where false positives hurt more than missed findings.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class FilterResult:
    kept: list[Any]
    dropped: list[Any]
    reasons: dict[str, str]  # rule_id|host -> reason

    @property
    def kept_count(self) -> int:
        return len(self.kept)

    @property
    def dropped_count(self) -> int:
        return len(self.dropped)


def _env_true(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _confidence(finding: Any) -> float:
    val = getattr(finding, "confidence", 1.0)
    try:
        return float(val) if val is not None else 1.0
    except (TypeError, ValueError):
        return 1.0


def _needs_verification(finding: Any) -> bool:
    return bool(getattr(finding, "needs_verification", False))


def _has_meaningful_evidence(finding: Any) -> bool:
    """An LLM finding needs concrete evidence (>= 20 non-whitespace
    chars) to deserve a slot in the final report. We don't try to be
    clever about content — operators verify the evidence themselves."""
    ev = getattr(finding, "evidence", "") or ""
    msg = getattr(finding, "message", "") or ""
    combined = (str(ev) + " " + str(msg)).strip()
    return len(combined) >= 20


def filter_unverified_llm_findings(
    findings: list[Any],
    *,
    drop_threshold: float = 0.7,
    strict: bool | None = None,
) -> FilterResult:
    """Drop LLM findings that fail the quality bar.

    Args:
        findings:        list of Finding (or compatible dataclass / dict).
        drop_threshold:  confidence below this is candidate for drop.
        strict:          when True, drop ANY ``needs_verification=True``
                         finding regardless of evidence. ``None``
                         consults ``KRYON_ADVERSARIAL_STRICT`` env.
    """
    if strict is None:
        strict = _env_true("KRYON_ADVERSARIAL_STRICT")

    kept: list[Any] = []
    dropped: list[Any] = []
    reasons: dict[str, str] = {}

    for f in findings:
        rule_id = str(getattr(f, "rule_id", "") or "")
        host = str(getattr(f, "host", "") or "")
        key = f"{rule_id}|{host}"
        conf = _confidence(f)
        needs_ver = _needs_verification(f)

        # Deterministic findings always pass.
        if not needs_ver and conf >= drop_threshold:
            kept.append(f)
            continue

        # Strict mode: drop anything flagged for verification.
        if strict and needs_ver:
            dropped.append(f)
            reasons[key] = f"strict mode: needs_verification=True (confidence={conf:.2f})"
            continue

        # Low confidence + no evidence text → drop.
        if conf < drop_threshold and not _has_meaningful_evidence(f):
            dropped.append(f)
            reasons[key] = f"confidence {conf:.2f} below {drop_threshold:.2f} and no meaningful evidence"
            continue

        # Anything else (low conf but with evidence, or non-strict mode) → keep.
        kept.append(f)

    if dropped:
        logger.info("F148 adversarial filter dropped %d/%d findings", len(dropped), len(findings))

    return FilterResult(kept=kept, dropped=dropped, reasons=reasons)
