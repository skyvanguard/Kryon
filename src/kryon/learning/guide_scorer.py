"""F77.G.4 — Guide score (relevance + naturalness) for auto-generated drafts.

Inspired by SGS (https://arxiv.org/abs/2604.20209): a third "Guide" role that
scores synthetic problems by *quality* and *relevance* prevents the
Conjecturer from collapsing into reward-hacked nonsense. Applied here to
the F3 self-creation pipeline: even a draft that passes the technical
CWE→tools eval gate can still be textually broken (mismatched
frontmatter/body, placeholder soup, repeated lines, generative-loop
artifacts). The Guide is a cheap heuristic second-axis filter — zero LLM
calls, stdlib-only.

The scorer is intentionally conservative: it scores on `[0, 1]` and only
subtracts. A pristine draft scores `1.0`. The combined score is a weighted
average favoring `relevance` (banking-safe: a draft pointing at the wrong
tools is worse than one with awkward prose).
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

# Combined score must clear this to pass the Guide gate. 0.6 is conservative
# but allows mostly-good drafts through; tighten via env if false-pass rate
# turns out high.
GUIDE_DEFAULT_THRESHOLD = 0.6
GUIDE_RELEVANCE_WEIGHT = 0.6
GUIDE_NATURALNESS_WEIGHT = 0.4

# Heuristic constants — change here, not at the call site.
_MIN_BODY_CHARS = 200
_MAX_BODY_CHARS = 20_000
_MAX_PLACEHOLDER_DENSITY = 0.30
_MAX_DUP_LINE_RATIO = 0.25

_PLACEHOLDER_PATTERN = re.compile(
    r"\bTODO\b|\bFIXME\b|\bXXXX+|<insert[^>]*>|\{TODO\}|\{[A-Z_]{3,}\}",
    re.IGNORECASE,
)
_EMPTY_CODE_BLOCK_PATTERN = re.compile(
    r"```[^\n]*\n\s*```|```[^\n]*\n\s*#\s*\.{2,}\s*\n\s*```",
    re.MULTILINE,
)
_PLAYBOOK_SECTION_PATTERN = re.compile(
    r"^#{1,4}\s*(steps|playbook|chain|procedure|detection|pre-?flight|workflow)",
    re.IGNORECASE | re.MULTILINE,
)


@dataclass(frozen=True)
class GuideScore:
    """Result of scoring a draft on the Guide axes."""

    relevance: float  # 0..1
    naturalness: float  # 0..1
    combined: float  # weighted average
    reasons: tuple[str, ...] = field(default_factory=tuple)

    def passes(self, threshold: float = GUIDE_DEFAULT_THRESHOLD) -> bool:
        return self.combined >= threshold


def _clamp(x: float) -> float:
    return max(0.0, min(1.0, x))


def score_relevance(draft: Any) -> tuple[float, list[str]]:
    """Coherence between the frontmatter and the body.

    Penalties:
      - Tools declared in `required_tools:` but never mentioned in body.
      - No `## Steps` / `## Playbook` / `## Detection` section header.
      - Empty body or empty `required_tools:` list.
    """
    reasons: list[str] = []
    score = 1.0

    fm = draft.frontmatter or {}
    body = draft.body or ""
    body_lower = body.lower()

    required_tools_raw = fm.get("required_tools") or []
    required_tools = [str(t).lower() for t in required_tools_raw if str(t).strip()]

    if not required_tools:
        score -= 0.30
        reasons.append("relevance: empty required_tools in frontmatter")

    if required_tools:
        missing = [t for t in required_tools if t not in body_lower]
        if missing:
            penalty = 0.30 * (len(missing) / len(required_tools))
            score -= penalty
            preview = ", ".join(missing[:3])
            reasons.append(
                f"relevance: required_tools not referenced in body: "
                f"{preview}{' …' if len(missing) > 3 else ''}",
            )

    if not _PLAYBOOK_SECTION_PATTERN.search(body):
        score -= 0.20
        reasons.append(
            "relevance: no Steps/Playbook/Detection section header found",
        )

    if not body.strip():
        score = 0.0
        reasons.append("relevance: body is empty")

    return _clamp(score), reasons


def score_naturalness(draft: Any) -> tuple[float, list[str]]:
    """Heuristics that flag generative-loop artifacts and stub drafts.

    Penalties:
      - Body length out of sane range (200..20000 chars).
      - High placeholder density (TODO / XXXX / {ALL_CAPS}).
      - Repeated identical lines beyond a small ratio.
      - Empty fenced code blocks (```\\n``` or ```\\n# ...\\n```).
    """
    reasons: list[str] = []
    score = 1.0
    body = draft.body or ""
    n = len(body)

    if n == 0:
        return 0.0, ["naturalness: empty body"]

    if n < _MIN_BODY_CHARS:
        score -= 0.40
        reasons.append(f"naturalness: body too short ({n} < {_MIN_BODY_CHARS} chars)")
    elif n > _MAX_BODY_CHARS:
        score -= 0.20
        reasons.append(
            f"naturalness: body suspiciously long ({n} > {_MAX_BODY_CHARS} chars)",
        )

    placeholders = _PLACEHOLDER_PATTERN.findall(body)
    if placeholders:
        density = len(placeholders) / max(1, n / 100)
        if density > _MAX_PLACEHOLDER_DENSITY:
            score -= 0.30
            reasons.append(
                f"naturalness: high placeholder density "
                f"({len(placeholders)} markers in {n} chars)",
            )

    nonblank = [ln.strip() for ln in body.split("\n") if ln.strip()]
    if nonblank:
        counts = Counter(nonblank)
        dup_extra = sum(c - 1 for c in counts.values() if c > 1)
        ratio = dup_extra / len(nonblank)
        if ratio > _MAX_DUP_LINE_RATIO:
            score -= 0.25
            reasons.append(
                f"naturalness: {dup_extra} duplicate lines "
                f"({ratio * 100:.0f}% — likely generative loop)",
            )

    empty_code = len(_EMPTY_CODE_BLOCK_PATTERN.findall(body))
    if empty_code:
        score -= min(0.30, 0.10 * empty_code)
        reasons.append(f"naturalness: {empty_code} empty/stub code block(s)")

    return _clamp(score), reasons


def score_draft(draft: Any) -> GuideScore:
    """Combined Guide score. `relevance` weighed higher than `naturalness`."""
    rel, rel_reasons = score_relevance(draft)
    nat, nat_reasons = score_naturalness(draft)
    combined = GUIDE_RELEVANCE_WEIGHT * rel + GUIDE_NATURALNESS_WEIGHT * nat
    return GuideScore(
        relevance=rel,
        naturalness=nat,
        combined=_clamp(combined),
        reasons=tuple(rel_reasons + nat_reasons),
    )
