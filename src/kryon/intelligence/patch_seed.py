"""Fase 3 — patch-diff seeding for the source-review hunter.

Anthropic's Mythos found bugs by *variant analysis*: a known vulnerability's
shape, replayed across a codebase, surfaces its siblings. Kryon already does
this intra-tree (``source_review._build_seed_context``). This module adds the
*inter-tree* seed: the shape of a RECENT CVE fix — the exact calls a security
patch removed/added — pointed at a fresh codebase to hunt the same class before
it's patched here too.

The seed source is the CVE-diff corpus that ``kryon update --only cve-corpus``
already produces (``EnrichedEntry`` JSONL: cve_id, cwe_ids, ecosystem, and per
file ``added_calls``/``removed_calls`` lifted from the fix commit). We read that
JSONL DETERMINISTICALLY — no ChromaDB, no embeddings, no network — so the whole
module is banca-safe and unit-testable with a fake corpus. The RAG/embedding
surface stays OFF-by-default; this is the deterministic complement.

Two effects on the review, mirroring how a human auditor primed by a recent CVE
works:

- **Triage boost** — a file whose code contains a patched sink call jumps the
  review queue (``boost_scores``), so the model sees the most CVE-relevant file
  first under a file cap.
- **Prompt seed** — the relevant CVE shapes are prepended to the review prompt
  (``render_seed_block`` → ``build_seeded_review_prompt``), directing the model
  to hunt that exact class and its variants instead of a blind sweep.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

logger = logging.getLogger(__name__)

__all__ = [
    "PatchSeed",
    "load_seeds_from_jsonl",
    "seeds_matching_code",
    "boost_scores",
    "render_seed_block",
    "SEED_BOOST_PER_MATCH",
]

# Each matched CVE sink call adds this to a file's triage score, so a file that
# carries a freshly-patched call outranks a merely sink-dense one. Kept modest so
# it biases ordering without swamping the base sink-density signal.
SEED_BOOST_PER_MATCH = 5

# Call tokens too generic to be a useful sink signal — matching them would boost
# every file. Extracted from diffs, these are language keywords / ubiquitous
# builtins, not vulnerability-bearing APIs.
_NOISE_CALLS: frozenset[str] = frozenset(
    {
        "if",
        "for",
        "while",
        "return",
        "print",
        "len",
        "str",
        "int",
        "list",
        "dict",
        "set",
        "map",
        "get",
        "self",
        "super",
        "range",
        "type",
        "isinstance",
        "append",
        "format",
        "join",
        "split",
        "new",
        "true",
        "false",
        "null",
        "none",
        "log",
        "logger",
        "error",
        "warn",
        "info",
        "debug",
        "assert",
        "raise",
        "throw",
    }
)
_MIN_CALL_LEN = 4  # tokens shorter than this rarely name a meaningful sink


@dataclass(frozen=True)
class PatchSeed:
    """One recent CVE fix, distilled to what a code auditor needs to hunt it.

    ``sink_calls`` are the function/method names the fix commit touched (removed
    ∪ added), noise-filtered — the concrete pattern to grep for in fresh code.
    """

    cve_id: str
    cwes: tuple[str, ...]
    ecosystem: str
    summary: str
    subject: str
    sink_calls: tuple[str, ...]

    def matches(self, code: str) -> tuple[str, ...]:
        """Return the sink calls from this seed that appear (as substrings) in
        ``code``. Substring match keeps it language-agnostic and cheap; a hit is
        a triage signal, not a finding."""
        return tuple(c for c in self.sink_calls if c in code)


def _clean_calls(raw_calls: Iterable[str]) -> list[str]:
    """Normalize + noise-filter the raw call tokens lifted from a diff."""
    out: list[str] = []
    seen: set[str] = set()
    for c in raw_calls:
        token = (c or "").strip().strip("()").strip()
        if len(token) < _MIN_CALL_LEN:
            continue
        if token.lower() in _NOISE_CALLS:
            continue
        if token in seen:
            continue
        seen.add(token)
        out.append(token)
    return out


def _seed_from_entry(entry: dict) -> PatchSeed | None:
    """Build a PatchSeed from one ``EnrichedEntry`` JSONL record. Returns None if
    the record carries no usable sink call (nothing to hunt with)."""
    files = entry.get("files") or []
    raw_calls: list[str] = []
    for f in files:
        if not isinstance(f, dict):
            continue
        raw_calls.extend(f.get("removed_calls") or [])
        raw_calls.extend(f.get("added_calls") or [])
    sink_calls = _clean_calls(raw_calls)
    if not sink_calls:
        return None
    return PatchSeed(
        cve_id=str(entry.get("cve_id") or entry.get("ghsa_id") or "").strip(),
        cwes=tuple(str(c) for c in (entry.get("cwe_ids") or [])),
        ecosystem=str(entry.get("ecosystem") or "").strip().lower(),
        summary=str(entry.get("summary") or "").strip(),
        subject=str(entry.get("subject") or "").strip(),
        sink_calls=tuple(sink_calls),
    )


def load_seeds_from_jsonl(
    path: str | Path,
    *,
    ecosystem: str | None = None,
    limit: int = 200,
    reader: Callable[[Path], str] | None = None,
) -> list[PatchSeed]:
    """Load PatchSeeds from an enriched CVE-diff JSONL (``kryon update
    --only cve-corpus`` output). Deterministic — no ChromaDB, no embeddings.

    ``ecosystem`` filters to seeds for the target's stack (e.g. ``"pip"`` /
    ``"npm"``) so a Python audit isn't seeded with npm patches. ``reader`` is
    injectable for tests. A malformed line is skipped, never fatal.
    """
    rd = reader or (lambda p: Path(p).read_text(encoding="utf-8", errors="replace"))
    p = Path(path)
    try:
        raw = rd(p)
    except OSError as e:
        logger.debug("patch_seed: cannot read %s: %s", p, e)
        return []

    eco = ecosystem.strip().lower() if ecosystem else None
    seeds: list[PatchSeed] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(entry, dict):
            continue
        seed = _seed_from_entry(entry)
        if seed is None:
            continue
        if eco and seed.ecosystem and seed.ecosystem != eco:
            continue
        seeds.append(seed)
        if len(seeds) >= limit:
            break
    return seeds


def seeds_matching_code(code: str, seeds: list[PatchSeed]) -> list[PatchSeed]:
    """Return the seeds whose sink calls appear in ``code`` (order preserved)."""
    return [s for s in seeds if s.matches(code)]


def boost_scores(
    scored: list[tuple[Path, int]],
    seeds: list[PatchSeed],
    *,
    reader: Callable[[Path], str],
    boost_per_match: int = SEED_BOOST_PER_MATCH,
) -> list[tuple[Path, int]]:
    """Re-rank triage scores, boosting files that carry a patched CVE sink call.

    Each distinct matched sink call adds ``boost_per_match`` to the file's score.
    Re-sorted descending, ties broken by path (same determinism contract as
    ``triage_files``). Files that error on read keep their base score.
    """
    if not seeds:
        return scored
    boosted: list[tuple[Path, int]] = []
    for path, base in scored:
        try:
            code = reader(path)
        except OSError:
            boosted.append((path, base))
            continue
        hits = {call for s in seeds for call in s.matches(code)}
        boosted.append((path, base + boost_per_match * len(hits)))
    boosted.sort(key=lambda t: (-t[1], str(t[0])))
    return boosted


def render_seed_block(seeds: list[PatchSeed], *, max_seeds: int = 6) -> str:
    """Render the relevant CVE shapes as a prompt block that directs the review
    toward those classes + their variants. Empty string when no seeds — the
    caller then builds the ordinary (unseeded) prompt."""
    if not seeds:
        return ""
    lines = [
        "RECENT CVE PATTERNS TO HUNT (variant analysis — the fixes below patched "
        "these exact calls in similar code; check this file for the SAME class of "
        "bug and its variants, then decide exploitable vs guarded):",
    ]
    for s in seeds[:max_seeds]:
        cwe = ", ".join(s.cwes) if s.cwes else "CWE-?"
        calls = ", ".join(s.sink_calls[:8])
        label = s.cve_id or "recent-fix"
        summary = (s.summary or s.subject or "")[:160]
        lines.append(f"- [{label} · {cwe}] sinks: {calls}" + (f" — {summary}" if summary else ""))
    return "\n".join(lines)
