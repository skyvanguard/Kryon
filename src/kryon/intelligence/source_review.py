"""Mythos-style source-review harness.

Anthropic's Claude "Mythos" read the Firefox 150 source and surfaced 271
vulnerabilities by *pure reasoning over code* — no fuzzing harness. This
module is Kryon's local equivalent: point a strong reasoning model
(default ``kryon-local``, override with ``KRYON_SOURCE_REVIEW_MODEL``) at a
source tree and have it review the
actual file contents file-by-file, then expand coverage via *variant
analysis* (found a dangerous pattern once → grep the tree for the same
sink and review those sites too).

Design contract:
- The orchestration (enumerate → triage → review → variant-expand →
  dedup → rank → report) is PURE and unit-testable. The only impure piece
  is the LLM call, isolated behind the ``Reviewer`` callable interface so
  tests inject a fake and never need a live model.
- Findings convert to ``kryon.cli.engage.Finding`` so they flow into the
  same downstream pipeline (investigate output, scoreboard, learning loop).
- Banca-safe: read-only. Reads source files, runs no target, no network
  except the local llama.cpp endpoint for inference.

Primary use is the zero-day / CVE-discovery research line — see memory
``project_zeroday_research_goal``. NOT the default banca-safe audit path.
"""

from __future__ import annotations

import inspect
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DEFAULT_MODEL = "kryon-local"

# Source extensions worth reviewing. Kept deliberately broad; triage ranks
# within this set so a low-signal file just sinks to the bottom.
SOURCE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".h",
        ".hpp",
        ".hh",
        ".py",
        ".rb",
        ".php",
        ".java",
        ".go",
        ".rs",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".kt",
        ".scala",
        ".cs",
        ".swift",
        ".m",
        ".mm",
        ".pl",
        ".lua",
        ".sh",
    }
)

# Directories never worth reviewing — vendored deps, build output, VCS,
# tests (a vuln in a test fixture is not a product vuln). Lowercased.
SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "vendor",
        "third_party",
        "dist",
        "build",
        "out",
        "target",
        "__pycache__",
        ".venv",
        "venv",
        "site-packages",
        "bower_components",
        ".tox",
        ".mypy_cache",
        "testdata",
        "fixtures",
        "examples",
        "docs",
        # Build-time codegen / assembly generators (e.g. OpenSSL's perl asm
        # generators under crypto/*/asm/). Their backtick/shell-out lines are
        # build tooling, not product attack surface — they swamped the
        # sink-density triage with CWE-78 noise and crowded out real source.
        "asm",
        "perlasm",
        "test",
        "tests",
    }
)

# Per-file byte cap. Above this we skip (huge minified/generated files are
# low-signal and blow the context window). 200 KB ~ 3-4k LOC.
DEFAULT_MAX_FILE_BYTES = 200_000

# Hard cap on files sent to the model per run, so an unbounded tree can't
# run forever. Triage decides WHICH files make the cut.
DEFAULT_MAX_FILES = 40

# Variant analysis adds AT MOST this many extra files on top of the primary
# cap (Mythos "where else does this sink appear?"). Kept separate so the CLI
# can report the real ceiling (primary + variant), not pretend it's max_files.
DEFAULT_VARIANT_MAX_FILES = 20


# Per-file char cap for the review prompt. Files up to DEFAULT_MAX_FILE_BYTES
# are enumerated, but only the first N chars reach the model — anything beyond
# is truncated (and now recorded, so coverage gaps are visible). Tunable via
# KRYON_SOURCE_REVIEW_MAX_CHARS: a big-context model (V4-Flash 1M) can take
# whole files + the variant seed context, so bump it there instead of hardcoding
# a value that would blow a small-context model's window.
def _env_int(name: str, default: int) -> int:
    try:
        v = int(os.environ.get(name, "").strip())
        return v if v > 0 else default
    except (TypeError, ValueError):
        return default


DEFAULT_MAX_CODE_CHARS = _env_int("KRYON_SOURCE_REVIEW_MAX_CHARS", 24_000)

# Sink patterns: language-agnostic markers of a place where untrusted data
# meets a dangerous operation. Used purely for TRIAGE (which files to look
# at first) and VARIANT analysis (where else does this sink appear). The
# associated CWE is only a hint shown to the model, never an assertion.
SINK_PATTERNS: dict[str, str] = {
    # command / code execution
    r"\bsystem\s*\(": "CWE-78",
    r"\bpopen\s*\(": "CWE-78",
    r"\bexec[lv]?[pe]?\s*\(": "CWE-78",
    r"\bos\.system\s*\(": "CWE-78",
    r"\bsubprocess\.(?:call|run|Popen)\s*\(": "CWE-78",
    r"\beval\s*\(": "CWE-95",
    r"\bunserialize\s*\(": "CWE-502",
    r"\bpickle\.loads?\s*\(": "CWE-502",
    r"\byaml\.load\s*\(": "CWE-502",
    # injection
    r"(?:execute|query|exec)\s*\(\s*[\"'].*?(?:\+|%|\$\{|f[\"'])": "CWE-89",
    r"\binnerHTML\s*=": "CWE-79",
    r"\bdangerouslySetInnerHTML\b": "CWE-79",
    r"\bdocument\.write\s*\(": "CWE-79",
    # path / file
    r"\bopen\s*\(\s*.*\+": "CWE-22",
    r"\bfopen\s*\(": "CWE-22",
    r"\.\./": "CWE-22",
    # memory (C/C++)
    r"\bstrcpy\s*\(": "CWE-120",
    r"\bstrcat\s*\(": "CWE-120",
    r"\bsprintf\s*\(": "CWE-120",
    r"\bgets\s*\(": "CWE-242",
    r"\bmemcpy\s*\(": "CWE-119",
    r"\bmemmove\s*\(": "CWE-119",
    r"\balloca\s*\(": "CWE-119",
    r"\bmalloc\s*\(": "CWE-789",
    # java deserialization / JNDI (Log4Shell-class): resolving remote objects
    # from untrusted data instantiates classes = insecure deserialization.
    r"\bJndiLookup\b": "CWE-502",
    r"\bInitialContext\b": "CWE-502",
    r"\.lookup\s*\(": "CWE-502",
    r"\breadObject\s*\(": "CWE-502",
    r"\bObjectInputStream\b": "CWE-502",
    r"\breadExternal\s*\(": "CWE-502",
    # expression / template injection (Struts-OGNL / SpEL class)
    r"\bOgnl(?:Util|Context)?\b": "CWE-917",
    r"\btranslateVariables\s*\(": "CWE-917",
    r"\.getValue\s*\(\s*[^)]*\bexpr": "CWE-917",
    r"\bScriptEngine\b": "CWE-94",
    # java command execution
    r"\bRuntime\s*\.\s*getRuntime\s*\(": "CWE-78",
    r"\bProcessBuilder\b": "CWE-78",
    # ssrf / deserialization / crypto
    r"\brequests\.(?:get|post)\s*\(": "CWE-918",
    r"\burllib\.request\.urlopen\s*\(": "CWE-918",
    r"\bMD5\b|\bmd5\s*\(": "CWE-327",
    r"\bDES\b|\bECB\b": "CWE-327",
    # secrets
    r"(?:api_?key|secret|password|token)\s*=\s*[\"'][^\"']{6,}": "CWE-798",
}

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceFinding:
    """One vulnerability the reviewer flagged in source."""

    file: str
    line: int
    cwe: str
    severity: str
    title: str
    description: str = ""
    evidence: str = ""
    sink: str = ""  # the dangerous expression — drives variant analysis
    confidence: float = 0.5
    variant_of: str | None = None  # file:line of the seed finding, if any
    # Novelty gate (F1): filled in post-review by novelty_gate.annotate_novelty.
    # Distinguishes "re-detected a known/patched CVE" from "no prior art found".
    novelty_score: float | None = None  # 0 = twin of a known CVE, 1 = no prior art
    novelty_verdict: str = ""  # likely-known | uncertain | likely-novel | no-corpus
    nearest_cve: str | None = None  # the closest known CVE, if any
    # Verification (F2/F3): filled in by verification_bridge after the finding
    # is (or isn't) reproduced. ``verified`` gates needs_verification downstream.
    verified: bool = False
    verification_verdict: str = (
        ""  # confirmed | not-reproduced | poc-build-failed | unsupported | no-poc | inconclusive
    )
    crash_type: str = ""  # ASAN crash class when confirmed (e.g. heap-buffer-overflow)

    def key(self) -> tuple[str, int, str]:
        """Dedup key: same file + line + CWE is the same finding."""
        return (self.file, self.line, self.cwe.upper())

    def severity_rank(self) -> int:
        return _SEV_RANK.get(self.severity.upper(), 4)

    def to_engage_finding(self):  # -> kryon.cli.engage.Finding
        """Convert to the canonical Finding so it flows downstream."""
        from kryon.cli.engage import Finding

        msg = self.title if not self.description else f"{self.title} — {self.description}"
        # An ASAN-confirmed finding (F2) is ground truth: flip needs_verification
        # off and lift confidence. Everything unverified stays LLM-derived and
        # never auto-trusted.
        confidence = 0.98 if self.verified else self.confidence

        # T4-M8: the F1/F2/F3 pipeline computes novelty + verification verdicts on the
        # SourceFinding, but this converter dropped them — so downstream reports never
        # saw that a finding is "likely-novel" (the zero-day payoff) or ASAN-confirmed.
        # Fold them into the evidence so the signal survives the conversion boundary.
        notes: list[str] = []
        if self.novelty_verdict:
            nv = self.novelty_verdict
            if self.nearest_cve:
                nv += f" (nearest {self.nearest_cve}"
                nv += f", score={self.novelty_score:.2f})" if self.novelty_score is not None else ")"
            notes.append(f"novelty={nv}")
        if self.verification_verdict:
            vv = self.verification_verdict
            if self.crash_type:
                vv += f" ({self.crash_type})"
            notes.append(f"verification={vv}")
        evidence = self.evidence
        if notes:
            evidence = (evidence + " | " if evidence else "") + " · ".join(notes)

        return Finding(
            cwe=self.cwe,
            severity=self.severity.upper(),
            host=self.file,
            # Include the line: downstream finding_dedup keys on (host, rule_id)
            # with no line component, so a bare "SAST-CWE-89" would collapse two
            # distinct SQLi in the same file into one. Line-granular rule_id
            # keeps them separate.
            rule_id=f"SAST-{self.cwe}-L{self.line}",
            message=msg,
            evidence=evidence,
            severity_rank=self.severity_rank(),
            confidence=confidence,
            needs_verification=not self.verified,
        )


@dataclass
class SourceReviewResult:
    findings: list[SourceFinding] = field(default_factory=list)
    files_total: int = 0
    files_reviewed: int = 0
    variant_files_reviewed: int = 0
    elapsed_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)


# A Reviewer takes (relative_path, code) and returns raw findings for that
# file. The LLM lives behind this; tests inject a fake.
Reviewer = Callable[[str, str], list[SourceFinding]]


# ---------------------------------------------------------------------------
# Enumeration (pure)
# ---------------------------------------------------------------------------


def enumerate_source_files(
    root: Path,
    *,
    extensions: frozenset[str] = SOURCE_EXTENSIONS,
    skip_dirs: frozenset[str] = SKIP_DIRS,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> list[Path]:
    """Walk ``root`` and return reviewable source files (sorted, stable).

    Skips vendored/build/test dirs, non-source extensions, and oversized
    files. Pure modulo the filesystem read.
    """
    root = Path(root)
    root_resolved = root.resolve()
    out: list[Path] = []
    if root.is_file():
        candidates = [root]
    else:
        candidates = []
        # os.walk with followlinks=False (the default, made explicit here) does
        # NOT descend into symlinked directories. Since `investigate` points at
        # UNTRUSTED cloned target code, this is a security boundary, not an
        # optimization: a symlinked dir pointing outside the tree (or a self-
        # referential loop) would otherwise recurse forever and/or leak files
        # from outside `root` to the review model (which may be a remote/frontier
        # endpoint). Pruning skip_dirs in-place also avoids stat-ing giant
        # vendored trees (node_modules, .git) we'd only throw away.
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d.lower() not in skip_dirs]
            for fn in filenames:
                p = Path(dirpath) / fn
                # Reject symlinked FILES too (a dir walk won't catch a
                # notes.py -> /home/operator/.ssh/id_rsa exfil symlink).
                if p.is_symlink():
                    continue
                candidates.append(p)
    for p in candidates:
        if p.suffix.lower() not in extensions:
            continue
        try:
            # Belt-and-suspenders: never include anything that resolves outside
            # the audited root, whatever the path shape.
            if not p.resolve().is_relative_to(root_resolved):
                continue
            if p.stat().st_size > max_file_bytes:
                continue
        except OSError:
            continue
        out.append(p)
    return sorted(out)


# ---------------------------------------------------------------------------
# Triage (pure) — which files to look at first
# ---------------------------------------------------------------------------

_COMPILED_SINKS = [(re.compile(pat), cwe) for pat, cwe in SINK_PATTERNS.items()]


# Sink weights by CWE class. A plain hit-count fails because ubiquitous sinks
# (malloc/memcpy in every C file) drown out the DISTINCTIVE one that marks the
# real bug: a JNDI lookup, a deserialization call, an OGNL eval are RARE and
# high-signal, so a file carrying one should rank above a file merely dense in
# common calls. (Log4Shell's JndiLookup.java ranked 28th by raw count; weighted,
# its CWE-502 sink lifts it to the top.)
_SINK_WEIGHTS: dict[str, int] = {
    "CWE-502": 40,  # deserialization / JNDI lookup — rare + critical
    "CWE-917": 40,  # expression / OGNL / template injection
    "CWE-94": 30,  # code injection
    "CWE-95": 30,  # eval
    "CWE-78": 15,  # command execution
    "CWE-89": 10,  # SQLi (string-built query)
    "CWE-79": 8,  # XSS sink
    "CWE-918": 8,  # SSRF
    "CWE-22": 6,  # path traversal
    "CWE-798": 4,  # hardcoded secret
    "CWE-327": 2,  # weak crypto
    "CWE-242": 2,  # gets
    "CWE-120": 2,  # strcpy/strcat/sprintf
    "CWE-119": 2,  # memcpy/memmove — common
    "CWE-789": 1,  # malloc — extremely common, near-noise
}
_DEFAULT_SINK_WEIGHT = 3

# Untrusted-input SOURCES — where attacker-controlled data enters. A sink is only
# dangerous if input REACHES it; a lone sink is usually safe. Cheap same-file
# taint proxy: a sink co-located with a source is the real signal (heartbleed's
# memcpy sits next to the network-parsed heartbeat length; a request-fed lookup
# next to getHeader). Not inter-procedural — it can't link a source and sink in
# DIFFERENT files (e.g. Log4Shell's message→lookup chain), a known limitation.
_INPUT_SOURCE_PATTERNS: tuple[str, ...] = (
    # C: network / buffer parsing
    r"\brecv\s*\(", r"\bread\s*\(", r"\bfread\s*\(", r"\brecvfrom\s*\(",
    r"\bn2s\s*\(", r"\bc2l\s*\(", r"\bntohs\s*\(", r"\bntohl\s*\(",
    r"->\s*data\b", r"->\s*length\b", r"\bpayload\b", r"\bhbtype\b",
    # Java / servlet request input
    r"\bgetParameter\b", r"\bgetHeader\b", r"\bgetInputStream\b", r"\bgetReader\b",
    r"\bHttpServletRequest\b", r"\bgetQueryString\b", r"\bgetContentType\b",
    r"\breadLine\s*\(", r"\bgetPart\b",
    # generic web frameworks
    r"\breq(?:uest)?\.(?:body|params|query|args|form|json|headers)\b",
)
_COMPILED_INPUT_SRC = [re.compile(p) for p in _INPUT_SOURCE_PATTERNS]

_TAINT_WINDOW = 20  # lines: a source within ±this of a sink counts as "reaches"
_TAINT_BOOST = 30  # per sink that an input source can reach in the same file


def _taint_boost(code: str) -> int:
    """Same-file taint heuristic: reward each sink that an untrusted-input source
    reaches within ``_TAINT_WINDOW`` lines. A memcpy next to a parsed network
    length, a lookup next to a request header — the real bug signal, versus a
    lone sink in every file."""
    lines = code.splitlines()
    src_lines = [i for i, ln in enumerate(lines) if any(rx.search(ln) for rx in _COMPILED_INPUT_SRC)]
    if not src_lines:
        return 0
    boost = 0
    for i, ln in enumerate(lines):
        if any(rx.search(ln) for rx, _ in _COMPILED_SINKS) and any(
            abs(i - s) <= _TAINT_WINDOW for s in src_lines
        ):
            boost += _TAINT_BOOST
    return boost


def score_file_risk(code: str) -> int:
    """Weighted sink signal + same-file taint — a proxy for "interesting to review".

    NOT a hit-count: rare/high-signal sinks (deserialization, OGNL, eval) outweigh
    ubiquitous ones (malloc/memcpy), and a sink an untrusted-input source can REACH
    (same file, within a window) gets a large boost — so the file where input
    actually flows into a sink outranks one merely dense in lone sinks.
    """
    weighted = sum(
        len(rx.findall(code)) * _SINK_WEIGHTS.get(cwe, _DEFAULT_SINK_WEIGHT) for rx, cwe in _COMPILED_SINKS
    )
    return weighted + _taint_boost(code)


def triage_files(
    files: list[Path],
    *,
    reader: Callable[[Path], str] | None = None,
) -> list[tuple[Path, int]]:
    """Rank files by descending sink-density. Ties broken by path for
    determinism. ``reader`` is injectable for tests."""
    rd = reader or _read_text
    scored: list[tuple[Path, int]] = []
    for f in files:
        try:
            scored.append((f, score_file_risk(rd(f))))
        except OSError:
            continue
    scored.sort(key=lambda t: (-t[1], str(t[0])))
    return scored


def _read_text(p: Path) -> str:
    return Path(p).read_text(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Prompt + output parsing (pure)
# ---------------------------------------------------------------------------

_REVIEW_INSTRUCTIONS = (
    "You are a senior application-security auditor performing a manual "
    "source-code review. Examine the file below and report ONLY concrete, "
    "exploitable vulnerabilities you can justify from the code shown — no "
    "speculation, no style nits, no 'could be an issue'. For each real "
    "finding, identify the precise line and the dangerous expression (the "
    "sink).\n\n"
    "Respond with a JSON array ONLY (no prose, no markdown fences). Each "
    'element: {"line": int, "cwe": "CWE-XXX", "severity": '
    '"CRITICAL|HIGH|MEDIUM|LOW", "title": str, "description": str, '
    '"evidence": "the exact vulnerable line(s)", "sink": "the '
    'dangerous call/expression", "confidence": 0.0-1.0}. '
    "If there are no real vulnerabilities, respond with []."
)


def build_review_prompt(
    rel_path: str,
    code: str,
    *,
    max_code_chars: int = DEFAULT_MAX_CODE_CHARS,
    seed_context: str = "",
) -> str:
    """Assemble the per-file review prompt. Truncates very large files at a
    char cap (triage already filtered by byte size; this is a safety net).

    ``seed_context`` (Etapa B of variant analysis) prepends the confirmed sinks
    from the primary pass so a variant re-review is *directed* — the model
    looks for the same pattern and decides guard-equivalent vs exploitable —
    instead of a blind independent review. Empty for the primary pass."""
    snippet = code if len(code) <= max_code_chars else code[:max_code_chars] + "\n…(truncated)\n"
    numbered = _number_lines(snippet)
    seed_block = f"\n\n{seed_context}\n" if seed_context.strip() else ""
    return f"{_REVIEW_INSTRUCTIONS}{seed_block}\n\nFile: {rel_path}\n```\n{numbered}\n```\n"


def build_seeded_review_prompt(
    rel_path: str,
    code: str,
    patch_seeds: list,
    *,
    max_code_chars: int = DEFAULT_MAX_CODE_CHARS,
    seed_context: str = "",
) -> str:
    """Fase 3 — review prompt seeded with recent CVE fixes (inter-tree variant
    analysis). Only the seeds whose patched sink calls actually appear in ``code``
    are rendered, so the model is primed on the CVE classes present in THIS file,
    then decides exploitable vs guarded — instead of a blind sweep.

    Composes with the intra-tree ``seed_context`` (Etapa B): the CVE block goes
    first, then the confirmed-sink variant block. Falls back to the ordinary
    unseeded prompt when no seed is relevant.
    """
    from kryon.intelligence.patch_seed import render_seed_block, seeds_matching_code

    cve_block = render_seed_block(seeds_matching_code(code, patch_seeds)) if patch_seeds else ""
    combined = "\n\n".join(b for b in (cve_block, seed_context) if b.strip())
    return build_review_prompt(rel_path, code, max_code_chars=max_code_chars, seed_context=combined)


def _number_lines(code: str) -> str:
    return "\n".join(f"{i + 1:>5}  {ln}" for i, ln in enumerate(code.splitlines()))


_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def strip_think(raw: str) -> str:
    """Remove <think>…</think> reasoning blocks (foundation-sec / R1 emit
    them) and any dangling unterminated trailing <think>."""
    out = _THINK_RE.sub("", raw)
    # An unterminated <think> (truncated output) — drop from the tag on.
    idx = out.lower().rfind("<think>")
    if idx != -1 and "</think>" not in out[idx:].lower():
        out = out[:idx]
    return out.strip()


def _extract_json_array(text: str) -> str | None:
    """Best-effort: pull the JSON array out of a model reply. Handles
    ```json fences and free-floating arrays. Returns the array substring
    or None."""
    fence = _FENCE_RE.search(text)
    if fence:
        inner = fence.group(1).strip()
        if inner.startswith("["):
            return inner
    start = text.find("[")
    if start == -1:
        return None
    # Walk to the matching bracket, ignoring brackets inside strings.
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def parse_findings_json(raw: str, *, file: str) -> list[SourceFinding]:
    """Parse a model reply into SourceFinding objects. Tolerant: strips
    think blocks + fences, validates/coerces each element, drops junk."""
    cleaned = strip_think(raw)
    arr = _extract_json_array(cleaned)
    if arr is None:
        # Distinguish "model said []" (legit no-findings) from "couldn't find a
        # JSON array at all" (truncated/malformed output). The latter looks
        # identical to zero vulns downstream, so surface it.
        if cleaned.strip():
            logger.warning(
                "source-review: no JSON array in model reply for %s (%d chars) — "
                "treating as no findings; output may be truncated/malformed: %.160r",
                file,
                len(cleaned),
                cleaned,
            )
        return []
    try:
        items = json.loads(arr)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning("source-review: JSON parse failed for %s: %s — array=%.160r", file, e, arr)
        return []
    if not isinstance(items, list):
        return []

    out: list[SourceFinding] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        cwe = str(it.get("cwe", "")).strip().upper()
        if not cwe:
            continue
        if not cwe.startswith("CWE-"):
            m = re.search(r"(\d{1,4})", cwe)
            if not m:
                continue
            cwe = f"CWE-{m.group(1)}"
        try:
            line = int(it.get("line", 0))
        except (TypeError, ValueError):
            line = 0
        sev = str(it.get("severity", "MEDIUM")).strip().upper()
        if sev not in _SEV_RANK:
            sev = "MEDIUM"
        try:
            conf = float(it.get("confidence", 0.5))
        except (TypeError, ValueError):
            conf = 0.5
        conf = min(1.0, max(0.0, conf))
        out.append(
            SourceFinding(
                file=file,
                line=max(0, line),
                cwe=cwe,
                severity=sev,
                title=str(it.get("title", "")).strip()[:200] or cwe,
                description=str(it.get("description", "")).strip()[:1000],
                evidence=str(it.get("evidence", "")).strip()[:500],
                sink=str(it.get("sink", "")).strip()[:200],
                confidence=conf,
            )
        )
    return out


# ---------------------------------------------------------------------------
# Variant analysis (pure) — found a sink once, find it everywhere
# ---------------------------------------------------------------------------

# Extract call identifiers (``foo`` in ``foo(...``) so variant matching is
# whitespace/newline-insensitive — the same idea find_callers uses (reader.py).
_CALL_TOKEN_RE = re.compile(r"([A-Za-z_]\w+)\s*\(")


def _compile_sink_matchers(sinks: set[str]) -> list[re.Pattern[str]]:
    """Turn each sink string into a robust matcher (Etapa A of variant analysis).

    A call-shaped sink (``memcpy(dst, src, n)``) matches on its call token
    ``\\bmemcpy\\s*\\(`` — so ``memcpy (dest,`` and ``memcpy(\\n  dst,`` still
    hit, unlike the old literal substring that missed them. A non-call sink
    (``innerHTML =``, ``../``) falls back to a literal regex.
    """
    out: list[re.Pattern[str]] = []
    for s in sinks:
        s = s.strip()
        if not s:
            continue
        fns = _CALL_TOKEN_RE.findall(s)
        if fns:
            for fn in fns:
                out.append(re.compile(rf"\b{re.escape(fn)}\s*\("))
        else:
            out.append(re.compile(re.escape(s)))
    return out


def collect_variant_targets(
    root: Path,
    findings: list[SourceFinding],
    already_reviewed: set[Path],
    *,
    min_confidence: float = 0.6,
    max_targets: int = 20,
    reader: Callable[[Path], str] | None = None,
    all_files: list[Path] | None = None,
) -> list[Path]:
    """For each confident finding's ``sink``, grep the tree for the same
    literal and return files containing it that weren't reviewed yet.

    This is the Mythos "where else does this pattern appear?" step — it
    expands coverage toward the long tail the file-cap missed. ``all_files``
    lets the caller pass an already-enumerated file list so the tree isn't
    walked twice.
    """
    rd = reader or _read_text
    sinks = {
        f.sink.strip()
        for f in findings
        if f.confidence >= min_confidence and len(f.sink.strip()) >= 4 and not f.variant_of
    }
    if not sinks:
        return []
    matchers = _compile_sink_matchers(sinks)  # Etapa A: whitespace-insensitive
    if not matchers:
        return []
    reviewed_resolved = {p.resolve() for p in already_reviewed}
    targets: list[Path] = []
    seen: set[Path] = set()
    for p in all_files if all_files is not None else enumerate_source_files(root):
        rp = p.resolve()
        if rp in reviewed_resolved or rp in seen:
            continue
        try:
            code = rd(p)
        except OSError:
            continue
        if any(rx.search(code) for rx in matchers):
            targets.append(p)
            seen.add(rp)
            if len(targets) >= max_targets:
                break
    return targets


# ---------------------------------------------------------------------------
# Dedup + rank (pure)
# ---------------------------------------------------------------------------


def dedup_findings(findings: list[SourceFinding]) -> list[SourceFinding]:
    """Collapse duplicate (file, line, cwe). Keep the highest-confidence
    instance of each."""
    best: dict[tuple[str, int, str], SourceFinding] = {}
    for f in findings:
        k = f.key()
        cur = best.get(k)
        if cur is None or f.confidence > cur.confidence:
            best[k] = f
    return list(best.values())


def rank_findings(findings: list[SourceFinding]) -> list[SourceFinding]:
    """Order by severity (CRITICAL first), then confidence desc, then
    file/line for stability."""
    return sorted(
        findings,
        key=lambda f: (f.severity_rank(), -f.confidence, f.file, f.line),
    )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def _build_seed_context(findings: list[SourceFinding], *, min_confidence: float = 0.6, max_seeds: int = 8) -> str:
    """Etapa B: summarize the confident primary-pass sinks so the variant
    re-review is *directed*. The model looks for the SAME pattern in each
    variant file and decides, per occurrence, guard-equivalent (safe) vs
    exploitable variant — instead of a blind independent review. Leverages the
    big context window (V4-Flash 1M) that a per-file review otherwise wastes."""
    seeds = [f for f in findings if f.confidence >= min_confidence and not f.variant_of and f.sink.strip()]
    if not seeds:
        return ""
    lines = [
        "VARIANT ANALYSIS — a prior review confirmed these vulnerability sinks. "
        "Look for the SAME dangerous pattern in this file. For each occurrence, "
        "decide whether it has the equivalent guard/validation (safe, skip) or "
        "is an exploitable variant (report it):",
    ]
    for f in seeds[:max_seeds]:
        lines.append(f"- `{f.sink}` ({f.cwe}) — {f.title}")
    return "\n".join(lines)


def _reviewer_accepts_seed(reviewer: Reviewer) -> bool:
    """True if ``reviewer`` takes a ``seed_context`` kwarg (LocalReviewer does).
    Fakes/plain callables that don't are called the classic 2-arg way."""
    try:
        params = inspect.signature(reviewer).parameters
    except (TypeError, ValueError):
        return False
    return "seed_context" in params or any(p.kind == p.VAR_KEYWORD for p in params.values())


def _call_reviewer(reviewer: Reviewer, rel: str, code: str, seed_context: str) -> list[SourceFinding]:
    """Call the reviewer, threading ``seed_context`` only when it's non-empty
    AND the reviewer accepts it — keeping the Reviewer = Callable[[str, str]]
    contract intact for injected fakes."""
    if seed_context and _reviewer_accepts_seed(reviewer):
        return list(reviewer(rel, code, seed_context=seed_context))  # type: ignore[call-arg]
    return list(reviewer(rel, code))


def review_tree(
    root: Path,
    *,
    reviewer: Reviewer,
    max_files: int = DEFAULT_MAX_FILES,
    variant_analysis: bool = True,
    variant_max_files: int = DEFAULT_VARIANT_MAX_FILES,
    wall_budget_s: float | None = None,
    novelty_query: Callable[[str, int], list[dict]] | None = None,
    patch_seeds: list | None = None,
    reader: Callable[[Path], str] | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> SourceReviewResult:
    """Run the full Mythos-style pass over ``root``.

    enumerate → triage → review top-N → variant-expand → dedup → rank.
    ``reviewer`` is the only impure dependency (the LLM); inject a fake in
    tests. ``reader``/``clock`` are injectable for determinism.

    Total files sent to the model is at most ``max_files + variant_max_files``.
    ``wall_budget_s`` (when set) caps total wall-clock: the primary/variant
    loops stop early once exceeded, so a hung endpoint can't run for hours.

    ``patch_seeds`` (Fase 3) primes the run with recent CVE fixes: files
    carrying a patched sink call are boosted up the triage queue, and each
    review prompt is seeded with the relevant CVE shapes so the model hunts that
    class + its variants first.
    """
    root = Path(root)
    rd = reader or _read_text
    t0 = clock()
    result = SourceReviewResult()

    all_files = enumerate_source_files(root)
    result.files_total = len(all_files)
    if not all_files:
        result.elapsed_seconds = clock() - t0
        return result

    ranked = triage_files(all_files, reader=rd)
    if patch_seeds:
        # Fase 3 — float files carrying a freshly-patched CVE sink to the front.
        from kryon.intelligence.patch_seed import boost_scores

        ranked = boost_scores(ranked, patch_seeds, reader=rd)
    primary = [p for p, _score in ranked[: max(0, max_files)]]

    raw: list[SourceFinding] = []
    reviewed: set[Path] = set()

    def _over_budget() -> bool:
        return wall_budget_s is not None and (clock() - t0) > wall_budget_s

    def _review_one(path: Path, seed_context: str = "") -> None:
        try:
            code = rd(path)
        except OSError as e:
            result.errors.append(f"read {path}: {e}")
            return
        rel = _safe_relpath(path, root)
        if len(code) > DEFAULT_MAX_CODE_CHARS:
            # The model only sees the first DEFAULT_MAX_CODE_CHARS; record it so
            # a sink near the bottom of a big file isn't silently unreviewed.
            result.errors.append(f"WARN {rel}: {len(code)} chars > {DEFAULT_MAX_CODE_CHARS}, review truncated")
        # Fase 3 — prepend the relevant recent-CVE shapes (present in THIS file)
        # to whatever intra-tree variant context we already have.
        effective_seed = seed_context
        if patch_seeds:
            from kryon.intelligence.patch_seed import render_seed_block, seeds_matching_code

            cve_block = render_seed_block(seeds_matching_code(code, patch_seeds))
            effective_seed = "\n\n".join(b for b in (cve_block, seed_context) if b.strip())
        try:
            for f in _call_reviewer(reviewer, rel, code, effective_seed):
                # reviewer may return findings keyed to its own file label;
                # pin them to the real relative path.
                raw.append(_pin_file(f, rel))
        except Exception as e:  # noqa: BLE001 — one bad file must not abort the run
            result.errors.append(f"review {rel}: {type(e).__name__}: {e}")
        reviewed.add(path)

    for path in primary:
        if _over_budget():
            result.errors.append("WARN wall budget exceeded — primary review stopped early")
            break
        _review_one(path)
    result.files_reviewed = len(reviewed)

    if variant_analysis and not _over_budget():
        variant_targets = collect_variant_targets(
            root, raw, reviewed, max_targets=max(0, variant_max_files), reader=rd, all_files=all_files
        )
        seed_context = _build_seed_context(raw)  # Etapa B: direct the re-review
        seed_index = {(f.file, f.line): f for f in raw}
        for path in variant_targets:
            if _over_budget():
                result.errors.append("WARN wall budget exceeded — variant review stopped early")
                break
            before = len(raw)
            _review_one(path, seed_context)
            # mark the newly-added ones as variants for transparency
            for i in range(before, len(raw)):
                f = raw[i]
                if (f.file, f.line) not in seed_index:
                    raw[i] = SourceFinding(**{**f.__dict__, "variant_of": "variant-expansion"})
        result.variant_files_reviewed = len(reviewed) - result.files_reviewed

    findings = rank_findings(dedup_findings(raw))
    # F1 novelty gate: when a CVE-corpus query is supplied, stamp each finding
    # with a known-vs-novel verdict and float the novel ones to the top. Import
    # locally so novelty_gate (which imports SourceFinding) can't cycle.
    if novelty_query is not None:
        from kryon.intelligence.novelty_gate import annotate_novelty, rank_by_novelty

        findings = rank_by_novelty(annotate_novelty(findings, novelty_query))
    result.findings = findings
    result.elapsed_seconds = clock() - t0
    return result


def _safe_relpath(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except ValueError:
        return path.name


def _pin_file(f: SourceFinding, rel: str) -> SourceFinding:
    if f.file == rel:
        return f
    return SourceFinding(**{**f.__dict__, "file": rel})


# ---------------------------------------------------------------------------
# The LLM reviewer (impure, isolated)
# ---------------------------------------------------------------------------


class LocalReviewer:
    """Default ``Reviewer`` — asks the local reasoning model (``DEFAULT_MODEL``,
    i.e. ``kryon-local``, unless ``KRYON_SOURCE_REVIEW_MODEL`` overrides) via
    llama.cpp to review one file and parses its JSON reply, over the
    OpenAI-compatible ``/v1/chat/completions`` endpoint (stdlib urllib, no
    optional deps)."""

    def __init__(
        self,
        model: str | None = None,
        host: str | None = None,
        *,
        timeout: int = 180,
        temperature: float = 0.3,
        num_ctx: int = 16384,
        num_predict: int = 4096,
    ) -> None:
        self.model = model or os.environ.get("KRYON_SOURCE_REVIEW_MODEL", DEFAULT_MODEL)
        # OpenAI-compatible base (llama-server). KRYON_SOURCE_REVIEW_BASE_URL
        # overrides; otherwise the engagement's OPENAI_BASE_URL; else local default.
        self.host = host or os.environ.get(
            "KRYON_SOURCE_REVIEW_BASE_URL",
            os.environ.get("OPENAI_BASE_URL", "http://localhost:8080/v1"),
        )
        self.api_key = os.environ.get("OPENAI_API_KEY", "llama")
        self.timeout = timeout
        self.temperature = temperature
        self.num_ctx = num_ctx  # retained for compat; not sent over OpenAI API
        self.num_predict = num_predict

    def __call__(self, rel_path: str, code: str, seed_context: str = "") -> list[SourceFinding]:
        prompt = build_review_prompt(rel_path, code, seed_context=seed_context)
        raw = self._chat(prompt)
        return parse_findings_json(raw, file=rel_path)

    def _chat(self, prompt: str) -> str:
        import urllib.request

        url = self.host.rstrip("/") + "/chat/completions"
        payload = json.dumps(
            {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "temperature": self.temperature,
                "max_tokens": self.num_predict,
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        choices = data.get("choices") or []
        if not choices:
            return ""
        return (choices[0].get("message", {}) or {}).get("content", "") or ""


# Backwards-compat alias — this reviewer was Ollama-based; it now speaks the
# OpenAI-compatible API (llama.cpp). Kept so existing imports keep working.
OllamaReviewer = LocalReviewer


# ---------------------------------------------------------------------------
# Report (pure)
# ---------------------------------------------------------------------------


def format_report_markdown(result: SourceReviewResult, *, root_label: str = "") -> str:
    """Human-readable summary of a review run."""
    lines = ["# Source review (Mythos-style)", ""]
    if root_label:
        lines.append(f"**Target**: `{root_label}`")
    lines.append(
        f"**Files**: {result.files_reviewed} reviewed "
        f"(+{result.variant_files_reviewed} via variant analysis) / "
        f"{result.files_total} total · {result.elapsed_seconds:.1f}s"
    )
    lines.append(f"**Findings**: {len(result.findings)}")
    lines.append("")
    if not result.findings:
        lines.append("_No vulnerabilities surfaced._")
        return "\n".join(lines)
    for f in result.findings:
        tag = " · variant" if f.variant_of else ""
        lines.append(f"## {f.severity} · {f.cwe} · `{f.file}:{f.line}`{tag}")
        lines.append(f"**{f.title}** (confidence {f.confidence:.2f})")
        if f.description:
            lines.append("")
            lines.append(f.description)
        if f.evidence:
            lines.append("")
            lines.append("```")
            lines.append(f.evidence)
            lines.append("```")
        lines.append("")
    if result.errors:
        lines.append("---")
        lines.append(f"_{len(result.errors)} file error(s) during review._")
    return "\n".join(lines)
