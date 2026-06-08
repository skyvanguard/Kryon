"""Mythos-style source-review harness.

Anthropic's Claude "Mythos" read the Firefox 150 source and surfaced 271
vulnerabilities by *pure reasoning over code* — no fuzzing harness. This
module is Kryon's local equivalent: point a strong reasoning model
(default ``Kryon-MOE-35B``) at a source tree and have it review the
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

DEFAULT_MODEL = "Kryon-MOE-35B"

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
    r"\bmalloc\s*\(": "CWE-789",
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

    def key(self) -> tuple[str, int, str]:
        """Dedup key: same file + line + CWE is the same finding."""
        return (self.file, self.line, self.cwe.upper())

    def severity_rank(self) -> int:
        return _SEV_RANK.get(self.severity.upper(), 4)

    def to_engage_finding(self):  # -> kryon.cli.engage.Finding
        """Convert to the canonical Finding so it flows downstream."""
        from kryon.cli.engage import Finding

        msg = self.title if not self.description else f"{self.title} — {self.description}"
        return Finding(
            cwe=self.cwe,
            severity=self.severity.upper(),
            host=self.file,
            rule_id=f"SAST-{self.cwe}",
            message=msg,
            evidence=self.evidence,
            severity_rank=self.severity_rank(),
            confidence=self.confidence,
            needs_verification=True,  # LLM-derived, never auto-trusted
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
Reviewer = Callable[[str, str], "list[SourceFinding]"]


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
    out: list[Path] = []
    if root.is_file():
        candidates = [root]
    else:
        candidates = []
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            parts_lower = {part.lower() for part in p.relative_to(root).parts[:-1]}
            if parts_lower & skip_dirs:
                continue
            candidates.append(p)
    for p in candidates:
        if p.suffix.lower() not in extensions:
            continue
        try:
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


def score_file_risk(code: str) -> int:
    """Count sink-pattern hits — a cheap proxy for "interesting to review".

    Not a vulnerability count; just a triage signal so the file most
    likely to hold a real bug goes to the model first under a file cap.
    """
    return sum(len(rx.findall(code)) for rx, _ in _COMPILED_SINKS)


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


def build_review_prompt(rel_path: str, code: str, *, max_code_chars: int = 24_000) -> str:
    """Assemble the per-file review prompt. Truncates very large files at a
    char cap (triage already filtered by byte size; this is a safety net)."""
    snippet = code if len(code) <= max_code_chars else code[:max_code_chars] + "\n…(truncated)\n"
    numbered = _number_lines(snippet)
    return f"{_REVIEW_INSTRUCTIONS}\n\nFile: {rel_path}\n```\n{numbered}\n```\n"


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
        return []
    try:
        items = json.loads(arr)
    except (json.JSONDecodeError, ValueError):
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


def collect_variant_targets(
    root: Path,
    findings: list[SourceFinding],
    already_reviewed: set[Path],
    *,
    min_confidence: float = 0.6,
    max_targets: int = 20,
    reader: Callable[[Path], str] | None = None,
) -> list[Path]:
    """For each confident finding's ``sink``, grep the tree for the same
    literal and return files containing it that weren't reviewed yet.

    This is the Mythos "where else does this pattern appear?" step — it
    expands coverage toward the long tail the file-cap missed.
    """
    rd = reader or _read_text
    sinks = {
        f.sink.strip()
        for f in findings
        if f.confidence >= min_confidence and len(f.sink.strip()) >= 4 and not f.variant_of
    }
    if not sinks:
        return []
    reviewed_resolved = {p.resolve() for p in already_reviewed}
    targets: list[Path] = []
    seen: set[Path] = set()
    for p in enumerate_source_files(root):
        rp = p.resolve()
        if rp in reviewed_resolved or rp in seen:
            continue
        try:
            code = rd(p)
        except OSError:
            continue
        if any(s in code for s in sinks):
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


def review_tree(
    root: Path,
    *,
    reviewer: Reviewer,
    max_files: int = DEFAULT_MAX_FILES,
    variant_analysis: bool = True,
    reader: Callable[[Path], str] | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> SourceReviewResult:
    """Run the full Mythos-style pass over ``root``.

    enumerate → triage → review top-N → variant-expand → dedup → rank.
    ``reviewer`` is the only impure dependency (the LLM); inject a fake in
    tests. ``reader``/``clock`` are injectable for determinism.
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
    primary = [p for p, _score in ranked[:max_files]]

    raw: list[SourceFinding] = []
    reviewed: set[Path] = set()

    def _review_one(path: Path) -> None:
        try:
            code = rd(path)
        except OSError as e:
            result.errors.append(f"read {path}: {e}")
            return
        rel = _safe_relpath(path, root)
        try:
            for f in reviewer(rel, code):
                # reviewer may return findings keyed to its own file label;
                # pin them to the real relative path.
                raw.append(_pin_file(f, rel))
        except Exception as e:  # noqa: BLE001 — one bad file must not abort the run
            result.errors.append(f"review {rel}: {type(e).__name__}: {e}")
        reviewed.add(path)

    for path in primary:
        _review_one(path)
    result.files_reviewed = len(reviewed)

    if variant_analysis:
        variant_targets = collect_variant_targets(root, raw, reviewed, reader=rd)
        seed_index = {(f.file, f.line): f for f in raw}
        for path in variant_targets:
            before = len(raw)
            _review_one(path)
            # mark the newly-added ones as variants for transparency
            for i in range(before, len(raw)):
                f = raw[i]
                if (f.file, f.line) not in seed_index:
                    raw[i] = SourceFinding(**{**f.__dict__, "variant_of": "variant-expansion"})
        result.variant_files_reviewed = len(variant_targets)

    result.findings = rank_findings(dedup_findings(raw))
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
    """Default ``Reviewer`` — asks the local reasoning model (Kryon-MOE-35B
    via llama.cpp) to review one file and parses its JSON reply, over the
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

    def __call__(self, rel_path: str, code: str) -> list[SourceFinding]:
        prompt = build_review_prompt(rel_path, code)
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
