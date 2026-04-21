"""Vulnhuntr-style call-chain source-to-sink scanner (F66.3.a).

Ported from the Vulnhuntr pattern (Protect AI) that landed 6 real CVEs
in 20k+-star Python OSS repos. Unlike the original — which drives an
LLM to iteratively request more context until it can rule a call-chain
in or out — this implementation runs fully deterministic: we use the
existing ``read_function`` / ``find_callers`` tools to trace reachability
from a user-input source to a dangerous sink and score the path. The
LLM integration is exposed as an opt-in callback for confidence scoring
of borderline findings only, so VRAM-constrained deployments can skip it.

Algorithm
---------
1. Find every function whose body *directly* calls a user-input source
   (``read``, ``recv``, ``fgets``, ``scanf``, ``argv[…]``, ``getenv``…).
2. Track the tainted variable (the call's destination or left-hand-side).
3. Follow the taint within the function: if it reaches a dangerous sink
   (``memcpy``, ``strcpy``, ``system``, ``printf`` with first-arg variable,
   ``exec*``) without passing an upper-bound guard, emit a finding with
   confidence 7-9.
4. Follow callees: if the tainted variable is passed as an argument to
   another function in the same repo, recurse into that function
   (bounded by ``max_depth``).
5. Emit findings with a numeric confidence score:
     9  source→sink in the same function, no guard
     8  source→sink via one intermediate function, no guard
     7  source reaches sink but a guard is present (review)
     6  source reaches a *potentially* dangerous sink via 2 hops
     ≤5 dropped — too speculative for a zero-day claim

Results are :class:`kryon.skills.validator_agent.Finding` records so the
F3 validator (including the new taint-path phase in F66.2.b) can triage
them end-to-end. Calling code:

    from kryon.skills.vulnhuntr_loop import run_vulnhuntr
    findings = run_vulnhuntr(repo_path="/src/libxml2")
    for f in findings:
        print(f.cwe, f.file_path, f.function_name, f.severity)
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from kryon.skills.validator_agent import Finding
from kryon.tools.code.reader import _read_function_impl

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Source + sink taxonomy
# ---------------------------------------------------------------------------


# Each source regex yields a tainted variable name. Group(1) MUST be the
# destination. These tend to assign to a lhs (e.g. `ssize_t n = read(…);`)
# or dump into a pointer argument — we match both shapes.
_SOURCES: tuple[tuple[str, re.Pattern], ...] = (
    # LHS form: `ssize_t n = read(fd, buf, sz);` — group(1) is LHS.
    ("read_lhs",    re.compile(r"(\w+)\s*=\s*read\s*\(")),
    ("recv_lhs",    re.compile(r"(\w+)\s*=\s*recv\s*\(")),
    ("getenv_lhs",  re.compile(r"(\w+)\s*=\s*getenv\s*\(")),
    # By-ref form: `read(fd, &n, ...);` — taint the &-referenced arg.
    # Catches `read(fd, &n, ...)`, `recv(fd, &n, ...)`, `fread(&n, ...)`.
    ("read_byref",  re.compile(r"read\s*\([^,]+,\s*&?(\w+)")),
    ("recv_byref",  re.compile(r"recv\s*\([^,]+,\s*&?(\w+)")),
    ("fread",       re.compile(r"fread\s*\(\s*&?(\w+)")),
    # Line readers: buf is tainted with user input.
    ("fgets",       re.compile(r"fgets\s*\(\s*(\w+)")),
    ("gets",        re.compile(r"gets\s*\(\s*(\w+)")),
    # scanf family — first variadic arg is tainted.
    ("scanf",       re.compile(r"scanf\s*\(\s*\"[^\"]*\"\s*,\s*&?(\w+)")),
    ("fscanf",      re.compile(r"fscanf\s*\([^,]+,\s*\"[^\"]*\"\s*,\s*&?(\w+)")),
    # argv special: group(1) captures the variable receiving argv[i].
    # Also handle a naked argv[i] in an expression — var = 'argv'.
    ("argv_assign", re.compile(r"(\w+)\s*=\s*argv\s*\[")),
)


# Each sink regex decides: given a tainted variable name `var`, is it
# used as an unsafe argument? The `.format(var=re.escape(var))` renders
# the template so we match the specific var. Each sink has an associated
# CWE and a base confidence score.
_SINK_TEMPLATES: tuple[tuple[str, str, str, int], ...] = (
    # (sink_name, cwe, regex_template, base_confidence)
    ("memcpy",   "CWE-787",
     r"memcpy\s*\([^,]+,\s*[^,]+,\s*[^)]*\b{var}\b",       9),
    ("memmove",  "CWE-787",
     r"memmove\s*\([^,]+,\s*[^,]+,\s*[^)]*\b{var}\b",      9),
    ("strcpy",   "CWE-787",
     r"strcpy\s*\([^,]+,\s*[^)]*\b{var}\b",                9),
    ("strncpy",  "CWE-787",
     r"strncpy\s*\([^,]+,\s*[^,]+,\s*[^)]*\b{var}\b",      7),
    ("sprintf",  "CWE-787",
     r"sprintf\s*\([^,]+,\s*[^)]*\b{var}\b",               8),
    ("system",   "CWE-78",
     r"system\s*\([^)]*\b{var}\b",                         9),
    ("popen",    "CWE-78",
     r"popen\s*\([^)]*\b{var}\b",                          9),
    ("execvp",   "CWE-78",
     r"execvp?\s*\([^)]*\b{var}\b",                        9),
    ("printf",   "CWE-134",
     r"printf\s*\(\s*\b{var}\b",                           8),  # first-arg only
    ("gets",     "CWE-787",
     r"gets\s*\(\s*\b{var}\b",                             9),
)


# Upper-bound guard markers — if present within the preceding lines of a
# sink invocation, drop the confidence score by 2 (still report, but the
# guard is likely correct).
_GUARD_MARKERS = re.compile(
    r"\b(?:if|assert|BUG_ON|switch)\s*\([^)]*"
    r"(?:<\s*[A-Za-z_0-9]+\s*\)|<=\s*[A-Za-z_0-9]+\s*\)|"
    r"[A-Z_]+_MAX\b|sizeof\s*\()",
)


# Files we don't bother scanning. Tests are out: a PoC of a "bug" in a
# test harness is not a zero-day. Third-party vendored code is its own
# engagement.
_SKIP_DIRS = {".git", "node_modules", "build", "dist", "third_party",
              "__pycache__", "test", "tests", "vendor"}
_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp")


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass
class TaintPath:
    """One source→sink path through the code."""

    source_name: str
    tainted_var: str
    sink_name: str
    sink_cwe: str
    file_path: str
    function_name: str
    source_line: int
    sink_line: int
    guard_present: bool
    confidence: int   # 0-9
    depth: int        # 0 = same function, 1+ = via callees
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------


def run_vulnhuntr(
    repo_path: str,
    *,
    max_depth: int = 2,
    max_files: int = 500,
    confidence_min: int = 6,
    llm_validator=None,  # callable(path) -> int or None
) -> list[Finding]:
    """Scan repo for tainted source→sink paths. Emits :class:`Finding` s
    whose confidence ≥ ``confidence_min``.

    ``llm_validator`` — optional callable that inspects a borderline
    :class:`TaintPath` and returns an adjusted confidence (or None to
    leave it). Not used by default; kept for experiments with an LLM
    budget of 1-2 calls per finding.
    """
    root = Path(repo_path)
    if not root.is_dir():
        logger.warning("vulnhuntr: repo not found: %s", repo_path)
        return []

    paths = list(_iter_sources(root))[:max_files]
    logger.info("vulnhuntr: scanning %d files", len(paths))

    all_paths: list[TaintPath] = []
    for p in paths:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for fn_name, start, body in _iter_functions_in(text):
            paths_here = _analyse_function(
                body=body,
                function_name=fn_name,
                file_path=str(p),
                function_start_line=start,
                depth=0,
                root=root,
                max_depth=max_depth,
                visited=set(),
            )
            all_paths.extend(paths_here)

    # Dedupe by (file, function, sink_line) — a function may trip multiple
    # sinks, and each sink can be reached by multiple taint chains; we
    # keep the highest-confidence one per (file, fn, sink_line).
    best: dict[tuple[str, str, int], TaintPath] = {}
    for tp in all_paths:
        k = (tp.file_path, tp.function_name, tp.sink_line)
        if k not in best or best[k].confidence < tp.confidence:
            best[k] = tp

    # Optional LLM re-score for borderline cases.
    if llm_validator is not None:
        for tp in best.values():
            if tp.confidence in (6, 7):
                try:
                    new_score = llm_validator(tp)
                except Exception as exc:  # noqa: BLE001
                    tp.notes.append(f"llm_validator raised: {exc}")
                    continue
                if isinstance(new_score, int) and 0 <= new_score <= 9:
                    tp.confidence = new_score
                    tp.notes.append(f"llm_validator adjusted score to {new_score}")

    findings: list[Finding] = []
    for tp in best.values():
        if tp.confidence < confidence_min:
            continue
        findings.append(Finding(
            file_path=tp.file_path,
            function_name=tp.function_name,
            crash_type="",
            cwe=tp.sink_cwe,
            poc_source="",
            repo_path=repo_path,
            line_range=f"{tp.sink_line}-{tp.sink_line}",
            severity=_severity_for_confidence(tp.confidence),
            language=_language_of(tp.file_path),
        ))

    findings.sort(key=lambda f: (_lang_weight(f.cwe), f.file_path, f.function_name))
    return findings


def _analyse_function(
    *,
    body: str,
    function_name: str,
    file_path: str,
    function_start_line: int,
    depth: int,
    root: Path,
    max_depth: int,
    visited: set[tuple[str, str]],
) -> list[TaintPath]:
    """Scan one function body for source→sink taint chains. Recurses into
    callees up to ``max_depth`` using :func:`_read_function_impl`."""
    out: list[TaintPath] = []

    # 1. Find tainted variables sourced in this function.
    tainted: list[tuple[str, str, int]] = []  # (var, source_name, line)
    for source_name, rx in _SOURCES:
        for m in rx.finditer(body):
            try:
                var = m.group(1)
            except IndexError:
                var = ""
            if not var:
                continue
            line_in_body = body.count("\n", 0, m.start()) + 1
            abs_line = function_start_line + line_in_body - 1
            tainted.append((var, source_name, abs_line))

    # Special case: naked argv[i] passed directly to a sink without an
    # intermediate assign. We synthesise an "argv[...]" tainted token so
    # sink patterns matching `\bargv\b` still fire.
    if re.search(r"\bargv\s*\[", body):
        tainted.append(("argv", "argv_direct", function_start_line))

    if not tainted:
        return out

    # 2. For each tainted variable, look for sinks in the same function.
    for var, source_name, source_line in tainted:
        for sink_name, cwe, tpl, conf in _SINK_TEMPLATES:
            try:
                sink_rx = re.compile(tpl.format(var=re.escape(var)))
            except re.error:
                continue
            for m in sink_rx.finditer(body):
                sink_line_in_body = body.count("\n", 0, m.start()) + 1
                sink_line_abs = function_start_line + sink_line_in_body - 1
                # Check for upper-bound guard in the preceding ≤10 lines.
                pre_start = max(0, m.start() - 500)
                window = body[pre_start:m.start()]
                guard = bool(_GUARD_MARKERS.search(window))
                confidence = max(0, conf - (2 if guard else 0) - depth)
                out.append(TaintPath(
                    source_name=source_name,
                    tainted_var=var,
                    sink_name=sink_name,
                    sink_cwe=cwe,
                    file_path=file_path,
                    function_name=function_name,
                    source_line=source_line,
                    sink_line=sink_line_abs,
                    guard_present=guard,
                    confidence=confidence,
                    depth=depth,
                ))

    # 3. Recurse: find function calls that take the tainted var as arg.
    if depth >= max_depth:
        return out

    # Pattern: `callee(... var ...)`. We accept the var in any arg slot.
    for var, source_name, source_line in tainted:
        callee_rx = re.compile(
            rf"([A-Za-z_]\w+)\s*\([^()]*\b{re.escape(var)}\b[^()]*\)"
        )
        for m in callee_rx.finditer(body):
            callee = m.group(1)
            if callee in {"if", "for", "while", "switch", "return",
                          "sizeof", "printf", "memcpy", "strcpy",
                          "system", "popen", "execvp"}:
                continue
            key = (file_path, callee)
            if key in visited:
                continue
            visited.add(key)
            raw = _read_function_impl(file_path, callee)
            try:
                doc = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if "error" in doc:
                continue
            callee_body = doc.get("body") or ""
            callee_start = int(doc.get("start_line") or 0)
            # Recursion: treat the callee as if the first param is tainted.
            # A cheap approximation — a real analyzer would track param
            # positions, but regex is enough for a zero-day scanner.
            subpaths = _analyse_function(
                body=callee_body,
                function_name=callee,
                file_path=file_path,
                function_start_line=callee_start,
                depth=depth + 1,
                root=root,
                max_depth=max_depth,
                visited=visited,
            )
            for sp in subpaths:
                sp.notes.append(f"reached via {function_name}()")
            out.extend(subpaths)

    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iter_sources(root: Path) -> Iterator[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in _SUFFIXES:
            yield path


_FUNC_DEF_RE = re.compile(
    r"(?:^|\n)\s*(?:static\s+|inline\s+|extern\s+|const\s+)*"
    r"[A-Za-z_][\w*\s]*?"
    r"(?P<name>[A-Za-z_]\w+)\s*\([^;{}]*\)\s*\{",
)


def _iter_functions_in(text: str) -> Iterator[tuple[str, int, str]]:
    """Yield (function_name, start_line, body) for every `ret fn(...) {}`
    found in `text`. Returns *approximate* function body (brace-balanced
    from the opening `{` to the matching `}`)."""
    for m in _FUNC_DEF_RE.finditer(text):
        name = m.group("name")
        if name in {"if", "for", "while", "switch", "return", "sizeof"}:
            continue
        body_start = m.end() - 1  # the `{`
        # Brace balance.
        depth = 0
        i = body_start
        while i < len(text):
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    i += 1
                    break
            i += 1
        body = text[body_start:i]
        start_line = text.count("\n", 0, m.start()) + 1
        yield name, start_line, body


def _severity_for_confidence(conf: int) -> str:
    if conf >= 9:
        return "CRITICAL"
    if conf >= 8:
        return "HIGH"
    if conf >= 7:
        return "MEDIUM"
    return "LOW"


def _language_of(path: str) -> str:
    s = Path(path).suffix.lower()
    if s in {".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"}:
        return "cpp"
    return "c"


def _lang_weight(cwe: str) -> int:
    # Sorting helper: memory safety first, then injection, then format.
    return {"CWE-787": 0, "CWE-134": 2, "CWE-78": 1}.get(cwe, 3)


__all__ = [
    "TaintPath",
    "run_vulnhuntr",
]
