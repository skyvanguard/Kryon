"""
code_priority_score — rank files 1-5 by attack-surface likelihood.

Ported from the Mythos methodology: before diving into code review,
prioritize. Parsers, deserialization, crypto, auth, and network I/O are
historically where vulnerabilities live. UI, logging, and build scripts
almost never are.

Score meaning
-------------
  5 = prime target (parsers, deserialization, network input handling)
  4 = high   (crypto, auth/session, unsafe strings, file I/O with user input)
  3 = medium (general business logic with some external input)
  2 = low    (internal helpers, format-only utilities)
  1 = minimal (tests, docs, logging, pure math, UI strings)
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from kryon.sdk.agents import function_tool

# Filename / path hints — cheap heuristic before reading file bodies
_PATH_HINTS_5 = (
    "parser", "parse", "decode", "unserialize", "deserialize",
    "lexer", "scanner", "tokenizer",
    "protocol", "packet", "frame", "message",
)
_PATH_HINTS_4 = (
    "crypto", "cipher", "hash", "auth", "session", "login",
    "jwt", "oauth", "ssl", "tls",
    "upload", "import", "export",
)
_PATH_HINTS_3 = (
    "network", "socket", "request", "response", "http", "server", "client",
    "file", "stream", "buffer",
)
_PATH_HINTS_1 = (
    "test", "tests", "__tests__", "spec", "mock", "fixture",
    "docs", "doc", "examples", "example", "demo",
    "logging", "logger", "log_", "build", "cmake", "makefile",
    # Non-core trees — they may use dangerous funcs, but the core is the
    # interesting attack surface. Explicit downgrade.
    "contrib/", "contrib\\",
    "vendor/", "third_party/", "external/",
    "benchmark", "fuzz/",
)

# Dangerous function tokens (C/C++ flavored; other langs fall through)
_DANGEROUS_FUNCS = [
    # unbounded string
    r"\bstrcpy\s*\(", r"\bstrcat\s*\(", r"\bsprintf\s*\(", r"\bgets\s*\(",
    r"\bscanf\s*\([^,]*?,\s*&?\w+\s*\)", r"\bvsprintf\s*\(",
    # memory moves with attacker-controlled size
    r"\bmemcpy\s*\(", r"\bmemmove\s*\(", r"\balloca\s*\(",
    r"\b[zZ]memcpy\s*\(", r"\b[zZ]memcmp\s*\(",  # project-specific wrappers (zlib, openssl, etc.)
    r"\bmalloc\s*\(\s*\w+\s*\*\s*\w+\s*\)",  # alloc with product (int overflow)
    # Pointer arithmetic patterns (classic source of OOB bugs — CVE-2024 inflateCopy)
    r"\b\w+\s*\-\s*\w+\s*\-\s*\w+\b",  # a - b - c (compound subtraction)
    r"\bnext_in\s*[+\-]", r"\bnext_out\s*[+\-]",  # stream pointer math
    r"->next_in\s*[+\-]", r"->next_out\s*[+\-]",
    r"\bwrite\s*-\s*\w+", r"\bread\s*-\s*\w+",  # offset into buffer
    # Array access with computed index (partial — false positives expected)
    r"\[\s*\w+\s*[+\-*]\s*\w+\s*\]",  # arr[i + j], arr[i - 1], arr[i * 2]
    # cmd/exec
    r"\bsystem\s*\(", r"\bpopen\s*\(", r"\bexecve?p?\s*\(",
    # file ops with path
    r"\bfopen\s*\(", r"\bopen\s*\(",
    # network recv
    r"\brecv\s*\(", r"\brecvfrom\s*\(", r"\bread\s*\([^,]+,",
    # format string
    r"\bprintf\s*\(\s*\w+\s*[),]",  # printf(user_var) with no format str
    # deserialization
    r"\bpickle\.loads?\s*\(", r"\byaml\.load\s*\(", r"\bunserialize\s*\(",
    r"\beval\s*\(", r"\bexec\s*\(",
]
# Case-sensitive SQL dangers compiled separately to avoid inline-flag merge errors
_DANGEROUS_SQL = [
    r"SELECT\s+.+\s+FROM\s+\"?\s*\+\s*\w",
    r"execute\s*\(\s*[fr]?[\"'][^\"']*\{\w+\}",  # f-string SQL
]
_DANGEROUS_RE = re.compile("|".join(_DANGEROUS_FUNCS))
_DANGEROUS_SQL_RE = re.compile("|".join(_DANGEROUS_SQL), re.IGNORECASE)

# Untrusted-input entry-point signals
_INPUT_SIGNALS = [
    r"argv\[", r"getenv\(", r"stdin", r"fgets\(",
    r"request\.", r"req\.(body|query|params)",
    r"HttpRequest", r"WSGI",
    r"socket\.recv", r"SocketChannel", r"accept\(",
    r"BytesIO", r"BufferedReader",
    r"fs\.readFileSync", r"io\.open",
]
_INPUT_RE = re.compile("|".join(_INPUT_SIGNALS))

_EXT_SUPPORTED = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh",
                  ".py", ".js", ".ts", ".go", ".rs", ".java", ".php", ".rb"}


def _path_score(p: str) -> int:
    low = p.lower()
    for token in _PATH_HINTS_1:
        if token in low:
            return 1
    for token in _PATH_HINTS_5:
        if token in low:
            return 5
    for token in _PATH_HINTS_4:
        if token in low:
            return 4
    for token in _PATH_HINTS_3:
        if token in low:
            return 3
    return 2


def _content_uplift(text: str) -> tuple[int, dict]:
    """Return (delta, evidence) — how much to bump score based on file body."""
    danger_hits = len(_DANGEROUS_RE.findall(text)) + len(_DANGEROUS_SQL_RE.findall(text))
    input_hits = len(_INPUT_RE.findall(text))

    delta = 0
    if danger_hits >= 5:
        delta += 2
    elif danger_hits >= 1:
        delta += 1
    if input_hits >= 1 and danger_hits >= 1:
        delta += 1  # dangerous func AND external input in same file

    return delta, {
        "danger_hits": danger_hits,
        "input_hits": input_hits,
    }


def _code_priority_score_impl(
    repo_path: str,
    max_files: int = 50,
    min_loc: int = 20,
) -> str:
    """Walk repo, score each source file 1-5, return top N."""
    rp = Path(repo_path)
    if not rp.is_dir():
        return json.dumps({"error": f"not a dir: {repo_path}"})

    skip_dirs = {".git", "node_modules", "vendor", "third_party", "external",
                 "__pycache__", ".venv", "venv", "build", "dist", "target"}
    scored: list[dict] = []

    for root, dirs, files in os.walk(rp):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for name in files:
            ext = Path(name).suffix.lower()
            if ext not in _EXT_SUPPORTED:
                continue
            fpath = Path(root) / name
            try:
                stat = fpath.stat()
                if stat.st_size > 2_000_000:
                    continue
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            loc = text.count("\n")
            if loc < min_loc:
                continue

            rel = str(fpath.relative_to(rp))
            base = _path_score(rel)
            delta, ev = _content_uplift(text)
            final = max(1, min(5, base + delta))
            scored.append({
                "file": rel,
                "score": final,
                "base_from_path": base,
                "content_delta": delta,
                "loc": loc,
                "evidence": ev,
            })

    scored.sort(key=lambda r: (-r["score"], -r["evidence"]["danger_hits"], -r["loc"]))
    top = scored[:max_files]
    return json.dumps({
        "repo_path": str(rp),
        "files_scored": len(scored),
        "top": top,
    }, indent=2)


@function_tool(strict_mode=False)
def code_priority_score(
    repo_path: str,
    max_files: int = 50,
    min_loc: int = 20,
) -> str:
    """Rank source files 1-5 by attack-surface likelihood.

    Uses path hints + dangerous function patterns + untrusted-input signals
    to prioritize where the 0-day hunter should look first.

    Returns JSON: {files_scored, top: [{file, score, evidence, loc}]}.
    """
    return _code_priority_score_impl(repo_path, max_files, min_loc)
