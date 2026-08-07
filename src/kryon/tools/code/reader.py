"""
read_function + find_callers.

Extract an individual function body from a source file, and locate all
call-sites of that function across the repo. Uses regex heuristics
tuned per-language — not a real AST, but good enough for hunter loops
until tree-sitter is wired in (F1 follow-up).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from kryon.sdk.agents import function_tool

# ---------------------------------------------------------------------------
# Per-language function-signature regex.
# ---------------------------------------------------------------------------
# We match the function SIGNATURE line; the body is then extracted by
# brace/indent balancing. This keeps us independent of tree-sitter.

_SIG_PATTERNS: dict[str, re.Pattern] = {
    # C / C++:  [return type] name(args) {
    "c": re.compile(
        r"^[ \t]*(?:(?:static|inline|extern|const|unsigned|signed|struct|enum)[ \t]+)*"
        r"[\w\s\*]+?\b(?P<name>\w+)\s*\([^;{}]*?\)\s*(?:\w+\s+)?\{",
        re.M,
    ),
    # Python:  def name(...):   or  async def name(...):
    "python": re.compile(
        r"^(?P<indent>[ \t]*)(?:async\s+)?def\s+(?P<name>\w+)\s*\([^)]*\)\s*(?:->\s*[^:]+)?:",
        re.M,
    ),
    # JS/TS:  function name( ...  |  name = ( ... ) =>  |  name( ... ) {
    "javascript": re.compile(
        r"^[ \t]*(?:export\s+)?(?:async\s+)?(?:function\s+)?(?P<name>\w+)\s*\([^)]*\)\s*(?:=>\s*)?\{",
        re.M,
    ),
    # Go:  func (recv) name(...) ret {
    "go": re.compile(
        r"^func\s+(?:\([^)]*\)\s*)?(?P<name>\w+)\s*\([^)]*\)[^{]*\{",
        re.M,
    ),
    # Rust:  fn name(...) -> ret {   (or pub fn, async fn, etc.)
    "rust": re.compile(
        r"^[ \t]*(?:pub\s+)?(?:async\s+)?fn\s+(?P<name>\w+)\s*(?:<[^>]+>\s*)?\([^)]*\)[^{;]*\{",
        re.M,
    ),
}

_LANG_BY_EXT = {
    ".c": "c",
    ".h": "c",
    ".cc": "c",
    ".cpp": "c",
    ".cxx": "c",
    ".hpp": "c",
    ".hh": "c",
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".go": "go",
    ".rs": "rust",
}


def _detect_lang(path: str) -> str | None:
    return _LANG_BY_EXT.get(Path(path).suffix.lower())


def _extract_by_braces(text: str, start: int) -> tuple[int, str]:
    """Given the `{` position, return (end_offset, body) using brace balance."""
    depth = 0
    i = start
    n = len(text)
    in_str: str | None = None
    in_line_comment = False
    in_block_comment = False
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
        elif in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 1
        elif in_str:
            if ch == "\\":
                i += 1  # skip escaped char
            elif ch == in_str:
                in_str = None
        else:
            if ch == "/" and nxt == "/":
                in_line_comment = True
                i += 1
            elif ch == "/" and nxt == "*":
                in_block_comment = True
                i += 1
            elif ch in ("'", '"', "`"):
                in_str = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i + 1, text[start : i + 1]
        i += 1
    return n, text[start:n]


def _extract_by_indent(text: str, sig_start: int, indent: str) -> tuple[int, str]:
    """For Python-style blocks — end when a non-empty, non-comment line
    at the same-or-less indent appears after the header."""
    # Find end of header line
    header_end = text.find("\n", sig_start)
    if header_end == -1:
        return len(text), text[sig_start:]
    i = header_end + 1
    n = len(text)
    base_indent = len(indent)
    while i < n:
        line_end = text.find("\n", i)
        if line_end == -1:
            line_end = n
        line = text[i:line_end]
        stripped = line.rstrip()
        if stripped:  # non-empty
            # Count leading whitespace
            lead = len(stripped) - len(stripped.lstrip(" \t"))
            if lead <= base_indent and not stripped.lstrip().startswith("#"):
                return i, text[sig_start:i]
        i = line_end + 1
    return n, text[sig_start:n]


# C / C++ keywords that our loose signature regex can capture as "function names".
# Filter them out to keep list_functions output honest.
_C_KEYWORDS = {
    "if",
    "else",
    "for",
    "while",
    "switch",
    "case",
    "default",
    "do",
    "return",
    "break",
    "continue",
    "goto",
    "sizeof",
    "typedef",
    "struct",
    "enum",
    "union",
    "const",
    "static",
    "extern",
    "inline",
    "volatile",
    "register",
    "auto",
    "unsigned",
    "signed",
    "void",
    "int",
    "char",
    "long",
    "short",
    "float",
    "double",
    "bool",
    "size_t",
    "ssize_t",
    "uint8_t",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t",
    "ptrdiff_t",
    "off_t",
    # Often-seen defines/macros that bleed through
    "FILE",
    "NULL",
    "TRUE",
    "FALSE",
}


def _strip_c_comments_preserve_offsets(text: str) -> str:
    """Replace /* ... */ blocks and // ... lines with spaces (keep length/lines).

    Critical for signature-matching regex: if the regex is allowed to start
    matching inside a comment, its non-overlapping consumption can hide the
    REAL function definition that follows. Stripping comments upfront gives
    a clean substrate whose byte offsets still map 1:1 to the original text.
    """
    out = list(text)
    i = 0
    n = len(text)
    in_str: str | None = None
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_str:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        if ch in ('"', "'"):
            in_str = ch
            i += 1
            continue
        if ch == "/" and nxt == "/":
            # Line comment — blank to end of line
            j = text.find("\n", i)
            if j == -1:
                j = n
            for k in range(i, j):
                out[k] = " "
            i = j
            continue
        if ch == "/" and nxt == "*":
            # Block comment — blank through closing */
            j = text.find("*/", i + 2)
            end = (j + 2) if j != -1 else n
            for k in range(i, end):
                # Preserve newlines so line numbers don't shift
                if text[k] != "\n":
                    out[k] = " "
            i = end
            continue
        i += 1
    return "".join(out)


def _list_functions_impl(file_path: str) -> str:
    """Return a JSON list of every function definition found in the file."""
    p = Path(file_path)
    if not p.is_file():
        return json.dumps({"error": f"file not found: {file_path}"})

    lang = _detect_lang(file_path)
    if lang is None:
        return json.dumps(
            {
                "error": f"unsupported extension: {p.suffix}",
                "supported": sorted(set(_LANG_BY_EXT.values())),
            }
        )

    try:
        raw_text = p.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return json.dumps({"error": f"read failed: {e}"})

    # Strip comments (preserving offsets) before signature matching so that
    # a commented-out pattern can't steal bytes from the real function below.
    if lang == "c":
        text = _strip_c_comments_preserve_offsets(raw_text)
    else:
        text = raw_text

    pattern = _SIG_PATTERNS[lang]
    out: list[dict] = []
    source_for_preview = raw_text  # use uncommented text for signature display
    for m in pattern.finditer(text):
        name = m.group("name")
        if lang == "c" and name in _C_KEYWORDS:
            continue
        if not name or not (name[0].isalpha() or name[0] == "_"):
            continue
        # Use the captured name's offset for line numbers (not m.start(), which
        # may point backward into blanked-out whitespace after comment stripping)
        name_start = m.start("name")
        line_start = source_for_preview.rfind("\n", 0, name_start) + 1
        line = source_for_preview.count("\n", 0, name_start) + 1
        start = line_start  # signature preview begins at the line, not earlier
        sig_end = source_for_preview.find("{", start)
        if sig_end == -1:
            sig_end = source_for_preview.find(":", start)  # python
        if sig_end == -1:
            sig_end = start + 200
        signature = source_for_preview[line_start:sig_end].strip().replace("\n", " ")[:200]
        out.append({"name": name, "line": line, "signature": signature})

    # Dedup by name (keep first occurrence line)
    seen: set[str] = set()
    unique: list[dict] = []
    for f in out:
        if f["name"] in seen:
            continue
        seen.add(f["name"])
        unique.append(f)

    return json.dumps(
        {
            "file": str(p),
            "lang": lang,
            "count": len(unique),
            "functions": unique,
        },
        indent=2,
    )


def _read_function_impl(
    file_path: str,
    function_name: str,
    context_lines: int = 0,
) -> str:
    """See read_function for docs."""
    p = Path(file_path)
    if not p.is_file():
        return json.dumps({"error": f"file not found: {file_path}"})

    lang = _detect_lang(file_path)
    if lang is None:
        return json.dumps(
            {
                "error": f"unsupported extension: {p.suffix}",
                "supported": sorted(set(_LANG_BY_EXT.values())),
            }
        )

    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return json.dumps({"error": f"read failed: {e}"})

    # Same comment-stripping trick as list_functions — keeps the signature
    # regex from getting "stolen" by comment pseudo-matches before the
    # real definition.
    if lang == "c":
        scan_text = _strip_c_comments_preserve_offsets(text)
    else:
        scan_text = text

    pattern = _SIG_PATTERNS[lang]
    for m in pattern.finditer(scan_text):
        if m.group("name") != function_name:
            continue

        sig_start = m.start("name")
        # Start of the header line for accurate line number
        line_start = text.rfind("\n", 0, sig_start) + 1
        start_line = text.count("\n", 0, line_start) + 1

        if lang == "python":
            indent = m.group("indent") or ""
            end_off, body = _extract_by_indent(text, line_start, indent)
        else:
            brace_pos = text.index("{", sig_start)
            end_off, body = _extract_by_braces(text, brace_pos)
            body = text[line_start:end_off]

        end_line = start_line + body.count("\n")

        # Prepend context if requested
        prefix = ""
        if context_lines > 0:
            ctx_start_line = max(1, start_line - context_lines)
            # Find the byte offset of ctx_start_line
            off = 0
            for _ in range(ctx_start_line - 1):
                nl = text.find("\n", off)
                if nl == -1:
                    break
                off = nl + 1
            prefix = text[off:line_start]

        return json.dumps(
            {
                "file": str(p),
                "function": function_name,
                "lang": lang,
                "start_line": start_line,
                "end_line": end_line,
                "loc": body.count("\n"),
                "body": (prefix + body)[:15000],  # cap
            },
            indent=2,
        )

    return json.dumps(
        {
            "error": f"function '{function_name}' not found in {file_path}",
            "lang": lang,
        }
    )


def _find_callers_impl(
    repo_path: str,
    function_name: str,
    max_hits: int = 50,
    exclude_definitions: bool = True,
) -> str:
    """See find_callers for docs."""
    rp = Path(repo_path)
    if not rp.is_dir():
        return json.dumps({"error": f"not a dir: {repo_path}"})

    call_re = re.compile(rf"\b{re.escape(function_name)}\s*\(")
    # Patterns that indicate this is the definition, not a call:
    def_signal = re.compile(rf"\b(?:def|fn|func|function)\s+{re.escape(function_name)}\b")
    # C/C++: "type name(" at start of line (approximate — may have false pos)
    c_def_signal = re.compile(rf"^[\w\s\*]+\s{re.escape(function_name)}\s*\([^;]*\)\s*\{{?\s*$")

    skip_dirs = {".git", "node_modules", "vendor", "third_party", "build", "dist"}
    hits: list[dict] = []

    for root, dirs, files in os.walk(rp):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            lang = _detect_lang(fname)
            if lang is None:
                continue
            fpath = Path(root) / fname
            try:
                if fpath.stat().st_size > 2_000_000:
                    continue
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if function_name not in text:
                continue
            rel = fpath.relative_to(rp)
            for i, line in enumerate(text.splitlines(), 1):
                if not call_re.search(line):
                    continue
                if exclude_definitions:
                    if def_signal.search(line):
                        continue
                    if lang == "c" and c_def_signal.match(line.rstrip()):
                        continue
                # Skip comments
                stripped = line.lstrip()
                if stripped.startswith(("//", "#", "*", "/*")):
                    continue
                hits.append(
                    {
                        "file": str(rel),
                        "line": i,
                        "snippet": line.strip()[:200],
                    }
                )
                if len(hits) >= max_hits:
                    break
            if len(hits) >= max_hits:
                break
        if len(hits) >= max_hits:
            break

    return json.dumps(
        {
            "function": function_name,
            "repo_path": str(rp),
            "total_callers": len(hits),
            "hits": hits,
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Public tool wrappers
# ---------------------------------------------------------------------------


@function_tool(strict_mode=False)
def read_function(
    file_path: str,
    function_name: str,
    context_lines: int = 0,
) -> str:
    """Extract the full body of a function by name from a source file.

    Supports C/C++, Python, JS/TS, Go, Rust via regex + brace/indent balancing.
    Returns JSON: {file, function, start_line, end_line, body, lang}.
    """
    return _read_function_impl(file_path, function_name, context_lines)


@function_tool(strict_mode=False)
def find_callers(
    repo_path: str,
    function_name: str,
    max_hits: int = 50,
    exclude_definitions: bool = True,
) -> str:
    """Locate all call-sites of a function across a repo.

    AST-lite: greps for `name(` filtering definitions + comments.
    Returns JSON: {hits: [{file, line, snippet}]}.
    """
    return _find_callers_impl(repo_path, function_name, max_hits, exclude_definitions)


@function_tool(strict_mode=False)
def list_functions(file_path: str) -> str:
    """List every function defined in a source file.

    Call this BEFORE read_function when you don't know the exact function name
    — it prevents wasting turns guessing names that turn out to be wrong
    (e.g. fill_window when the real names are fill_window_c90/fill_window_sse).

    Returns JSON: {file, lang, count, functions: [{name, line, signature}]}.
    """
    return _list_functions_impl(file_path)
