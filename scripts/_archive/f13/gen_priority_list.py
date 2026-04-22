"""F13.1 pre-scan: top-N priority list + distribution table.

Standalone: imports priority logic inline (skips kryon.sdk.agents).
Works on the host Python — no docker/kryon install needed.
"""
from __future__ import annotations

import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

# Inline copy of priority.py logic (kept in sync manually)
_PATH_HINTS_5 = ("parser", "parse", "decode", "unserialize", "deserialize",
                 "lexer", "scanner", "tokenizer",
                 "protocol", "packet", "frame", "message")
_PATH_HINTS_4 = ("crypto", "cipher", "hash", "auth", "session", "login",
                 "jwt", "oauth", "ssl", "tls",
                 "upload", "import", "export")
_PATH_HINTS_3 = ("network", "socket", "request", "response", "http", "server", "client",
                 "file", "stream", "buffer")
_PATH_HINTS_1 = ("test", "tests", "__tests__", "spec", "mock", "fixture",
                 "docs", "doc", "examples", "example", "demo",
                 "logging", "logger", "log_", "build", "cmake", "makefile",
                 "contrib/", "contrib\\",
                 "vendor/", "third_party/", "external/",
                 "benchmark", "fuzz/")

_DANGEROUS_FUNCS = [
    r"\bstrcpy\s*\(", r"\bstrcat\s*\(", r"\bsprintf\s*\(", r"\bgets\s*\(",
    r"\bscanf\s*\([^,]*?,\s*&?\w+\s*\)", r"\bvsprintf\s*\(",
    r"\bmemcpy\s*\(", r"\bmemmove\s*\(", r"\balloca\s*\(",
    r"\bmalloc\s*\(\s*\w+\s*\*\s*\w+\s*\)",
    r"\b\w+\s*\-\s*\w+\s*\-\s*\w+\b",
    r"\bsystem\s*\(", r"\bpopen\s*\(", r"\bexecve?p?\s*\(",
    r"\bfopen\s*\(", r"\bopen\s*\(",
    r"\brecv\s*\(", r"\brecvfrom\s*\(",
    r"\bprintf\s*\(\s*\w+\s*[),]",
]
_DANGEROUS_RE = re.compile("|".join(_DANGEROUS_FUNCS))
_INPUT_SIGNALS = [r"argv\[", r"getenv\(", r"stdin", r"fgets\(",
                  r"request\.", r"HttpRequest", r"socket\.recv", r"accept\(",
                  r"fs\.readFileSync", r"io\.open"]
_INPUT_RE = re.compile("|".join(_INPUT_SIGNALS))
_EXT_SUPPORTED = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh",
                  ".py", ".js", ".ts", ".go", ".rs", ".java", ".php", ".rb"}


def _path_score(p: str) -> int:
    low = p.lower()
    for t in _PATH_HINTS_1:
        if t in low:
            return 1
    for t in _PATH_HINTS_5:
        if t in low:
            return 5
    for t in _PATH_HINTS_4:
        if t in low:
            return 4
    for t in _PATH_HINTS_3:
        if t in low:
            return 3
    return 2


def _content_uplift(text: str) -> tuple[int, dict]:
    d = len(_DANGEROUS_RE.findall(text))
    i = len(_INPUT_RE.findall(text))
    delta = 0
    if d >= 5:
        delta += 2
    elif d >= 1:
        delta += 1
    if i >= 1 and d >= 1:
        delta += 1
    return delta, {"danger_hits": d, "input_hits": i}


def score_repo(repo_path: str, max_files: int, min_loc: int = 20) -> list[dict]:
    rp = Path(repo_path)
    skip = {".git", "node_modules", "vendor", "third_party", "external",
            "__pycache__", ".venv", "venv", "build", "dist", "target", "borrowed"}
    rows: list[dict] = []
    for root, dirs, files in os.walk(rp):
        dirs[:] = [d for d in dirs if d not in skip]
        for name in files:
            ext = Path(name).suffix.lower()
            if ext not in _EXT_SUPPORTED:
                continue
            fp = Path(root) / name
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            loc = text.count("\n") + 1
            if loc < min_loc:
                continue
            rel = str(fp.relative_to(rp)).replace("\\", "/")
            base = _path_score(rel)
            delta, ev = _content_uplift(text)
            score = min(5, base + delta)
            rows.append({
                "file": rel,
                "score": score,
                "loc": loc,
                "evidence": ev,
            })
    rows.sort(key=lambda x: (-x["score"], -x["evidence"]["danger_hits"], -x["loc"]))
    return rows[:max_files]


def main(repo_path: str, max_files: int, out_dir: str) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    top = score_repo(repo_path, max_files)
    label = Path(repo_path).name

    (out / f"{label}-priority-top{max_files}.json").write_text(
        json.dumps({"top": top}, indent=2), encoding="utf-8"
    )

    dirs = Counter()
    for e in top:
        parts = e["file"].split("/", 2)
        dirs["/".join(parts[:2])] += 1

    lines = [
        f"# {label} top-{max_files} priority files",
        f"\nTotal ranked: {len(top)}",
        "\n## Distribution by top-level dir\n",
    ]
    for d, c in dirs.most_common():
        lines.append(f"- `{d}`: {c}")
    lines.append("\n## Full list\n")
    lines.append("| # | score | danger | input | loc | file |")
    lines.append("|---|-------|--------|-------|-----|------|")
    for i, e in enumerate(top, 1):
        ev = e["evidence"]
        lines.append(
            f"| {i} | {e['score']} | {ev['danger_hits']} | "
            f"{ev['input_hits']} | {e['loc']} | `{e['file']}` |"
        )
    (out / f"{label}-priority-top{max_files}.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )
    print(f"{label}: {len(top)} entries")
    print("Top-level dir distribution:")
    for d, c in dirs.most_common(20):
        print(f"  {c:4d}  {d}")


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: gen_priority_list.py <repo_path> <N> <out_dir>")
        sys.exit(1)
    main(sys.argv[1], int(sys.argv[2]), sys.argv[3])
