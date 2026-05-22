"""F203.Y — Dead code audit for src/kryon/tools/.

Identifies files with 0 references anywhere outside themselves
(excluding __pycache__/, .git/, the file itself).

Classifies each tool file into:
  - dead         : 0 refs anywhere
  - test_only    : refs only in tests/
  - cli          : refs in src/kryon/cli/
  - service      : refs in services/skills/agents/learning/etc.
  - register_only: refs only in tool_budget.py / toolsets.py / unified_agent.py

Usage: python scripts/dead_code_audit.py [--write-list dead_files.txt]
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "src" / "kryon" / "tools"

EXCLUDE_DIRS = {"__pycache__", ".git", ".venv", "node_modules"}
REGISTRY_FILES = (
    "tool_budget.py",
    "toolsets.py",
    "unified_agent.py",
)


def public_names(py_path: Path) -> list[str]:
    """Return public function + class names declared in py_path.

    Skips _underscored names and methods inside classes (only top-level).
    """
    try:
        tree = ast.parse(py_path.read_text(encoding="utf-8", errors="ignore"))
    except (SyntaxError, OSError):
        return []
    names = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not node.name.startswith("_"):
                names.append(node.name)
        elif isinstance(node, ast.ClassDef):
            if not node.name.startswith("_"):
                names.append(node.name)
    return names


def grep_repo(pattern: str, exclude_path: Path) -> list[Path]:
    """grep -r for pattern; return paths that match (NOT the exclude_path)."""
    try:
        cp = subprocess.run(
            [
                "grep", "-rln",
                "--include=*.py",
                "--include=*.md",
                "--include=*.yaml",
                "--include=*.yml",
                "--include=*.toml",
                "--include=*.json",
                pattern,
                str(REPO_ROOT / "src"),
                str(REPO_ROOT / "tests"),
                str(REPO_ROOT / "scripts"),
                str(REPO_ROOT / "agents"),
                str(REPO_ROOT / "docker"),
                str(REPO_ROOT / "docs"),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except Exception:
        return []
    hits = []
    for line in cp.stdout.splitlines():
        p = Path(line.strip())
        if not p.exists():
            continue
        # exclude __pycache__ etc.
        if any(part in EXCLUDE_DIRS for part in p.parts):
            continue
        if p.resolve() == exclude_path.resolve():
            continue
        hits.append(p)
    return hits


def classify_file(py_path: Path) -> tuple[str, list[Path]]:
    """Return (classification, list of files where refs were found)."""
    names = public_names(py_path)
    if not names:
        return "no_public", []

    all_refs: set[Path] = set()
    # Search by module path stem AND by each public name
    module_path_stem = py_path.relative_to(REPO_ROOT / "src").with_suffix("").as_posix().replace("/", ".")
    # e.g. kryon.tools.api.bola_tool
    queries = [module_path_stem]
    queries.extend(names[:5])  # cap at 5 names to keep grep fast

    for q in queries:
        # Escape for grep BRE
        esc = re.escape(q)
        refs = grep_repo(esc, py_path)
        all_refs.update(refs)

    if not all_refs:
        return "dead", []

    # Classify by directory of references
    in_tests = any("tests" in p.parts for p in all_refs)
    in_cli = any("cli" in p.parts and "kryon" in p.parts for p in all_refs)
    in_services = any(
        any(d in p.parts for d in ("services", "skills", "agents", "learning", "compliance", "reporting", "intelligence"))
        and "kryon" in p.parts
        for p in all_refs
    )
    in_registry_only = all(p.name in REGISTRY_FILES for p in all_refs)

    if in_registry_only:
        return "register_only", sorted(all_refs)
    if in_cli or in_services:
        # in production code, keep
        if not in_cli and in_tests and not in_services:
            return "test_only", sorted(all_refs)
        return "production", sorted(all_refs)
    if in_tests:
        return "test_only", sorted(all_refs)
    return "other", sorted(all_refs)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-list", default="")
    parser.add_argument("--show-test-only", action="store_true")
    parser.add_argument("--show-dead", action="store_true", default=True)
    args = parser.parse_args()

    classifications: dict[str, list[str]] = defaultdict(list)
    ref_map: dict[str, list[str]] = {}

    py_files = sorted(
        p for p in TOOLS_DIR.rglob("*.py")
        if p.name != "__init__.py"
        and not any(part in EXCLUDE_DIRS for part in p.parts)
    )

    print(f"Auditing {len(py_files)} tool files...")
    for py in py_files:
        try:
            cls, refs = classify_file(py)
        except Exception as e:
            print(f"  ERROR {py}: {e}")
            continue
        rel = py.relative_to(REPO_ROOT).as_posix()
        classifications[cls].append(rel)
        ref_map[rel] = [r.relative_to(REPO_ROOT).as_posix() for r in refs]

    print()
    print("=== Classification Summary ===")
    for cls in ("dead", "test_only", "register_only", "production", "no_public", "other"):
        print(f"  {cls:15s}: {len(classifications[cls])}")

    if args.show_dead:
        print()
        print(f"=== DEAD ({len(classifications['dead'])} files, safe to delete) ===")
        for f in classifications["dead"]:
            print(f"  {f}")

    if args.show_test_only:
        print()
        print(f"=== TEST-ONLY ({len(classifications['test_only'])} files) ===")
        for f in classifications["test_only"]:
            refs = ref_map[f][:3]
            print(f"  {f}  -> refs: {refs}")

    if args.write_list:
        Path(args.write_list).write_text(
            "\n".join(classifications["dead"]) + "\n",
            encoding="utf-8",
        )
        print(f"\nWrote {len(classifications['dead'])} dead-file paths to {args.write_list}")


if __name__ == "__main__":
    main()
