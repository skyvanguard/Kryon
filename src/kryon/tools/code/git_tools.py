"""
Git-based source-code tools.

Functions:
- git_clone_and_index: clone a repo to a stable workspace path + index files.
- git_log_security:    mine git log for security-relevant commits.
- git_diff_fix:        extract before/after of a commit (for variant analysis).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

from kryon.sdk.agents import function_tool

# Where cloned repos live inside the container
_SOURCES_ROOT = Path(os.environ.get("KRYON_SOURCES_ROOT", "/workspace/sources"))

# Map extension -> language name (used by code_priority_score and read_function)
_LANG_BY_EXT = {
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".kt": "kotlin",
}

# Commit-message patterns that signal security intent — miner defaults.
_SECURITY_PATTERNS = [
    r"CVE-\d{4}-\d{3,7}",
    r"\bsecur(e|ity)\b",
    r"\bvuln(erab|)\b",
    r"\boverflow\b",
    r"\bunderflow\b",
    r"\buse[- ]after[- ]free\b",
    r"\bUAF\b",
    r"\bdouble[- ]free\b",
    r"\bnull[- ]?deref\b",
    r"\boob\b|\bout[- ]of[- ]bounds\b",
    r"\bauth(z|n|entic|oriz)\b",
    r"\bsanitiz(e|ation)\b",
    r"\bescap(e|ing)\b",
    r"\bvalidat(e|ion)\b",
    r"\binject(ion)?\b",
    r"\bbound[s]?\s*check\b",
    r"\bleak\b",
    r"\brace\b.*\bcondition\b",
    r"\bTOCTOU\b",
    r"\bfix(es|ed|ing)?\b.*\b(crash|panic|assert)\b",
]


def _repo_slug(repo_url: str) -> str:
    """Produce a stable, short directory name for a repo URL."""
    # Strip protocol + trailing .git
    cleaned = re.sub(r"^https?://|^git@|\.git$", "", repo_url.strip())
    cleaned = cleaned.replace(":", "/").replace("/", "_")
    # Cap at 60 chars + hash suffix for uniqueness
    h = hashlib.sha1(repo_url.encode()).hexdigest()[:8]
    return f"{cleaned[:60]}_{h}"


def _run(cmd: list[str], cwd: Path | None = None, timeout: int = 300) -> tuple[int, str, str]:
    """Run a subprocess and capture rc/stdout/stderr."""
    try:
        r = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except FileNotFoundError as e:
        return 127, "", str(e)


def _git_clone_and_index_impl(
    repo_url: str,
    ref: str = "",
    shallow: bool = True,
) -> str:
    """See git_clone_and_index for docs. Split out for direct testing."""
    _SOURCES_ROOT.mkdir(parents=True, exist_ok=True)
    slug = _repo_slug(repo_url)
    target = _SOURCES_ROOT / slug

    if not target.exists():
        cmd = ["git", "clone"]
        if shallow and not ref:
            cmd += ["--depth", "1"]
        cmd += [repo_url, str(target)]
        rc, _, err = _run(cmd, timeout=600)
        if rc != 0:
            return json.dumps({"error": f"clone failed: {err[:500]}", "cmd": " ".join(cmd)})

    if ref:
        # If we need a specific ref, unshallow first
        _run(["git", "fetch", "--unshallow"], cwd=target, timeout=600)
        rc, _, err = _run(["git", "checkout", ref], cwd=target)
        if rc != 0:
            return json.dumps({"error": f"checkout {ref} failed: {err[:200]}"})

    # Get HEAD SHA
    _, head_sha, _ = _run(["git", "rev-parse", "HEAD"], cwd=target)

    # Build the file index
    by_lang: dict[str, dict] = {}
    files_total = 0
    loc_total = 0
    # Skip typical vendored/third-party dirs
    skip_dirs = {
        ".git",
        "node_modules",
        "vendor",
        "third_party",
        "external",
        "__pycache__",
        ".venv",
        "venv",
        "build",
        "dist",
        "target",
    }

    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for name in files:
            ext = Path(name).suffix.lower()
            lang = _LANG_BY_EXT.get(ext)
            if not lang:
                continue
            fpath = Path(root) / name
            try:
                # Fast LoC — don't load big files fully
                if fpath.stat().st_size > 5_000_000:
                    continue
                with open(fpath, "rb") as f:
                    loc = sum(1 for _ in f)
            except OSError:
                continue
            files_total += 1
            loc_total += loc
            bucket = by_lang.setdefault(lang, {"files": 0, "loc": 0})
            bucket["files"] += 1
            bucket["loc"] += loc

    # Persist index for other tools to consume
    index = {
        "repo_url": repo_url,
        "repo_path": str(target),
        "head_sha": head_sha.strip(),
        "ref_requested": ref or None,
        "files_total": files_total,
        "loc_total": loc_total,
        "by_lang": dict(sorted(by_lang.items(), key=lambda kv: -kv[1]["loc"])),
    }
    try:
        (target / ".kryon_index.json").write_text(json.dumps(index, indent=2))
    except OSError:
        pass

    return json.dumps(index, indent=2)


def _git_log_security_impl(
    repo_path: str,
    since: str = "",
    max_commits: int = 50,
) -> str:
    """See git_log_security for docs."""
    rp = Path(repo_path)
    if not (rp / ".git").exists():
        return json.dumps({"error": f"not a git repo: {repo_path}"})

    # Build the range argument
    log_cmd = ["git", "log", "--format=%H%x09%ad%x09%s", "--date=short"]
    if since:
        log_cmd.append(since if ".." in since else f"--since={since}")

    rc, out, err = _run(log_cmd, cwd=rp, timeout=60)
    if rc != 0:
        return json.dumps({"error": f"git log failed: {err[:200]}"})

    combined_re = re.compile("|".join(_SECURITY_PATTERNS), re.IGNORECASE)

    hits: list[dict] = []
    for line in out.splitlines():
        parts = line.split("\t", 2)
        if len(parts) < 3:
            continue
        sha, date, subject = parts
        m = combined_re.search(subject)
        if not m:
            continue
        # Cheap file count (numstat would be slower)
        hits.append(
            {
                "sha": sha,
                "date": date,
                "subject": subject[:200],
                "pattern": m.group(0),
            }
        )
        if len(hits) >= max_commits:
            break

    return json.dumps(
        {
            "repo_path": str(rp),
            "total_matches": len(hits),
            "hits": hits,
        },
        indent=2,
    )


def _git_diff_fix_impl(
    repo_path: str,
    commit: str,
    context_lines: int = 5,
) -> str:
    """See git_diff_fix for docs."""
    rp = Path(repo_path)
    if not (rp / ".git").exists():
        return json.dumps({"error": f"not a git repo: {repo_path}"})

    # Subject line
    _, subject, _ = _run(["git", "log", "-1", "--format=%s", commit], cwd=rp)
    subject = subject.strip()

    # Full diff vs parent
    rc, diff_out, err = _run(
        ["git", "diff", f"-U{context_lines}", f"{commit}^!"],
        cwd=rp,
        timeout=60,
    )
    if rc != 0:
        return json.dumps({"error": f"git diff failed: {err[:200]}"})

    files: list[dict] = []
    current_file: dict | None = None
    current_diff: list[str] = []

    def flush():
        if current_file is not None:
            current_file["diff"] = "\n".join(current_diff)[:12000]  # cap per-file
            files.append(current_file)

    for line in diff_out.splitlines():
        if line.startswith("diff --git "):
            flush()
            # Path from the `b/` side of the header
            m = re.search(r" b/(\S+)$", line)
            path = m.group(1) if m else "?"
            current_file = {"path": path, "added_calls": [], "removed_calls": []}
            current_diff = [line]
        elif current_file is not None:
            current_diff.append(line)
            # Heuristic: track function calls added/removed (language-agnostic)
            stripped = line.lstrip()
            call_match = re.search(r"^[+-](?![+-])\s*(\w+)\s*\(", line)
            if call_match:
                fname = call_match.group(1)
                if fname in {"if", "for", "while", "switch", "return", "sizeof"}:
                    continue
                bucket = "added_calls" if line.startswith("+") else "removed_calls"
                if fname not in current_file[bucket]:
                    current_file[bucket].append(fname)

    flush()
    return json.dumps(
        {
            "sha": commit,
            "subject": subject,
            "repo_path": str(rp),
            "files": files[:15],  # cap number of files
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Public tool wrappers — thin shims over the _impl functions so the
# function_tool decorator doesn't obscure testability.
# ---------------------------------------------------------------------------


@function_tool(strict_mode=False)
def git_clone_and_index(
    repo_url: str,
    ref: str = "",
    shallow: bool = True,
) -> str:
    """Clone a git repository and build an index of source files.

    Args:
        repo_url: URL of the repo (https, git@, or local path).
        ref: Optional commit SHA, branch, or tag to checkout after clone.
        shallow: If True, use --depth=1 (faster, but blocks deep git_log_security).

    Returns JSON: {repo_path, files_total, by_lang, loc_total, head_sha}.
    """
    return _git_clone_and_index_impl(repo_url, ref, shallow)


@function_tool(strict_mode=False)
def git_log_security(
    repo_path: str,
    since: str = "",
    max_commits: int = 50,
) -> str:
    """Mine git log for security-relevant commits (CVE, overflow, auth, etc.).

    Returns JSON: {hits: [{sha, date, subject, pattern}]}.
    """
    return _git_log_security_impl(repo_path, since, max_commits)


@function_tool(strict_mode=False)
def git_diff_fix(
    repo_path: str,
    commit: str,
    context_lines: int = 5,
) -> str:
    """Extract before/after diff of a commit — input for variant analysis.

    Returns JSON: {sha, subject, files: [{path, diff, added_calls, removed_calls}]}.
    """
    return _git_diff_fix_impl(repo_path, commit, context_lines)
