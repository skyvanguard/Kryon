"""
Source-code tools for KRYON.

Fase 1 of the ZERO_DAY_ROADMAP. Kryon was 90% blackbox before this module —
these tools give the agent whitebox capability: clone a repo, index files by
language + LoC, extract individual functions, mine git history for security
commits, and (eventually) run PoCs in an ASAN-instrumented sandbox.

Tools
-----
- git_clone_and_index(repo_url, ref) → clones + indexes at /workspace/sources/
- read_function(file, function_name) → extracts a single function body
- git_log_security(repo_path, since) → finds commits matching security patterns
- git_diff_fix(repo_path, commit) → before/after + touched files for a commit
- find_callers(repo_path, function_name) → AST-lite call-site search
- code_priority_score(repo_path) → ranks files 1-5 by attack-surface score
- run_sandboxed(cmd, repo_path) → runs PoC in ASAN container (stub until F1.3)
"""

from .git_tools import (
    git_clone_and_index,
    git_diff_fix,
    git_log_security,
)
from .joern_tool import joern_scan
from .priority import code_priority_score
from .reader import find_callers, list_functions, read_function
from .sandbox import run_sandboxed
from .semgrep_tool import semgrep_scan

__all__ = [
    "git_clone_and_index",
    "git_diff_fix",
    "git_log_security",
    "find_callers",
    "list_functions",
    "read_function",
    "code_priority_score",
    "run_sandboxed",
    "semgrep_scan",
    "joern_scan",
]
