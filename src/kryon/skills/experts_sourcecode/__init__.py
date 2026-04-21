"""Source-code expert sub-agents per CWE family (F66.1.b — HPTSA pattern).

Mirror of :mod:`kryon.webexploit.experts` for source-code bug discovery.
Each expert owns one CWE family, carries the filtered pattern library
for those CWEs, and (optionally) dispatches semgrep / joern scans
scoped to its rules only.

The experts produce :class:`kryon.skills.validator_agent.Finding`
records so the existing F3 planner + F3.4 validator (including the new
F66.2.b taint-path phase) consume them without adaptation.

Exports:
  - :class:`SourceExpert`          — abstract base
  - :class:`MemorySafetyExpert`    — CWE-787 / 121 / 122 / 125 / 416
  - :class:`NumericExpert`         — CWE-190 / 191 / 369
  - :class:`InjectionExpert`       — CWE-78 / 89 / 94
  - :class:`FormatStringExpert`    — CWE-134

  - :func:`all_experts`            — canonical expert set
  - :func:`dispatch_experts`       — shared-budget runner
"""

from __future__ import annotations

from kryon.skills.experts_sourcecode.base import SourceExpert, SourceExpertResult
from kryon.skills.experts_sourcecode.expert_format_string import FormatStringExpert
from kryon.skills.experts_sourcecode.expert_injection import InjectionExpert
from kryon.skills.experts_sourcecode.expert_memory_safety import MemorySafetyExpert
from kryon.skills.experts_sourcecode.expert_numeric import NumericExpert


def all_experts() -> list[SourceExpert]:
    """Return the canonical expert set.

    Order follows impact density: memory safety (worst crashes), then
    numeric (frequent overflow → OOB), then injection, then format
    strings (rarer but high-signal when present).
    """
    return [
        MemorySafetyExpert(),
        NumericExpert(),
        InjectionExpert(),
        FormatStringExpert(),
    ]


def dispatch_experts(
    repo_path: str,
    *,
    experts: list[SourceExpert] | None = None,
    total_budget: int = 60,
    max_files_per_expert: int = 200,
) -> list[SourceExpertResult]:
    """Run each expert on the repo with a shared file-scan budget.

    ``total_budget`` is the sum of files inspected across all experts;
    when exhausted the remaining experts skip. ``max_files_per_expert``
    caps individual greediness so memory-safety (large ruleset) can't
    starve the others on a large repo.
    """
    if experts is None:
        experts = all_experts()

    remaining = total_budget
    out: list[SourceExpertResult] = []
    for e in experts:
        if remaining <= 0:
            break
        allocated = min(e.max_budget, remaining, max_files_per_expert)
        result = e.investigate(repo_path=repo_path, budget=allocated)
        out.append(result)
        remaining -= result.budget_used
    return out


__all__ = [
    "SourceExpert",
    "SourceExpertResult",
    "MemorySafetyExpert",
    "NumericExpert",
    "InjectionExpert",
    "FormatStringExpert",
    "all_experts",
    "dispatch_experts",
]
