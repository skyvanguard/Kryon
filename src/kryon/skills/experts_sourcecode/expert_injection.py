"""InjectionExpert (source) — CWE-78 / CWE-89 / CWE-94.

OS command injection, SQL injection, generic code injection. Patterns
match ``system()``, ``popen()``, ``execvp()``, concat-then-query SQL
idioms, ``eval()``, ``exec()``. The base scan drives the detection —
the expert is thin.
"""

from __future__ import annotations

from kryon.skills.experts_sourcecode.base import SourceExpert


class InjectionExpert(SourceExpert):
    expert_id = "injection"
    cwe_family = ("CWE-78", "CWE-89", "CWE-94")
    max_budget = 30
    confidence_floor = "medium"


__all__ = ["InjectionExpert"]
