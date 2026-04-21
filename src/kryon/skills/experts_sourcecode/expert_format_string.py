"""FormatStringExpert — CWE-134.

Uncontrolled format string. Regex matches ``printf(user_input)``-style
calls where the first argument is a non-literal. The library's CWE-134
patterns already encode the discriminating idioms.
"""

from __future__ import annotations

from kryon.skills.experts_sourcecode.base import SourceExpert


class FormatStringExpert(SourceExpert):
    expert_id = "format_string"
    cwe_family = ("CWE-134",)
    max_budget = 20
    confidence_floor = "medium"


__all__ = ["FormatStringExpert"]
