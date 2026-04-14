"""
Kryon CWE pattern library — single source of truth for detection.

Replaces scattered patterns previously in priority.py, semgrep_tool.py
and hardcoded PoC builders. Each CWE has one YAML at
`patterns/cwe/cwe-NNN.yaml` describing detection regexes, semgrep
rules, PoC templates, escalation hints, and FPR filters.

Public API:

    from kryon.skills.patterns import (
        get_pattern, iter_all_patterns, get_poc_template,
        normalize_cwe, cwes_match,
    )
"""
from .loader import (
    cwes_match,
    get_pattern,
    get_poc_template,
    iter_all_patterns,
    iter_detection_regexes,
    normalize_cwe,
)

__all__ = [
    "get_pattern",
    "iter_all_patterns",
    "iter_detection_regexes",
    "get_poc_template",
    "normalize_cwe",
    "cwes_match",
]
