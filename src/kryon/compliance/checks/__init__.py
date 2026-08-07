"""F15.1 — PCI-DSS v4 deterministic check engine.

All checks in this package conform to the `Check` protocol defined in
`base.py`. The runner in `runner.py` composes them into a reproducible
audit artifact.

LLM boundary rule (regulatory):
  LLMs may read CheckResult objects to generate explanatory prose for the
  PDF's Context and Remediation sections. LLMs MUST NEVER modify:
    - verdict
    - evidence_stdout / evidence_stderr
    - evidence_parsed
    - remediation_static
    - control_id or section
  Violating this rule breaks regulatory defensibility of the audit.
"""

from kryon.compliance.checks.base import (
    Check,
    CheckContext,
    CheckResult,
    Severity,
    Verdict,
)

__all__ = ["Check", "CheckContext", "CheckResult", "Verdict", "Severity"]
