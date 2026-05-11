"""CIS Section 10 — Logging / audit trails. Explicit submodule imports
register checks via side-effect when imported."""

from kryon.compliance.checks.section_10 import (  # noqa: F401 — side-effect
    c_10_2_1_audit_trails,
)
