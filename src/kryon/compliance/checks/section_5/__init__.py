"""PCI Section 5 — Malicious software protection. Explicit submodule imports
register checks via side-effect when the section package is imported."""

from kryon.compliance.checks.section_5 import (  # noqa: F401 — side-effect
    c_5_2_1_antimalware,
)
