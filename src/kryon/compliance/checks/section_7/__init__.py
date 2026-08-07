"""PCI Section 7 — Access control by need-to-know. Explicit submodule imports
register checks via side-effect when the section package is imported."""

from kryon.compliance.checks.section_7 import (  # noqa: F401 — side-effect
    c_7_2_1_sensitive_file_perms,
)
