"""PCI Section 4 — Cryptography in transit. Explicit submodule imports
register checks via side-effect when the section package is imported."""

from kryon.compliance.checks.section_4 import (  # noqa: F401 — side-effect
    c_4_2_1_strong_tls,
)
