"""PCI Section 11 — Testing / intrusion detection. Explicit submodule imports
register checks via side-effect when the section package is imported."""

from kryon.compliance.checks.section_11 import (  # noqa: F401 — side-effect
    c_11_5_1_ids_ips,
)
