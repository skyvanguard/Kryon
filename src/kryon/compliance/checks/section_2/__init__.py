"""CIS Section 2 — Services, network parameters. Explicit submodule imports
register checks via side-effect when the section package is imported."""

from kryon.compliance.checks.section_2 import (  # noqa: F401 — side-effect
    c_2_2_2_default_accounts,
    c_2_2_7_ssh_hardening,
)
