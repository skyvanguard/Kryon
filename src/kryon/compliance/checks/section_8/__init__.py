"""CIS Section 8 — Identity / access. Explicit submodule imports register
checks via side-effect when imported."""

from kryon.compliance.checks.section_8 import (  # noqa: F401 — side-effect
    c_8_2_1_unique_ids,
    c_8_3_6_password_policy,
    c_8_4_3_mfa,
)
