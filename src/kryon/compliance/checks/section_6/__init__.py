"""CIS Section 6 — System maintenance / app security. Explicit submodule
imports register checks via side-effect when imported."""

from kryon.compliance.checks.section_6 import (  # noqa: F401 — side-effect
    c_6_3_3_patch_currency,
    c_6_4_1_web_headers,
)
