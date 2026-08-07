"""Cinc Auditor (FOSS InSpec) integration — compliance-as-code over SSH.

Kryon orchestrates the Apache-2.0 ``cinc-auditor`` binary (NOT the EULA'd
InSpec 5+) as a subprocess. dev-sec.io / CIS profiles carry the authoritative,
community-maintained hardening content; Kryon normalizes the JSON report to
engage.Finding and filters through the applicability gates.
"""

from kryon.integrations.cinc.client import CincError, cinc_cmd, run_profile
from kryon.integrations.cinc.config import (
    build_ssh_extra_args,
    build_target,
    is_cinc_enabled,
    profiles_from_env,
)
from kryon.integrations.cinc.normalizer import impact_to_severity, parse_controls, results_to_findings

__all__ = [
    "CincError",
    "cinc_cmd",
    "run_profile",
    "is_cinc_enabled",
    "profiles_from_env",
    "build_target",
    "build_ssh_extra_args",
    "impact_to_severity",
    "parse_controls",
    "results_to_findings",
]
