"""OpenVAS / Greenbone integration — arm's-length GMP client + result normalizer.

Kryon orchestrates a **stock, unmodified** Greenbone (own container) over GMP
via ``gvm-cli`` subprocess (never importing python-gvm), keeping the two as
separate programs (mere aggregation) — a clean license boundary with
Greenbone's GPL/AGPL components.
"""

from kryon.integrations.openvas.client import (
    GmpConnection,
    OpenVASClient,
    OpenVASError,
    gmp_socket_runner,
    gvm_cli_runner,
)
from kryon.integrations.openvas.config import is_openvas_enabled, runner_from_env
from kryon.integrations.openvas.normalizer import cvss_to_severity, parse_results, results_to_findings

__all__ = [
    "OpenVASClient",
    "OpenVASError",
    "GmpConnection",
    "gmp_socket_runner",
    "gvm_cli_runner",
    "is_openvas_enabled",
    "runner_from_env",
    "cvss_to_severity",
    "parse_results",
    "results_to_findings",
]
