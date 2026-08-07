"""Lynis (CISOfy) integration — host audit over SSH.

Kryon invokes the GPL-3.0 ``lynis`` binary at arm's length (subprocess / SSH
exec on the target), never modifying it, then normalizes the report.dat to
engage.Finding through the applicability gates.
"""

from kryon.integrations.lynis.client import LynisError, lynis_cmd, run_audit
from kryon.integrations.lynis.config import include_suggestions, is_lynis_enabled
from kryon.integrations.lynis.normalizer import parse_report, report_to_findings

__all__ = [
    "LynisError",
    "lynis_cmd",
    "run_audit",
    "is_lynis_enabled",
    "include_suggestions",
    "parse_report",
    "report_to_findings",
]
