"""Application Security (AppSec) pipeline tools — SAST, DAST, SCA, API Security, Supply Chain."""

from kryon.tools.appsec.api_security import api_security_scan, owasp_api_top10_check
from kryon.tools.appsec.burp_tools import (
    burp_active_scan,
    burp_proxy_history,
    burp_send_to_repeater,
)
from kryon.tools.appsec.compliance_audit import generate_compliance_pdf, run_compliance_audit
from kryon.tools.appsec.http_fetch import http_fetch
from kryon.tools.appsec.sbom import dependency_tree, generate_sbom, scan_sbom_vulns
from kryon.tools.appsec.semgrep import semgrep_scan, semgrep_scan_with_rules
from kryon.tools.appsec.supply_chain import check_typosquatting, detect_dependency_confusion
from kryon.tools.appsec.zap import zap_api_scan, zap_baseline_scan, zap_full_scan

__all__ = [
    "semgrep_scan",
    "semgrep_scan_with_rules",
    "zap_baseline_scan",
    "zap_full_scan",
    "zap_api_scan",
    "generate_sbom",
    "scan_sbom_vulns",
    "dependency_tree",
    "api_security_scan",
    "owasp_api_top10_check",
    "detect_dependency_confusion",
    "check_typosquatting",
    # F15.2 deterministic compliance
    "run_compliance_audit",
    "generate_compliance_pdf",
    # HTTP fetch (Python requests with browser UA)
    "http_fetch",
    # Burp Suite REST API + mitmproxy fallback
    "burp_send_to_repeater",
    "burp_active_scan",
    "burp_proxy_history",
]
