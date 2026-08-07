"""Offensive validation tools — BAS, Purple Teaming, Detection as Code, EVE."""

from kryon.tools.validation.attack_simulator import list_attack_techniques, simulate_attack
from kryon.tools.validation.bas_scenarios import (
    bas_ad_reconnaissance,
    bas_data_exfiltration,
    bas_endpoint_security,
    mitre_attack_mapping,
)
from kryon.tools.validation.coverage_scorer import calculate_mitre_coverage, generate_coverage_report
from kryon.tools.validation.detection_generator import generate_sigma_rule, generate_suricata_rule, generate_yara_rule
from kryon.tools.validation.detection_validator import check_siem_alert, validate_detection
from kryon.tools.validation.exploit_validator import (
    validate_auth_bypass,
    validate_finding,
    validate_rce,
    validate_sqli,
    validate_xss,
)
from kryon.tools.validation.http_replay_tool import replay_idor, replay_ssrf, replay_xss
from kryon.tools.validation.request_approval import request_approval

__all__ = [
    "request_approval",
    "simulate_attack",
    "list_attack_techniques",
    "bas_endpoint_security",
    "bas_data_exfiltration",
    "bas_ad_reconnaissance",
    "mitre_attack_mapping",
    "validate_detection",
    "check_siem_alert",
    "generate_sigma_rule",
    "generate_yara_rule",
    "generate_suricata_rule",
    "calculate_mitre_coverage",
    "generate_coverage_report",
    "validate_sqli",
    "validate_xss",
    "validate_rce",
    "validate_auth_bypass",
    "validate_finding",
    "replay_xss",
    "replay_ssrf",
    "replay_idor",
]
