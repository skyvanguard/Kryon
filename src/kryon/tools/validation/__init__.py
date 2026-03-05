"""Offensive validation tools — BAS, Purple Teaming, Detection as Code, EVE."""

from kryon.tools.validation.attack_simulator import list_attack_techniques, simulate_attack
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

__all__ = [
    "simulate_attack",
    "list_attack_techniques",
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
]
