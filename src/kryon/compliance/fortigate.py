"""FortiGate (FortiOS) compliance framework metadata.

Target: corporate / banking edge firewall audits. Checks run over SSH against
a FortiGate appliance and flag misconfigurations on admin surface, SSL VPN,
logging, and software lifecycle.

Transport: SSH to the FortiOS CLI (NOT a Linux shell). Each check sends one
short command (`show ...`, `get ...`, `diagnose ...`) and parses the text
response. The runner's existing SSH wrapper handles BatchMode + key auth.

Notes for FortiOS legacy versions (<= 6.4):
  Some clients require `-o KexAlgorithms=+diffie-hellman-group14-sha1`
  and `-o HostKeyAlgorithms=+ssh-rsa`. The default runner does not inject
  these; an operator running against a legacy box should add them via a
  custom SSH client config or upgrade the FortiOS to 7.x first.

The actual check modules live in `kryon.compliance.checks.fortigate.*` and
self-register on import.
"""

from __future__ import annotations

from dataclasses import dataclass

FRAMEWORK_ID = "fortigate"
FRAMEWORK_NAME = "FortiGate (FortiOS) hardening — CIS Fortinet Benchmark profile"
FRAMEWORK_VERSION = "1.0"

# Section numbers loosely align with CIS Fortinet FortiOS Benchmark v1.x
# plus banking add-ons (SSL VPN MFA, lifecycle CVE cross-ref).
SECTIONS = {
    "1": "Administrative access (credentials / 2FA / trusthost)",
    "2": "Management services (SNMP / NTP / DNS / interface allowaccess)",
    "3": "SSL VPN exposure",
    "4": "Logging & monitoring",
    "5": "Software lifecycle (FortiOS version, FortiGuard licenses, CVEs)",
}


@dataclass(frozen=True)
class FortiGateContext:
    """Extra hints a FortiGate check can use.

    The generic `compliance.CheckContext` already carries host / ssh_*;
    this just documents FortiGate-specific knobs that an operator may
    pass through env vars.
    """

    admin_https_port: int = 443
    sslvpn_port: int = 10443
    has_vdoms: bool = False
    expected_min_fortios_major: int = 7  # Anything < 7.0 → flagged on FGT-5.1
    expected_min_fortios_minor: int = 0
